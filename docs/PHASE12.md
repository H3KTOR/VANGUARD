# Phase 12 — Bounded Event Processing and Data Lifecycle

States used below: **Implemented** · **Tested (Windows)** · **Verified on Linux (none)** · **Blocked**.
Nothing in this phase has run on Linux, in Docker, under `-race`, or in CI.

## 12.1 Audit of the event path (as found, before any change)

```
log file ──nxadm/tail──► tailer goroutine ──► handler(line)            [SYNCHRONOUS in the tailer]
                                               │ parse (regex)
                                               │ checkIOC → rule(s) on per-IP in-memory windows
                                               │ risk.Score → correlation trackers (chain, scanner, auth-abuse…)
                                               │ createIncident: redact+bound evidence → INSERT incident (+IOC enrichment rows)
                                               └ Notifier.OnIncident → Autopilot → (UFW exec, DB writes, Telegram)
honeypot conn goroutine ─► IngestHoneypotHit ─► same engine path (inline, 256-connection cap from Phase 9)
hostsec scanner goroutines ─► Reporter.ReportHostFinding ─► createIncident (own goroutines, own timeouts)
```

Guarantees that existed:

| Property | Before Phase 12 |
|---|---|
| Ordering | Per log source: strict file order (one goroutine does everything). Across sources: no order, and none is required (state is keyed per source IP and lock-protected). |
| Backpressure | Implicit: the tail library's channel is unbuffered, so a slow handler stalled that tailer; the file was the buffer. |
| Latency | Detection + SQLite insert + **Autopilot (possibly a `ufw` subprocess)** all ran inside the line loop, so one slow ban delayed analysis of every later line from that source. |
| Loss | Lines written while VANGUARD is down are never read (tailing starts at EOF, by design). A failed `CreateIncident` was **only a log line**: the incident was neither stored nor sent to response, nothing counted it, health said "healthy", and the dedupe cooldown for that (IP, type) kept running so repeats were suppressed too. |
| Panics | A panic in a handler would kill the tailer goroutine silently. |
| Oversize/malformed lines | Passed to the regex parsers unbounded; unparseable lines are skipped silently (normal — most log lines are not security events). |

The two real defects found were therefore: (1) a lost incident was invisible, and (2) detection and response work shared the ingestion goroutine.

## 12.2 Bounded processing (`internal/pipeline`)

One `Queue` per log source (auth, each web log), **one worker per queue**.

| Requirement | Implementation | Test |
|---|---|---|
| Explicit limits | `-ingest-queue` lines per source (default 1024, 1–65536). One worker goroutine per queue; the queue starts no goroutine per line. | `TestMemoryBoundIsCapacity`, `TestConfigBoundsClamped` |
| Controlled backpressure | When full, `Submit` **blocks the tailer** (the log file is the durable buffer). Nothing is dropped for being late. Each wait is counted (`backpressure_waits`). | `TestBackpressureBlocksProducerWithoutLoss` |
| Per-source ordering | Single worker = FIFO. **Detectors were not parallelized.** Stateful detectors (sliding windows, chain, spraying, scanner heuristics) keep exactly the ordering they had. | `TestOrderPreservedPerQueue`, end-to-end test |
| Panic containment | A handler panic is recovered, counted (`processing_failures`), recorded (`last_error`) and the worker continues. | `TestPanicIsContainedAndCounted` |
| Malformed input | Lines > 64 KiB are refused and counted (`oversize_dropped`). Ordinary non-matching lines are still parsed-and-skipped as before. | `TestOversizeLineDroppedAndCounted` |
| Shutdown | On cancel: producers are released immediately (even if the handler is wedged), queued lines are drained for ≤ 2 s, anything left is **counted as abandoned**, late arrivals are counted as rejected. | `TestShutdownDrainsQueuedLines`, `TestDrainDeadlineAbandonsAndCounts`, `TestSubmitAfterShutdownIsRejectedAndCounted`, `TestMemoryBoundIsCapacity` |
| Double start | Second `Run` returns immediately. | `TestRunTwiceIsNoop` |

Telemetry (`GET /api/health/runtime`, component `ingest_queue:<name>`): `depth`, `capacity`, `high_water`, `enqueued`, `processed`, `backpressure_waits`, `processing_failures`, `oversize_dropped`, `rejected_at_shutdown`, `abandoned_at_shutdown`. State: **failed** if the worker is not running; **degraded** for 15 minutes after any loss (the counters never reset) or when the queue is ≥ 90 % full ("falling behind, no loss yet"). A queue that dropped something is never reported healthy.

### Incident persistence is now accounted for (`detection.Engine.Stats`)

`createIncident` retries a failed insert up to 3 attempts total (50 ms and 200 ms backoff — at most 250 ms added; SQLite already waits up to 5 s for locks inside each attempt). If it still fails, the incident is counted (`incidents_lost`, last error, time). Component `detection_engine` is **failed** for 15 minutes after a loss and **degraded** afterwards ("N detected incidents were lost earlier"). Response is still not triggered for an unpersisted incident (Autopilot is only notified after a successful insert) — that is unchanged and tested.

Known limit, unchanged: the dedupe cooldown (2 min) for a key whose incident failed to persist still runs, so a repeat inside it is suppressed. The loss is visible in health; it is not retried later.

### What is still synchronous

Inside one source's worker, detection → insert → `Autopilot.OnIncident` (→ `ufw`) still run in sequence, so a very slow firewall command delays later lines **of that source** (now visibly: queue depth rises, then backpressure). Honeypot hits and host-security findings do not go through the queue (they have their own goroutines and bounds from Phase 9). Moving response off the worker would change when a ban is applied relative to later events; that was judged out of scope and risky without Linux verification.

## 12.3 Timeouts and slow operations — what is and is not possible

**Measured, not assumed:** with the pure-Go SQLite driver in use, a context deadline does **not** interrupt a running statement. A recursive query given a 200 ms deadline returned `context deadline exceeded` only after it had run to completion (38.7 s in the recorded experiment). So adding `ctx` parameters would have *looked* like timeouts without being one.

What was built instead (`database.QueryGuard`, containment rather than cancellation):

- at most `-query-limit` (default 4, 1–32) guarded reads run at once, leaving connections for writers (pool is 8);
- the caller gets an answer within `-query-timeout` (default 15 s, 1 s–5 min): HTTP **503 + `Retry-After`**; nothing was changed;
- the slot of a timed-out query stays occupied until SQLite actually finishes it, so abandoned statements count against the limit and cannot pile up;
- applied to: `GET /api/incidents`, `/api/dashboard/summary`, `/api/investigate/incidents`, `/api/hunt/matches`, `/api/incidents/:id/{timeline,graph,export}`;
- visible as component `query_guard` (`in_flight`, `abandoned_running`, `rejected_busy`, `timed_out`); **degraded** while an abandoned statement still runs.

Not cancellable, and said so: the statement itself keeps running (and keeps its connection) after the caller is released. The real controls remain: indexed lookups, `LIMIT`ed results, `offset ≤ 10 000`, bounded export size, and now bounded data growth (retention). Remaining unguarded paths: single-row lookups and writes (bounded by the 5 s busy timeout), the maintenance loop, and backup `VACUUM INTO` (bounded by size 2 GiB; documented in Phase 11). No per-statement timeout exists anywhere.

Tests: `guard_test.go` (limit never exceeded, abandon keeps the slot, release after real completion, caller-cancel, panic, **real slow SQLite statement**), `phase12_test.go` (all seven endpoints return 503 + `Retry-After` while the guard is full, no data touched; recovery afterwards; one free slot still serves).

## 12.4 Retention (`internal/retention`, `vanguard retention`)

### Data audit

| Table | Relationship | Retention behaviour |
|---|---|---|
| `incidents` | root | **Deleted** only if status ∈ {resolved, false_positive, auto_blocked}, older than the policy (by `resolved_at`, else `detected_at`), no **active** firewall rule points at it, and (default) no live analyst note. `open` and `investigating` are never deleted. |
| `incident_events` | `incident_id` (no FK) | Deleted with their incident (the incident's own audit trail; enabling incident retention is the explicit permission). |
| `incident_notes` | `incident_id` | Deleted with the incident (soft-deleted notes; live notes block deletion unless the operator turns `keep_incidents_with_notes` off). |
| `ioc_matches` | `incident_id` | **Kept.** Link cleared (`incident_id = 0`); the hunt query already `LEFT JOIN`s. Has its own 30-day / 100 000-row bound. |
| `firewall_rules` | `incident_id` | **Kept** (ban history). The (inactive) rule's link is set NULL. Active rules protect their incident. |
| `rule_tuning_revisions`, `backup_audits`, `retention_runs`, `users`, `iocs`, `ioc_imports`, host baselines | — | **Never deleted by VANGUARD.** (Metrics keep their existing 7-day sweep.) |
| runtime health | not persisted | n/a |

There are no SQL foreign keys in this schema (relationships are soft), so every dependent is handled explicitly and inside the same transaction.

### Policy (stored in the database → carried by backups)

`vanguard retention set -days N [-batch N] [-max-batches N] [-keep-with-notes=true] [-expected-revision R] [-confirm]`

| Field | Default | Bounds |
|---|---|---|
| `incident_retention_days` | **0 = keep everything** (the behaviour of every earlier release) | 0, or 30–3650 |
| `batch_size` (incidents per transaction) | 200 | 10–1000 |
| `max_batches_per_run` | 20 (⇒ ≤ 4 000 incidents/run) | 1–100 |
| `keep_incidents_with_notes` | true | — |

Settings are validated on write **and again on every run** (an out-of-range stored value deletes nothing and fails the run). Changing the policy needs `-confirm`, uses compare-and-set on `revision`, and writes an audit row in the same transaction.

### Run semantics

- `vanguard retention run` = **dry run** (counts only; records a `dry_run` audit row; modifies nothing). `run -confirm` executes.
- The daemon applies the policy every 6 h (first run 2 min after start); with the default policy each tick is a no-op and **writes no audit row**. Component `retention` reads *disabled* (not healthy) when no policy is set, *degraded* when skipped/partial, *failed* on error.
- Each batch is one transaction: select eligible IDs → delete events, notes → unlink matches and inactive rules → delete incidents. Eligibility is re-evaluated inside the transaction, so a ban or note added after a preview protects the incident. A failure rolls the whole batch back (tested with a trigger that aborts the final delete: nothing partial survives) and is retried ×3; earlier committed batches stay and the run is `failed`/`partial` with `more_pending`.
- Idempotent (a second run deletes 0). Bounded by `batch_size × max_batches`. Cancellation is checked between batches.
- Not run while **Panic Mode** is active (daemon). Two runs in one process cannot overlap (`ErrAlreadyRunning`); the CLI against a live daemon relies on SQLite write locking and is safe because every step is idempotent.
- Audit: table `retention_runs` (actor, mode, status, policy revision/days, cutoff, counts, min/max incident ID, detail). It records *that* and *how much* was deleted, not the content. **No tombstones**: a deleted incident simply no longer exists. Append-only by convention; **not tamper-evident, not immutable**. Never auto-deleted.
- `GET /api/retention` (admin, read-only): policy + last 20 runs. There is deliberately **no HTTP route to change policy or delete**.

Missing records are not evidence that nothing happened: the audit rows state that retention ran, with ID ranges, and the policy window is stated in the API response.

## 12.5 Backup compatibility

The two new tables are discovered dynamically by the Phase 11 manifest (`retention_policies`, `retention_runs` appear in `tables`). Restore safety and sidecar handling were **not changed**. New tests (`backup/retention_compat_test.go`): policy + audit trail survive backup → restore, retention keeps working and is idempotent on the restored database; a **real database written by commit `1208a94`** (`legacy_1208a94.db`) migrates to the safe default (keep everything) and a disabled run deletes nothing. Retention is not coordinated with backups: a backup is one SQLite read transaction, so a concurrent retention batch is seen entirely or not at all (reasoned from Phase 11's consistency test, not separately tested).

## 12.6 Tests (this phase)

| Area | New tests |
|---|---|
| `pipeline` | 10 (order, backpressure, memory bound, oversize, panic, drain, drain deadline, reject-after-shutdown, run-twice, bounds) |
| `database` guard | 6 incl. a real slow SQLite statement |
| `detection` | persistence stats on a dead DB; bounded retries; healthy path |
| `api` | queue, engine and guard health mapping (3) + runtime-health exposure (1), guard 503 on 7 endpoints + recovery + free slot, retention API (admin-only, read-only, no mutation routes) |
| `retention` | 14 (disabled default, preview purity, eligibility matrix incl. open/investigating/recent/active-ban/live-note, notes toggle, unlink-not-delete, never-touched tables, idempotency, batch+run bounds, cancellation, atomic rollback, skip hook, re-check after preview, overlap refusal, validation bounds, revision CAS + audit, corrupt stored policy) |
| `backup` | 2 compatibility tests |
| `cmd/vanguard` | retention tick (default/disabled, skipped under Panic Mode, policy run), queue→engine→DB end to end, **tailer→queue→engine→DB end to end (skips on Windows, Linux-only)** |

## 12.7 Results (Windows, Go 1.27.0; no Linux, Docker, CGO)

| Command | Result |
|---|---|
| `gofmt -l .` | clean |
| `go build ./...`, `go vet ./...` | OK / clean |
| `go test -json ./...` → `tools/valreport` | **606 passed, 0 failed, 13 skipped** (previous report: 564/0/12). The new skip is the Linux-only tailer end-to-end test; skips are not passes |
| Real binary: `retention show/set (preview, invalid 7 days, confirm, stale revision)/run (dry)/history` against a temp DB | behaved as documented (invalid → exit 1, stale revision refused, dry run recorded, nothing deleted) |

## 12.8 Limits and risks (carry-over to Linux)

- The tailer → queue path was exercised on Windows only through the queue directly; the file-tail end-to-end test must run on Linux.
- `go test -race` has not been run for `pipeline`, `QueryGuard`, `retention` (new concurrency).
- A timed-out SQLite statement cannot be stopped; it holds a connection until it ends.
- Retention has not run against a large database; `COALESCE(resolved_at, detected_at)` has no matching index, so the eligibility scan is a table scan of incidents with a status filter (bounded per batch by `LIMIT`, but the `COUNT(*)` of eligible rows is a full scan). Acceptable at expected sizes, unmeasured at scale.
- Dashboard `open_incidents_total` is still capped at 500 by its query limit (pre-existing; not changed here).
- Dedupe suppression after a lost incident (above).
- Backups remain unsigned/unencrypted; retention audit rows are not tamper-evident.

## Acceptance

| Criterion | State |
|---|---|
| Concurrency bounded where changed | done, tested |
| Loss and failures observable | done (queue, engine, guard, retention health) |
| Stateful detector semantics preserved | one ordered worker per source; detectors untouched |
| Realistic timeout/containment | containment, with the non-cancellable limit measured and documented |
| Retention explicit, dry-run, bounded, auditable | done, tested |
| Backup/restore compatibility | tested (incl. real legacy DB) |

**Status: Implemented — Verification Pending.**
