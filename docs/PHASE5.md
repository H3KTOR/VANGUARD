# Phase 5 — Detection Intelligence, Incident Lifecycle & Verified Response

Progress log. States: `not started` < `in progress` < `implemented` < `tested` < `verified (target env)`; `deferred` carries a reason. These are not interchangeable: nothing here is `verified (target env)` unless Linux/Docker output is cited.

## Milestone 0 — Audit (baseline)

- Base revision: `9f36c00` (Phase 4), branch `main`, clean tree at start.
- Environment: Windows 10, Go 1.27 (no WSL, no Docker, no C compiler → no `-race`). Linux-only code compiles via `GOOS=linux go vet ./...`; tests run natively on Windows.
- Baseline failures on Windows (environment, not code): 7 Unix-permission/ownership tests in `internal/hostsec`; 10 attack-chain tests in `internal/detection`; `TestDecoyListenerReportsConnection` in `internal/honeypot`. The `detection` set was reproduced on the pre-Phase-4 commit. The `hostsec` and `honeypot` ones were not baseline-compared.

### Architecture as found

| Stage | Where | Finding |
|---|---|---|
| Detection → incident | `detection/engine.go:createIncident` (single choke point; host findings via `engine_hostsec.go`) | Metadata is a free-form map; **no detector/rule provenance, no observed-vs-inferred marker, no size bound, no secret redaction**. |
| Dedup | `detection.dedupeWindow` (in-memory, `(ip\|type)` key, 2 min) | Map is **never reaped** → grows with attacker-controlled IPs/subjects. Lost on restart (documented intent: a restart may re-raise). Recurrence after cooldown creates a **new** incident (correct). |
| Lifecycle | `DB.UpdateIncidentStatus` + `PUT /incidents/:id/status` | **Any status → any status**, no validation, no history, no compare-and-swap. `Autopilot.Ban` unconditionally overwrites status to `auto_blocked`, clobbering an analyst's `resolved`/`false_positive`. |
| Response | `firewall.Autopilot.HandleIncident/Ban` | Fail-safe whitelist, min score, already-banned checks exist and **must be preserved**. `Ban` calls `exec.Block`, persists a rule; **no outcome record, no verification** (a returned nil from `ufw` ≠ effective state). If DB persistence fails after `Block`, the block is orphaned silently. No non-mutating "what would happen" view. |
| Executor | `firewall.Executor` (UFW / Mock) | `MockExecutor` has unsynchronized maps (known pre-existing race). `Status()` exists, so a read-only verify is feasible. |
| Observability | `hostsec.Manager.runOnce` | Logs only; no last-run/last-error/skipped state; API cannot tell "clean" from "failed/skipped". |
| Correlation | Phase 2 `hostCor`, Phase 3 chain trackers | See Workstream E decision below. |

### Plan and acceptance criteria

| # | Milestone | Acceptance criteria | State |
|---|---|---|---|
| 1 | Evidence provenance, redaction, bounds, dedupe bound | Every new incident carries `provenance{rule_id,rule_revision,evidence_kind,limitations?}`; sensitive keys are redacted; serialized metadata ≤16 KiB with an explicit truncation marker; dedupe map capped + reaped; tests for each incl. benign/negative and concurrency | tested |
| 2 | Lifecycle + audit trail | Explicit transition table; invalid → 409, same-state idempotent; compare-and-swap so concurrent updates cannot silently overwrite; `incident_events` table (additive AutoMigrate), bounded per incident, sanitized; Autopilot never overrides analyst-terminal states; works against a pre-existing DB | tested |
| 3 | Response outcomes + verification + dry-run | Each ban records attempted/succeeded/failed/verification outcome as incident events; read-only verification via `IsBlocked`; verification failure/timeout/inconclusive remain visible and are never "verified"; DB-persist-failure after Block triggers compensating Unblock and is recorded; `GET /incidents/:id/response-plan` is non-mutating and shares policy code with `HandleIncident`; whitelist + Panic Mode untouched | tested |
| 4 | Operational status | Per-scanner last start/finish/duration/result (`ok`/`skipped`/`failed`/`timeout`) + note; `GET /api/detectors/status`; Phase 4 detectors report `skipped` (not clean) when `/proc`/dpkg unavailable | tested |
| 5 | Correlation + lab | Decision recorded (below); lab cases only for implemented behavior | lab scripted, not executed; correlation deferred |
| 6 | Final validation + docs | All applicable checks run and reported honestly | partially done: Windows checks run; race + Docker blocked |

### Workstream E decision (correlation)

Candidates considered: *new listener ⇄ new package*, *config drift ⇄ new listener*, *new listener ⇄ new process*. All of these join **host-local, actor-less** findings by time proximity alone; routine `apt upgrade`/service restarts produce exactly these pairs, and the scanners observe at 2–10 min granularity, so ordering within a window is not recoverable. No candidate meets the "low false-positive, defensible attribution" bar. **Decision: deferred** — no new correlation is implemented; Phase 4 findings stay independent.

### Phase 4 outstanding verification (tracked separately, unchanged by Phase 5)

- [ ] `cd lab && docker compose up -d --build victim && ./run-phase4.sh` — **not run** (no Docker here).
- [ ] `cd core && go test -race ./...` — **not run** (no CGO toolchain here). Known pre-existing `MockExecutor` race will be fixed in Milestone 3 and must be re-checked under `-race` on Linux.
- [ ] Linux execution of the 7 hostsec Unix-permission tests.

### Security & compatibility risks

- Schema: one additive table (`incident_events`); AutoMigrate only adds, no destructive change; old DBs and old API consumers keep working (new endpoints/fields are additive).
- Behavior change: `PUT /incidents/:id/status` now rejects some previously accepted transitions (e.g. `resolved → auto_blocked`) with 409. Dashboard buttons only issue valid ones.
- Redaction is key-name based: it cannot catch secrets embedded in free-text values (documented limitation).
- A local SQLite audit trail is **not tamper-proof**: anyone with DB write access can alter it.

## Results (Windows dev machine, Go 1.27; **no Linux, no Docker, no CGO**)

### What was implemented (all committed; see `git log`)

| Milestone | Delivered | Evidence |
|---|---|---|
| M1 | `prepareEvidence` at the `createIncident` choke point: `provenance{rule_id, rule_revision, evidence_kind observed\|correlated, limitations}`, key-based secret redaction, 16 KiB bound with explicit `evidence_truncated`; dedupe map capped (20 000) + reaped; **bug found by the new corpus**: SQLi/XSS/traversal signatures missed percent-/plus-/double-encoded payloads (access logs keep targets encoded) → targets decoded (2 passes) before matching | `detection/evidence_test.go` (positives, benign lookalikes, malformed input, per-IP isolation, duplicates, redaction, bounds, concurrent dedupe) |
| M2 | Explicit lifecycle table, idempotent same-state, CAS-in-transaction (`ErrInvalidTransition`/`ErrConflict` → 409), `incident_events` table (additive AutoMigrate), sanitized + bounded (200/incident) audit trail, `GET /api/incidents/:id/events`; automated blocking can no longer overwrite `investigating/resolved/false_positive`; `UpdateIncidentStatus` removed | `database/lifecycle_test.go` (full 5×5 matrix, concurrent transitions with audit-chain consistency, sanitization, migration of a pre-existing DB), `api/lifecycle_test.go` |
| M3 | `Autopilot.Plan` (pure policy, shared with execution) + `GET /api/incidents/:id/response-plan` (`executed:false`); response events `succeeded/failed/suppressed/not_eligible`; one bounded read-only verification (`verified/failed/inconclusive`; UFW: `ufw status`, inactive firewall = not blocking); failed verification keeps the incident open and deactivates the non-enforcing rule; persist failure after `Block` rolls the block back; `MockExecutor` made goroutine-safe | `firewall/response_test.go` (12 tests incl. timeout, no-effect, persist-failure rollback, whitelist, analyst-decision preservation) |
| M4 | `StatusBoard` + `Manager.runScan` (deadline, panic containment); Phase 4 detectors report `skipped`/`failed`; `last_clean_scan` only advances on `ok`; `GET /api/detectors/status` | `hostsec/status_test.go`, `api/detectors_test.go` |
| UI | Evidence panel (provenance, response summary, audit timeline, "Planned (not executed)"), scanner-health banner | 12 new Vitest tests; `vite build` OK |
| M5 | **Correlation deferred** (decision above). Lab: `lab/run-phase5.sh` scenarios V–Y | script written, `bash -n` OK, **not executed** |

### Test commands and actual results

| Command | Result |
|---|---|
| `gofmt -l .` (core) | clean |
| `GOOS=linux go vet ./...` | clean |
| `go build ./...` | OK |
| `go test ./...` (Windows) | pass: cmd, api, auth, database, firewall, metrics, notify. **Fail (pre-existing/environmental, identical set to base):** 10 attack-chain tests in `detection`, 7 Unix-permission tests in `hostsec`, `TestDecoyListenerReportsConnection` in `honeypot`. **No new failures.** |
| `cd core/frontend && npx vitest run` | 3 files, 34 tests pass (22 pre-existing + 12 new) |
| `npx vite build` | OK |

Classification of the failures: the 10 `detection` failures reproduce on the pre-Phase-4 commit (clean worktree comparison); root cause not investigated (Windows timing/environment suspected, not confirmed). The 7 `hostsec` tests assume Unix mode bits/ownership. `honeypot` is untouched by Phases 4–5 and was not baseline-compared.

### Not verified (blockers, not failures)

- `go test -race ./...` — no CGO toolchain. The `MockExecutor` race was fixed by construction (mutex + concurrent test), but is **unconfirmed under `-race`**.
- Docker lab: `run-phase4.sh` (Phase 4) and `run-phase5.sh` (Phase 5) — never executed.
- The 7 hostsec Unix tests on Linux.
- Response verification against a **real** `ufw`: only the output parser (`ufwStatusDenies`) is unit-tested; no real firewall was exercised.

### Known limitations of what was built

- Redaction is key-name based; secrets embedded in free-text values (e.g. a raw log line stored as `sample_line`) are not detected.
- The audit trail is a local SQLite table: not tamper-evident.
- Dedupe is in-memory: it is lost on restart (a restart may re-raise a finding once) and never suppresses a recurrence after its 2-minute cooldown; there is no automatic "reopen on recurrence" — recurrence creates a new incident.
- Verification is point-in-time; a rule removed later is not noticed until the TTL reaper.
- `auto_blocked` with verification `inconclusive` keeps the block (deliberate: removing protection on uncertainty is worse) but is shown as inconclusive.
- Scanners other than the four Phase 4 detectors only report `ok`/`timeout`/panic-`failed`; they do not yet report data-source-specific skips.
- Percent-decoding widens matching: a query containing the literal text "union select" (e.g. a search for that phrase) now matches, as it already did unencoded.

### Definition of Done — status

| Item | State |
|---|---|
| Architecture audited, no duplicate features, bounds + fail-safes preserved | done |
| Evidence distinguishes observed vs inferred; bounded; redacted | done (tested) |
| Positive/negative regressions for changed behavior | done (tested) |
| Dedup/recurrence semantics documented and tested | done (tested; restart behavior documented, not tested across a real restart) |
| Lifecycle valid + persisted; audit has no secrets (key-based) | done (tested) |
| Missing telemetry cannot look clean | done (tested) |
| Response attempts/outcomes distinguishable; verification observable; failures visible | done (mock-tested) |
| Whitelist + Panic Mode safeguards intact | done (existing + new tests pass); Panic Mode code untouched |
| Dry-run non-mutating | done (tested at unit and API level) |
| gofmt / vet / build | pass |
| Full Go tests | **partially**: remaining failures classified above, all environmental/pre-existing |
| Race tests | **blocked** (no CGO) |
| Docker lab (Phase 4 and Phase 5) | **blocked** (no Docker) |
| Linux-specific functionality | **unverified** |
| Frontend tests/build | pass |

**Conclusion: Implemented — Verification Pending.**
