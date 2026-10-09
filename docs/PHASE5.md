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
| 1 | Evidence provenance, redaction, bounds, dedupe bound | Every new incident carries `provenance{rule_id,rule_revision,evidence_kind,limitations?}`; sensitive keys are redacted; serialized metadata ≤16 KiB with an explicit truncation marker; dedupe map capped + reaped; tests for each incl. benign/negative and concurrency | not started |
| 2 | Lifecycle + audit trail | Explicit transition table; invalid → 409, same-state idempotent; compare-and-swap so concurrent updates cannot silently overwrite; `incident_events` table (additive AutoMigrate), bounded per incident, sanitized; Autopilot never overrides analyst-terminal states; works against a pre-existing DB | not started |
| 3 | Response outcomes + verification + dry-run | Each ban records attempted/succeeded/failed/verification outcome as incident events; read-only verification via `IsBlocked`; verification failure/timeout/inconclusive remain visible and are never "verified"; DB-persist-failure after Block triggers compensating Unblock and is recorded; `GET /incidents/:id/response-plan` is non-mutating and shares policy code with `HandleIncident`; whitelist + Panic Mode untouched | not started |
| 4 | Operational status | Per-scanner last start/finish/duration/result (`ok`/`skipped`/`failed`/`timeout`) + note; `GET /api/detectors/status`; Phase 4 detectors report `skipped` (not clean) when `/proc`/dpkg unavailable | not started |
| 5 | Correlation + lab | Decision recorded (below); lab cases only for implemented behavior | not started |
| 6 | Final validation + docs | All applicable checks run and reported honestly | not started |

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
