# Phase 9 — Runtime Reliability, Health, and Resource Governance

States: Implemented · Tested (automated, Windows) · Verified on Linux (**none**) · Blocked.

## Baseline

Base `57f5e37`, Windows 10 / Go 1.27 / Node 24, no Docker, no CGO, no Linux. Phases 4–8 remain awaiting Linux verification; this phase does not change that.

## 9.1 Audit: reliability risks found (before changes)

| # | Risk found in the code | Action |
|---|---|---|
| R1 | Honeypot spawned one goroutine (and held one fd) per accepted connection with **no bound**; a connection flood grew goroutines/fds without limit | **Fixed**: semaphore (256). Over the bound the connection is still reported as a hit, only banner/first-line capture is skipped; `shed` counter exposed |
| R2 | Honeypot accept loop `continue`d on any error with no delay (busy spin on e.g. fd exhaustion) | **Fixed**: exponential backoff 50 ms → 1 s, ctx-aware, `accept_errors` counter |
| R3 | A host scanner that ignores its context (stuck syscall/FS) wedged its own loop forever and blocked `Manager.Run` shutdown; the deadline only cancelled a context nobody was watching | **Fixed**: scans run in a goroutine; deadline + 5 s grace, then recorded `timeout` and *abandoned*; the scanner is not started again while the abandoned run is still in flight (≤1 stuck goroutine per scanner) |
| R4 | `Manager.Run` / `Matcher.Run` could be started twice (duplicate workers/reloads) | **Fixed**: atomic run guards |
| R5 | A log tailer on a missing/unopenable file only logged a line; nothing reported that a telemetry source was absent | **Fixed**: `TailObserver`; missing file = *degraded*, start failure = *failed*, started only when the file is open / lines flow |
| R6 | No authenticated runtime-health view of VANGUARD itself (only public liveness `/api/health` and scanner status) | **Added** `GET /api/health/runtime` |
| R7 | `shutdown()` was not idempotent | **Fixed**: `sync.Once` |
| R8 | Maintenance loop errors (ban-expiry sweep) were only logged | **Fixed**: recorded as component `maintenance` |
| R9 | Detection runs **synchronously** in the tailer goroutine (no queue). A slow database therefore slows log reading rather than growing a queue | **Not changed** — this is natural backpressure and bounded memory; documented. Lines are not dropped by VANGUARD; the OS/log file retains them |
| R10 | SQLite pool is 8 connections with a 5 s busy timeout; interactive endpoints are bounded by page limits but have **no per-query timeout** | **Documented gap**, not changed |
| R11 | The `incidents` table has **no retention policy** (events per incident, IOC matches, metrics and import history are bounded; incidents are not) | **Documented gap**; inventing a deletion policy for security records was out of scope |
| R12 | Unaudited: internal buffering of the third-party tail library under a stalled handler | **Documented, not verified** |

## 9.2 Health model

`GET /api/health/runtime` (authenticated, read-only, bounded). `GET /api/health` stays the public **liveness** probe and means only "the process answers".

| State | Meaning |
|---|---|
| `healthy` | The component recorded a real, recent success |
| `degraded` | Working with a known limitation (scan skipped, optional source missing, honeypot shed load or a decoy port unbound, intel reload failed but previous snapshot kept) |
| `failed` | Last attempt failed / cannot operate (DB probe failed, scanner failed, indicator snapshot never loaded, no decoy bound) |
| `timed_out` | The last run exceeded its deadline (possibly abandoned) |
| `disabled` | Turned off by configuration — a choice, not an alert |
| `not_yet_observed` | Registered but nothing recorded yet — **not** healthy |
| `unknown` | It *did* succeed once, but has not reported within 3× its expected interval — missing telemetry, **not** a clean result |

Each component reports **last attempt** and **last success** separately plus bounded counters. `overall` is the worst state; it is `healthy` only if every running component is healthy or intentionally disabled. Components: `database` (live ping with 2 s timeout), `detector:*` (derived from the scanner board), `intel_matcher`, `honeypot`, `detection_engine`, `metrics_collector` (recency of the last stored sample), `maintenance`, `log:auth`, `log:webN`. Error text is truncated to 160 chars and absolute paths are replaced with `<path>`; the endpoint exposes no environment, credentials or file paths.

Limits of each signal: *database* proves one `SELECT`-class ping answered, not that writes succeed; *log:* `healthy` means the file is open/lines were read — a quiet log is indistinguishable from a broken producer (no expected rate is invented); *detector:* `healthy` means the last scan completed without a reported problem; *maintenance* success covers only the ban-expiry sweep; the registry is in memory and resets on restart.

## 9.3 Resource bounds (audited paths)

Reported live in the endpoint's `bounds` object: honeypot concurrent connections 256 · incident dedupe keys 20 000 (+ reaped) · health components 64 (8 counters each) · investigation page 200 · timeline page 200 · export 2 MiB · IOC import 10 MiB / 50 000 records · evidence 16 KiB · audit events per incident 200. Pre-existing bounded structures (per-IP trackers reaped by the maintenance loop, IOC match history, import history, status board) are unchanged. Dropped/deferred work is counted (`shed`, `accept_errors`, abandoned scans show as `timed_out`), never silent.

## 9.4–9.5 Lifecycle and failure tests (all deterministic, no sleeps-as-assertions)

health registry (never-observed ≠ healthy, stale → unknown, failure not masked by staleness, bounds, copy semantics, concurrency); honeypot saturation (every connection still reported, exact accepted/shed counts, `Wait` returns after cancel) and bind failure counted; wedged-scan abandonment without overlap and recovery; double-start refusal (`Manager`, `Matcher`) incl. flag cleared on exit; tail observer (missing file = waiting not started, exactly-once `Stopped`, legacy `TailFile`); API runtime health (auth, every state mapping, stale detector → unknown, path not leaked, DB closed underneath → `failed` while the endpoint keeps answering, honeypot degrade/fail cases, registry staleness); engine with a dead database (no panic, **no response triggered for an unpersisted incident**); idempotent concurrent `shutdown`; registry reflects configuration (disabled vs not-yet-observed).

## Results (Windows; no Linux/Docker/CGO)

| Command | Result |
|---|---|
| `gofmt -l .` | clean |
| `GOOS=linux go vet ./...` | clean |
| `go build ./...` | OK |
| `go test -json ./...` → `tools/valreport` | **521 passed, 0 failed, 11 skipped** (skips are not passes: 10 Unix-permission `hostsec` tests + 1 tail line-delivery test, whose file-change notifications did not arrive in this Windows environment) |
| `npx vitest run` | 5 files, 53 tests pass |
| `npx vite build` | OK |

New tests: health 6 · api runtime-health 5 · honeypot 2 · hostsec 2 · intel 1 · detection (tailer 3, failure 1) · cmd 2 · frontend 5.

## Dashboard

`RuntimeHealthBanner` (all pages) renders **nothing** while overall is healthy, polls every 30 s, expands to the failing components with reason and last success, and reports an unreachable health endpoint as such. It supersedes the earlier scanner-only banner.

## Not verified / residual risk

Linux runtime behaviour (tail notifications, `/proc`), `go test -race` (new concurrency: registry, honeypot semaphore, abandoned-scan bookkeeping, shutdown once), Docker lab, real `ufw` — all unchanged and **pending**. R9–R12 above are documented gaps, not fixed. An abandoned scan's goroutine is never forcibly killed (Go cannot); a permanently wedged syscall leaks that one goroutine until process exit.

## Acceptance

| Criterion | State |
|---|---|
| Health states reflect observed outcomes | done, tested |
| Resource usage bounded in audited paths | done for R1–R4; R10–R12 documented gaps |
| Shutdown/cancellation tested | done (idempotent shutdown, tailer cancel, honeypot Wait, Run guards) |
| Failure states stay visible | done, tested |
| Auth/response policy/dashboard intact | existing tests pass |
| Deterministic tests | yes (explicit skips where Windows lacks notifications) |
| Limitations documented | yes |

**Status: Implemented — Verification Pending** (Linux/race/Docker not run).
