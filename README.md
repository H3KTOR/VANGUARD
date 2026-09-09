# VANGUARD v3.0

Lightweight AI-Assisted Linux IDS/IPS & Security Monitoring Platform.

## Project Overview
- **Goal**: A low-footprint, host-based Intrusion Detection/Prevention System for a single Linux server. A single ~25MB Go binary tails auth/web logs, detects attacks with deterministic rules, scores risk dynamically, auto-mitigates via UFW/iptables, and serves a full React dashboard embedded in the same binary. A separate ephemeral Python CLI (run via cron, 0 idle RAM) handles AI analysis, threat-intel sync, and PDF reporting.
- **Architecture**: Go core (always-on daemon + embedded REST API + embedded React dashboard) + Python toolkit (ephemeral CLI) + SQLite (shared local file, WAL mode). See the full design in the original project brief.

> **Deployment note**: VANGUARD is a traditional host-based Linux daemon (log tailing, raw sockets for the honeypot, direct UFW/iptables execution, an embedded static dashboard). It is **not** a Cloudflare Pages/Workers application — there is no serverless deployment story for this project. It is built, tested, and run directly in this sandbox (a Linux environment) and is intended to ultimately run as a systemd service on a real Linux host.

## Current Status: Steps 1–5 + Attack Correlation Engine + Automated Security Test Lab + VANGUARD Mega Expansion Phase 1 (Host Security) Complete

### ✅ Completed

**`core/internal/database`** — GORM + SQLite (pure-Go `glebarez/sqlite` driver, no CGO) data layer:
- Models: `User`, `SystemMetric`, `Incident`, `FirewallRule` (see field docs in `models.go`).
- Composite, query-pattern-driven indexes: `idx_incidents_ip_time`, `idx_incidents_type_time`, `idx_firewall_ip_active`, `idx_metrics_timestamp`, etc.
- `Open()` configures WAL mode + busy timeout for safe concurrent read/write from the API, detection engine, and the read-only Python toolkit.

**`core/internal/detection`, `risk`, `thresholds`** — deterministic rule engine (SSH brute force, honeypot triggers, port scan, web directory scan, path traversal, SQLi/XSS, HTTP flood, etc.) sharing the `Base Severity + Frequency + Threat Reputation (+ Escalation)` risk-scoring formula, plus the **Attack Correlation Engine ("Smart Detection")**:
- `ChainTracker` (`internal/detection/correlation.go`) — a concurrent-safe, per-IP in-memory state machine tracking the three stages of a coordinated attack (Recon/port-touch → Web Probing/403-404 → Auth Probing/SSH failures) within a sliding `AttackChainWindow` (5 min). `Evaluate()` requires all three stages to individually clear their minimum counts AND to have started in the correct order (recon ≤ web ≤ auth, tied timestamps allowed) before reporting a match. Stage timestamps are truncated to whole-second precision before the order comparison, since real log sources (syslog `auth.log`, nginx combined `access.log`) only carry second-level resolution — this avoids a live nanosecond-precision timestamp (e.g. a honeypot hit) spuriously sorting "after" a same-second, zero-fraction log-parsed timestamp.
- A match creates a single `ATTACK_CHAIN` incident via `risk.ScoreChain()` (aggregates the three constituent incident types' base severities, then multiplies by `AttackChainRiskMultiplier` = 1.5, clamped to 100), routed through the same `createIncident()` → `notify.OnIncident()` pipeline as every other rule — so Autopilot's instant ban and the Telegram alert fire automatically with zero extra integration code.
- `ScannerTracker` — a lighter per-IP heuristic (not a signature match) that flags **Web Scanner Behavior** on the *combination* of a high-frequency burst of 403/404 responses and a missing/known-scanner User-Agent (Nikto, dirbuster, sqlmap, nmap, etc. — see `thresholds.SuspiciousUserAgents`) within a 1-minute window.
- Every honeypot decoy-port connection also feeds `ChainTracker`'s Recon stage (see `engine.go`'s `EventHoneypotHit` handling), so a real `nmap` sweep that happens to touch a decoy port counts toward the chain exactly like a raw port-touch would.
- 21 Go unit tests (`correlation_test.go`, `chain_integration_test.go`) cover threshold gating, in-order vs. out-of-order sequencing, window expiry, per-IP isolation, reaping, and a same-second sub-second-precision regression case discovered while building the Task 4 lab below.

**`core/internal/firewall`** — UFW/iptables wrapper with an in-memory mock executor (safe for sandboxes/dev) or the real `ufw` CLI, TTL ban reaper (Autopilot maintenance loop), Panic Mode/lockdown preview + enter/exit, fail-safe admin-IP whitelist. Optional real-time push alerts (Telegram) on ban/Panic Mode toggle via the small `AlertNotifier` interface (decoupled from any specific alert channel — see `internal/notify`).

**`core/internal/honeypot`** — decoy listeners (SSH/MySQL/HTTP-like ports) that log any connection as a honeypot-trigger incident.

**`core/internal/metrics`** — periodic CPU/RAM/Disk/Network sampling with configurable retention, plus **daemon self-telemetry**: a `SelfSampler` (gopsutil `process` for CPU%, Go's `runtime.ReadMemStats` for heap RAM) samples VANGUARD's OWN process footprint on every tick, persisted alongside the host-wide reading and surfaced by `/api/metrics/latest` (`self_cpu_percent`, `self_memory_alloc_mb`, `self_memory_sys_mb`, `self_goroutines`) so the dashboard can prove the "single ~25MB binary, near-zero overhead" claim with real numbers.

**`core/internal/notify`** — stdlib-only Telegram Bot API wrapper (`net/http` POST to `sendMessage`, no SDK). Fire-and-forget: a Telegram outage/misconfiguration never blocks or fails the Autopilot ban/Panic Mode action it's attached to. Enabled by setting `TELEGRAM_BOT_TOKEN` + `TELEGRAM_CHAT_ID` (env var only, never a CLI flag, to avoid leaking secrets via `ps aux`); either unset makes it a safe no-op.

**`core/cmd/vanguard/dotenv.go` / `toolkit/env_loader.py`** — minimal, dependency-free `.env` file loaders (both languages, same semantics: skip comments/blanks, strip matching quotes, real environment variables always win over `.env` values). A dev convenience only — production should prefer systemd's `EnvironmentFile=` (Go) or a real secrets manager / inherited shell env (Python).

**`core/internal/auth`** — JWT-based session auth (bcrypt password hashing, first-run admin bootstrap).

**`core/internal/api`** — full Echo REST API: `/api/auth/*`, `/api/dashboard/summary`, `/api/incidents*`, `/api/firewall/*`, `/api/metrics/*`, `/api/simulate/*`, `/api/panic/*`, `/api/health`.

**`core/internal/simulator`** — Attack Simulation Mode (`vanguard simulate ssh-bruteforce|honeypot [-dry-run]`) for generating realistic synthetic incidents/bans without touching a real system, used throughout development/testing of the API and dashboard.

**`core/cmd/vanguard`** — CLI + daemon entry point:
- `vanguard serve [flags]` — runs the full daemon (log tailing, detection, Autopilot, metrics sampler, honeypot listeners, REST API) **and serves the embedded React dashboard** on the same HTTP port.
- `vanguard simulate <scenario> [flags]` — synthetic attack simulation.
- `vanguard help` — usage.

**`core/frontend`** (Step 4) — React + Vite + Tailwind CSS + Recharts + Lucide React dashboard, built to `core/cmd/vanguard/dist` and embedded into the Go binary via `//go:embed all:dist`:
- **Command Center** (`/`): Master Threat Posture circular risk gauge (0–100, client-computed from open-incident severity mix + active bans) with quick action buttons; System Health panel (Agent/SQLite/Honeypot/Uptime); CPU/RAM/DISK progress-bar cards + Network I/O sparkline; **Daemon Footprint widget** (VANGUARD's own self-telemetry: self-CPU%, self-RAM in MB, goroutine count — piggybacks on the existing 5s `/api/metrics/latest` poll, no extra endpoint/poll cycle needed); 4 severity threat counters (Critical/High/Medium/Low) with trend text; Attack Density AreaChart (last 60 minutes); Threat Mix donut chart.
- **Incidents**, **Firewall**, **Honeypot**, **Metrics**, **Settings** pages.
- Login screen with first-run admin bootstrap flow; dark-mode toggle; Panic Mode modal with dry-run preview.
- `src/api/vanguardClient.js` — typed fetch wrapper for every REST endpoint above, with JWT Bearer auth and centralized 401 handling.
- `cmd/vanguard/frontend.go` — `mountFrontend(e)` serves `index.html` + `/assets/*` from the embedded FS, with SPA catch-all fallback so client-side page state works without server routes; falls back to a clean 404 JSON error (not a crash) if the dashboard hasn't been built yet.

**`toolkit/`** (Step 5) — ephemeral Python 3 CLI (0 idle RAM, run via cron or on demand):
- `database.py` — read-only (`mode=ro`, hard SQLite-enforced, never risks the daemon's WAL file) and read-write (generous `busy_timeout`) connection helpers, typed dataclasses, and query/insert helpers.
- `env_loader.py` — loads `ANTHROPIC_API_KEY` / `OPENAI_API_KEY` (and anything else) from a local `.env` file (if present) before any other module runs, so `ai_analyst`'s provider auto-detection sees them; real environment variables always take precedence.
- `ai_analyst.py` — auto-detects `ANTHROPIC_API_KEY` or `OPENAI_API_KEY`, sends recent incidents to the LLM for a structured forensic verdict (JSON schema), with per-incident graceful degradation (a failed/misconfigured call never aborts the whole batch).
- `threat_sync.py` — fetches the public `ipsum` OSINT malicious-IP feed, filters out private/loopback/reserved ranges and low-corroboration entries, inserts new bans into `firewall_rules`.
- `pdf_reporter.py` — generates a multi-page SOC PDF (ReportLab platypus) summarizing metrics, severity breakdown, top offending IPs, and recent incidents.
- `main.py` — Typer CLI: `toolkit analyze`, `toolkit sync`, `toolkit report`, with Rich console output.

**`lab/`** — **Automated Security Test Lab** (Docker Compose, isolated to this directory ONLY — never part of VANGUARD's production build/deploy path, per the project's hard "zero external services in production" constraint):
- `lab/docker-compose.yml` — two services on a private bridge network (`172.28.0.0/24`): `victim` (multi-stage build of the real VANGUARD Go binary running on top of real `sshd` + `nginx` + `rsyslog`, health-gated on `/api/health`) and `attacker` (Alpine + `nmap`/`hydra`/`curl`/`jq` toolkit).
- `lab/victim/Dockerfile` + `entrypoint.sh` — starts `rsyslogd` (forced to `RSYSLOG_TraditionalFileFormat`, since modern rsyslog defaults to an ISO8601 template that VANGUARD's `AuthLogParser` doesn't expect — a real production host's traditional syslog format is what the parser is written against), then `sshd`, then `nginx`, then `vanguard serve` with honeypot decoys enabled — so every attack produces genuine, unmodified log traffic.
- `lab/attacker/Dockerfile` — Alpine 3.20 + `nmap`/`nmap-scripts`/`hydra`/`curl`/`jq`.
- `lab/run-tests.sh` — orchestrates 4 attack scenarios (Coordinated Attack Chain: `nmap` recon of 8 honeypot decoy ports → `curl` probes of 8 sensitive paths → `hydra` SSH brute force, strictly in that order; Web Scanner heuristic; path-traversal/SQLi-XSS signature probes; HTTP flood), then polls VANGUARD's own REST API (`GET /api/incidents?type=...&ip=...`) to assert each of the 8 expected incident types actually fired, printing a `[✓] DETECTED incident #N, risk=X/100, severity=Y` / `[✗] MISSING` report per assertion and exiting non-zero on any miss — a CI-style regression gate for the whole detection engine.
- **Verified end-to-end in this sandbox**: `docker compose build/up victim` → healthy in ~15s; `docker compose run --rm attacker ./run-tests.sh` → **8/8 PASS**, including `attack_chain` at risk=100/100 CRITICAL, and confirmed the Autopilot auto-banned the attacker IP (`GET /api/firewall/rules` shows an active `autopilot`-sourced ban) exactly as the honeypot-trigger's CRITICAL severity should trigger.
- Building this lab surfaced and fixed one real bug in `ChainTracker.Evaluate()` (the sub-second-precision sequencing issue described above) — not a lab-only artifact; it could affect any real fast, tightly-sequenced attack in production too.

**`core/internal/hostsec`** (VANGUARD Mega Expansion, Phase 1) — five periodic, zero-dependency Host Security scanners, each following the mandated Detection → Evidence → Risk → Correlation → Response pipeline and routing through the exact same `createIncident()` choke point as every log-driven rule (via `internal/detection.Engine.ReportHostFinding`, which implements `hostsec.Reporter` — see `engine_hostsec.go`), so there is zero duplicated detection/persistence logic:
- **File Integrity Monitoring** (`fim.go`) — SHA-256/size/mode/owner/group snapshot of sensitive paths (`/etc/passwd`, `/etc/shadow`, `/etc/sudoers[.d]`, `/etc/ssh/sshd_config`, `/root/.ssh/authorized_keys`, `/etc/crontab`, `/etc/cron.d`, `/etc/systemd/system`); any change to `/etc/shadow` or root's `authorized_keys` is auto-CRITICAL.
- **Persistence Detection** (`persistence.go`) — line-diffs cron, systemd units, every local user's SSH `authorized_keys`, shell startup files, and sudoers for newly-added entries.
- **Privilege Escalation Detection** (`privesc.go`) — flags new UID-0 accounts, new membership in privileged groups (sudo/wheel/root/adm/docker/shadow/disk), dangerous sudoers rules (NOPASSWD / blanket `ALL=(ALL)`), and a **BEST-EFFORT DETECTION** (explicitly labeled per the no-eBPF/no-kernel-module architectural constraint) periodic `/proc` scan for unexpected root-owned processes outside standard system paths.
- **Account Manipulation Detection** (`account.go`) — diffs `/etc/passwd`/`/etc/group` for created/deleted users and groups, UID/GID changes, and group-membership changes; guards against ever misreporting "every account deleted" if `/etc/passwd` becomes unreadable.
- **SUID/SGID Monitoring** (`suid.go`) — walks standard binary directories plus `/tmp`, `/var/tmp`, `/dev/shm` for setuid/setgid binaries; any new SUID/SGID binary found under a world-writable/temp directory is auto-CRITICAL.
- All five share a generic `database.HostFileBaseline` table (partitioned by category, JSON content blob) and a cold-start "first-scan seeding" pattern (`isFirstScan`/`markSeeded`) so a fresh install never floods incidents for pre-existing system state — only genuinely new changes after the first pass are ever reported.
- Host-security incidents have no attacker IP, so they're recorded with the sentinel `SourceIP = database.HostLocalIP` (`127.0.0.1`), which — along with `::1` — is now unconditionally seeded into Autopilot's fail-safe whitelist on every startup regardless of operator config, guaranteeing these findings can never trigger an accidental self-ban.
- Orchestrated by `hostsec.Manager` (`manager.go`), wired into `vanguard serve`'s background task set; each scanner runs on its own ticker (FIM/PrivEsc every 2 min, Persistence/Account every 3 min, SUID every 10 min) with a bounded 30s timeout per scan tick. Controlled via new CLI flags: `-hostsec` (bool, default `true`), `-fim-paths` / `-suid-roots` (comma-separated extra paths, env `VANGUARD_FIM_PATHS` / `VANGUARD_SUID_ROOTS`).
- 26 new Go unit tests (`internal/hostsec/*_test.go`, `internal/detection/engine_hostsec_test.go`, plus 2 new fail-safe tests in `internal/firewall/autopilot_test.go`) cover cold-start seeding silence, every change type per scanner, the SUID writable-dir CRITICAL escalation, the account empty-map read-failure guard, the sudo-group-rule non-flagging, and the HostLocalIP fail-safe whitelist/no-self-ban guarantee.
- Not yet wired into this phase: Docker lab attack scenarios for these 5 detectors, and a dedicated dashboard summary widget (the generic `/api/incidents?type=...` feed already surfaces all 5 new incident types with no API changes needed).

### 🚧 Not Yet Implemented / Known Gaps
- Exact pixel-for-pixel visual match against the originally referenced screenshot could not be verified in this environment (the reference image file was never present in the sandbox); the dashboard was built from the detailed widget spec and is functionally complete, but should be visually spot-checked against the original design if/when it's available.
- 2 npm audit findings (1 moderate, 1 high) in frontend dependencies — not yet triaged.

### Next Steps
1. Visual QA pass against the original reference design once available.
2. Triage npm audit findings; consider further code-splitting if bundle size becomes a concern.
3. Add Docker lab attack scenarios exercising the 5 new Host Security detectors end-to-end (extending `lab/run-tests.sh` / `lab/victim/entrypoint.sh`).
4. Continue into VANGUARD Mega Expansion Phase 2 (Process→File→Network Correlation) and onward through the remaining phases of the mega-prompt's recommended implementation order.
5. **Known pre-existing issue (not introduced by Phase 1)**: `go test -race ./...` flags a data race in `internal/firewall.MockExecutor` (unsynchronized map/bool field access from `TestPanicModeAutoRollbackFiresAfterTimeout`'s background auto-rollback goroutine vs. the main test goroutine) — confirmed present before any Phase 1 changes (reproduced against the prior commit). `go test ./...` (without `-race`) passes cleanly. Should be fixed by adding a `sync.Mutex` to `MockExecutor` in a future pass.

## Try It

```bash
# One-shot: builds the React dashboard AND the Go binary with it embedded
make build

# Run the full daemon + REST API + dashboard (sandbox-safe: mock firewall executor, no real ufw calls)
./core/vanguard serve -db vanguard.db -honeypot=false -auth-log ""
# Dashboard: http://localhost:8080/  (first run prompts you to create the admin account)

# Simulate attacks to populate the dashboard with data
./core/vanguard simulate ssh-bruteforce -db vanguard.db -ip 185.220.101.5 -attempts 30
./core/vanguard simulate honeypot -db vanguard.db

# Frontend-only dev loop (hot reload, proxies /api to a locally running `vanguard serve` on :8080)
cd core/frontend && npm install && npm run dev

# Python toolkit (ephemeral, run on demand or via cron)
cd toolkit && pip3 install -r requirements.txt
python3 main.py report --db ../vanguard.db --output soc_report.pdf
python3 main.py sync --db ../vanguard.db --dry-run
ANTHROPIC_API_KEY=sk-... python3 main.py analyze --db ../vanguard.db --limit 10
# ...or drop a toolkit/.env file (see toolkit/.env.example) so keys don't need
# to be passed inline every run -- env_loader.py loads it automatically.
```

### Configuration (.env)
Both halves of VANGUARD support an optional local `.env` file as a dev convenience (never overwrites real environment variables, which always win). See `core/.env.example` and `toolkit/.env.example` for the full list. In production, prefer systemd's `EnvironmentFile=` (Go daemon) or a real secrets manager / inherited shell env (Python toolkit) over a checked-out `.env` file.

| Variable | Consumed by | Purpose |
|---|---|---|
| `TELEGRAM_BOT_TOKEN` | Go daemon (`vanguard serve`) | Bot token for real-time Telegram alerts on Autopilot ban / Panic Mode toggle. Unset = alerts disabled (safe no-op). |
| `TELEGRAM_CHAT_ID` | Go daemon (`vanguard serve`) | Destination chat ID for the above. Both must be set together to enable alerts. |
| `VANGUARD_JWT_SECRET` | Go daemon | HMAC secret for signing dashboard session JWTs (falls back to an ephemeral generated secret if unset — sessions won't survive a restart). |
| `VANGUARD_ADMIN_IPS` | Go daemon | Comma-separated fail-safe admin IPs Autopilot can never ban. |
| `ANTHROPIC_API_KEY` / `OPENAI_API_KEY` | Python toolkit (`toolkit analyze`) | LLM provider credentials for AI forensic analysis (auto-detected; either enables `analyze`). |
| `VANGUARD_ANTHROPIC_MODEL` / `VANGUARD_OPENAI_MODEL` | Python toolkit | Optional model overrides for the above. |

## Data Architecture
- **Storage**: SQLite (single local file, WAL mode), accessed via GORM (Go) with a pure-Go driver (no CGO), and via Python's built-in `sqlite3` (read-only `mode=ro` URI for the toolkit's analysis/report paths, read-write with a busy timeout for the sync path).
- **Models**: `users`, `system_metrics`, `incidents`, `firewall_rules` — see `core/internal/database/models.go` for exact fields; `toolkit/database.py` mirrors these as Python dataclasses.
- **Risk Scoring**: `Base Severity + Frequency + Threat Reputation (+ Escalation)`, clamped to 0-100, bucketed into LOW (0-29) / MEDIUM (30-59) / HIGH (60-79) / CRITICAL (80-100). The dashboard additionally computes a client-side "Master Threat Posture" composite score from open-incident severity counts + active ban count (presentation only, not persisted).

## User Guide
1. Run `vanguard serve` (see above). On first launch with an empty `users` table, the dashboard's login screen offers an admin bootstrap form instead of a login form.
2. Log in — the dashboard opens on **Command Center**, showing live-polling widgets (risk gauge, system health, resource metrics, threat counters, attack density/mix charts).
3. Use the sidebar (OPERATIONS: Command Center, Incidents, Firewall, Honeypot; PLATFORM: Metrics, Settings) to navigate.
4. From Command Center or the Incidents page, block an offending IP or mark an incident investigated/resolved directly from the UI.
5. Use the Header's Panic Mode button for an emergency lockdown, with a dry-run preview before committing.
6. Periodically (e.g. via cron) run the Python toolkit off-box or on the same host: `analyze` for AI forensic verdicts on recent incidents, `sync` to pull fresh OSINT threat-intel bans, `report` for a shareable SOC PDF.

## Deployment
- **Platform**: Linux host (systemd service recommended); the React dashboard is compiled and embedded into the Go binary at build time — no separate frontend deployment/hosting step.
- **Status**: ✅ Core daemon + REST API + embedded dashboard + Python toolkit all built and live-tested end-to-end in this sandbox.
- **Tech Stack**: Go (Echo, GORM/SQLite) + React 18 (Vite, Tailwind CSS, Recharts, Lucide React) + Python 3 (Typer, ReportLab, Anthropic/OpenAI SDKs).
- **Last Updated**: 2026-09-07

## Repository Structure

```
VANGUARD/
├── core/
│   ├── cmd/vanguard/        # CLI entry point, serve.go, frontend.go (go:embed), dist/ (build output)
│   ├── frontend/            # React + Vite + Tailwind dashboard source (builds into cmd/vanguard/dist)
│   └── internal/
│       ├── api/             # Echo REST API handlers + routes
│       ├── auth/            # JWT auth, bcrypt, session helpers
│       ├── database/        # GORM models + repository
│       ├── detection/        # Deterministic rule engine + Attack Correlation Engine (correlation.go)
│       ├── firewall/         # UFW/iptables executor, Autopilot, Panic Mode
│       ├── honeypot/          # Decoy listeners
│       ├── metrics/          # CPU/RAM/Disk/Network sampler
│       ├── risk/             # Risk scoring formula (incl. ScoreChain for ATTACK_CHAIN)
│       ├── simulator/        # Synthetic attack simulation scenarios
│       └── thresholds/       # Severity bucket thresholds
├── toolkit/                 # Python ephemeral CLI — AI analyst, threat intel sync, PDF reports
├── lab/                     # Automated Security Test Lab (Docker Compose) -- lab-only exception
│   ├── docker-compose.yml   # victim + attacker services on an isolated bridge network
│   ├── victim/              # Dockerfile + entrypoint.sh: real sshd/nginx/rsyslog + the VANGUARD binary
│   ├── attacker/            # Dockerfile: Alpine + nmap/hydra/curl/jq toolkit
│   └── run-tests.sh         # synthetic-attack orchestration + REST-API detection assertions
├── docs/                    # Architecture & setup guides
├── Makefile                 # build / build-frontend / build-go / test / vet / fmt / clean / toolkit-install
└── README.md
```
