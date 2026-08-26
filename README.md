# VANGUARD v3.0

Lightweight AI-Assisted Linux IDS/IPS & Security Monitoring Platform.

## Project Overview
- **Goal**: A low-footprint, host-based Intrusion Detection/Prevention System for a single Linux server. A single ~25MB Go binary tails auth/web logs, detects attacks with deterministic rules, scores risk dynamically, auto-mitigates via UFW/iptables, and serves a full React dashboard embedded in the same binary. A separate ephemeral Python CLI (run via cron, 0 idle RAM) handles AI analysis, threat-intel sync, and PDF reporting.
- **Architecture**: Go core (always-on daemon + embedded REST API + embedded React dashboard) + Python toolkit (ephemeral CLI) + SQLite (shared local file, WAL mode). See the full design in the original project brief.

> **Deployment note**: VANGUARD is a traditional host-based Linux daemon (log tailing, raw sockets for the honeypot, direct UFW/iptables execution, an embedded static dashboard). It is **not** a Cloudflare Pages/Workers application — there is no serverless deployment story for this project. It is built, tested, and run directly in this sandbox (a Linux environment) and is intended to ultimately run as a systemd service on a real Linux host.

## Current Status: Steps 1–5 Complete (Go Core + REST API + React Dashboard + Python Toolkit)

### ✅ Completed

**`core/internal/database`** — GORM + SQLite (pure-Go `glebarez/sqlite` driver, no CGO) data layer:
- Models: `User`, `SystemMetric`, `Incident`, `FirewallRule` (see field docs in `models.go`).
- Composite, query-pattern-driven indexes: `idx_incidents_ip_time`, `idx_incidents_type_time`, `idx_firewall_ip_active`, `idx_metrics_timestamp`, etc.
- `Open()` configures WAL mode + busy timeout for safe concurrent read/write from the API, detection engine, and the read-only Python toolkit.

**`core/internal/detection`, `risk`, `thresholds`** — deterministic rule engine (SSH brute force, honeypot triggers, etc.) sharing the `Base Severity + Frequency + Threat Reputation (+ Escalation)` risk-scoring formula.

**`core/internal/firewall`** — UFW/iptables wrapper with an in-memory mock executor (safe for sandboxes/dev) or the real `ufw` CLI, TTL ban reaper (Autopilot maintenance loop), Panic Mode/lockdown preview + enter/exit, fail-safe admin-IP whitelist.

**`core/internal/honeypot`** — decoy listeners (SSH/MySQL/HTTP-like ports) that log any connection as a honeypot-trigger incident.

**`core/internal/metrics`** — periodic CPU/RAM/Disk/Network sampling with configurable retention.

**`core/internal/auth`** — JWT-based session auth (bcrypt password hashing, first-run admin bootstrap).

**`core/internal/api`** — full Echo REST API: `/api/auth/*`, `/api/dashboard/summary`, `/api/incidents*`, `/api/firewall/*`, `/api/metrics/*`, `/api/simulate/*`, `/api/panic/*`, `/api/health`.

**`core/internal/simulator`** — Attack Simulation Mode (`vanguard simulate ssh-bruteforce|honeypot [-dry-run]`) for generating realistic synthetic incidents/bans without touching a real system, used throughout development/testing of the API and dashboard.

**`core/cmd/vanguard`** — CLI + daemon entry point:
- `vanguard serve [flags]` — runs the full daemon (log tailing, detection, Autopilot, metrics sampler, honeypot listeners, REST API) **and serves the embedded React dashboard** on the same HTTP port.
- `vanguard simulate <scenario> [flags]` — synthetic attack simulation.
- `vanguard help` — usage.

**`core/frontend`** (Step 4) — React + Vite + Tailwind CSS + Recharts + Lucide React dashboard, built to `core/cmd/vanguard/dist` and embedded into the Go binary via `//go:embed all:dist`:
- **Command Center** (`/`): Master Threat Posture circular risk gauge (0–100, client-computed from open-incident severity mix + active bans) with quick action buttons; System Health panel (Agent/SQLite/Honeypot/Uptime); CPU/RAM/DISK progress-bar cards + Network I/O sparkline; 4 severity threat counters (Critical/High/Medium/Low) with trend text; Attack Density AreaChart (last 60 minutes); Threat Mix donut chart.
- **Incidents**, **Firewall**, **Honeypot**, **Metrics**, **Settings** pages.
- Login screen with first-run admin bootstrap flow; dark-mode toggle; Panic Mode modal with dry-run preview.
- `src/api/vanguardClient.js` — typed fetch wrapper for every REST endpoint above, with JWT Bearer auth and centralized 401 handling.
- `cmd/vanguard/frontend.go` — `mountFrontend(e)` serves `index.html` + `/assets/*` from the embedded FS, with SPA catch-all fallback so client-side page state works without server routes; falls back to a clean 404 JSON error (not a crash) if the dashboard hasn't been built yet.

**`toolkit/`** (Step 5) — ephemeral Python 3 CLI (0 idle RAM, run via cron or on demand):
- `database.py` — read-only (`mode=ro`, hard SQLite-enforced, never risks the daemon's WAL file) and read-write (generous `busy_timeout`) connection helpers, typed dataclasses, and query/insert helpers.
- `ai_analyst.py` — auto-detects `ANTHROPIC_API_KEY` or `OPENAI_API_KEY`, sends recent incidents to the LLM for a structured forensic verdict (JSON schema), with per-incident graceful degradation (a failed/misconfigured call never aborts the whole batch).
- `threat_sync.py` — fetches the public `ipsum` OSINT malicious-IP feed, filters out private/loopback/reserved ranges and low-corroboration entries, inserts new bans into `firewall_rules`.
- `pdf_reporter.py` — generates a multi-page SOC PDF (ReportLab platypus) summarizing metrics, severity breakdown, top offending IPs, and recent incidents.
- `main.py` — Typer CLI: `toolkit analyze`, `toolkit sync`, `toolkit report`, with Rich console output.

### 🚧 Not Yet Implemented / Known Gaps
- Exact pixel-for-pixel visual match against the originally referenced screenshot could not be verified in this environment (the reference image file was never present in the sandbox); the dashboard was built from the detailed widget spec and is functionally complete, but should be visually spot-checked against the original design if/when it's available.
- No automated test suite for the React frontend or Python toolkit (Go core has `go test ./...` coverage for api/auth/detection/firewall/honeypot/metrics).
- 2 npm audit findings (1 moderate, 1 high) in frontend dependencies — not yet triaged.
- Main dashboard JS bundle is ~630KB (174KB gzipped) — a single chunk; code-splitting not yet applied.

### Next Steps
1. Visual QA pass against the original reference design once available.
2. Add frontend/toolkit test coverage.
3. Triage npm audit findings; consider `manualChunks` code-splitting if bundle size becomes a concern.
4. systemd unit file + install docs for running `vanguard serve` as a real host service.

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
```

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
- **Last Updated**: 2026-08-26

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
│       ├── detection/        # Deterministic attack-detection rule engine
│       ├── firewall/         # UFW/iptables executor, Autopilot, Panic Mode
│       ├── honeypot/          # Decoy listeners
│       ├── metrics/          # CPU/RAM/Disk/Network sampler
│       ├── risk/             # Risk scoring formula
│       ├── simulator/        # Synthetic attack simulation scenarios
│       └── thresholds/       # Severity bucket thresholds
├── toolkit/                 # Python ephemeral CLI — AI analyst, threat intel sync, PDF reports
├── docs/                    # Architecture & setup guides
├── Makefile                 # build / build-frontend / build-go / test / vet / fmt / clean / toolkit-install
└── README.md
```
