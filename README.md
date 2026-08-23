# VANGUARD v3.0

Lightweight AI-Assisted Linux IDS/IPS & Security Monitoring Platform.

## Project Overview
- **Goal**: A low-footprint, host-based Intrusion Detection/Prevention System for a single Linux server. A single ~25MB Go binary tails auth/web logs, detects attacks with deterministic rules, scores risk dynamically, and can auto-mitigate via UFW/iptables. A separate ephemeral Python CLI (run via cron, 0 idle RAM) handles AI analysis, threat-intel sync, and PDF reporting.
- **Architecture**: Go core (always-on) + Python toolkit (ephemeral) + SQLite (shared local file). See the full design in the original project brief.

> **Deployment note**: VANGUARD is a traditional host-based Linux daemon (log tailing, raw sockets for the honeypot, direct UFW/iptables execution). It is **not** a Cloudflare Pages/Workers application — there is no serverless deployment story for this project. It is built, tested, and run directly in this sandbox (a Linux environment) and is intended to ultimately run as a systemd service on a real Linux host.

## Current Status: Step 1 of N — Go Core Database Layer & Simulation Engine

### ✅ Completed
- **`core/internal/database`** — GORM + SQLite (pure-Go `glebarez/sqlite` driver, no CGO) data layer:
  - Models: `User`, `SystemMetric`, `Incident`, `FirewallRule` (see field docs in `models.go`).
  - Composite, query-pattern-driven indexes: `idx_incidents_ip_time`, `idx_incidents_type_time`, `idx_firewall_ip_active`, `idx_metrics_timestamp`, etc.
  - `Open()` configures WAL mode + busy timeout for safe concurrent read/write from the API and detection engine, and runs `AutoMigrate`.
  - `repository.go` — typed query/write helpers the detection engine, Autopilot, and REST API will build on: incident CRUD/filtering, firewall ban/whitelist checks (`IsWhitelisted`, `IsBanned`, `ActiveBans`, `ExpiredBans`), metric time-range queries, repeat-offender lookups (`CountRecentEventsByIP`) used for the "Threat Reputation" risk component.
- **`core/internal/simulator`** — Attack Simulation Mode:
  - `Simulator` interface + `Registry` (`vanguard simulate --list`).
  - **`ssh-bruteforce`** fully implemented: generates N synthetic failed-SSH-login events (optionally escalating to a failed→successful sequence, which is flagged CRITICAL per spec), computes a risk score using the documented `Base Severity + Frequency + Threat Reputation` formula, persists an `Incident`, and — unless disabled or the IP is whitelisted (fail-safe honored) — creates a TTL `FirewallRule` to represent the Autopilot's automatic response.
  - `honeypot` and `port-scan` are registered (show up in `--list`) but intentionally stubbed (`ErrNotImplemented`) pending the shared detection engine in a later step.
- **`core/cmd/vanguard`** — minimal CLI (`vanguard simulate <scenario> [flags]`, `vanguard help`) wiring the above together end-to-end. Verified manually: dry-run mode, real DB writes, whitelist fail-safe skip, repeat-offender reputation scoring, and clean error handling for unimplemented/unknown scenarios.

### 🚧 Not Yet Implemented
- Log tailing (`/var/log/auth.log`, Nginx/Apache) and the real deterministic **detection engine** (`core/internal/detection`).
- **Firewall execution** (`core/internal/firewall`): actual UFW/iptables calls, TTL ban reaper loop, Panic Mode/lockdown, dry-run preview, emergency rollback.
- REST API (`core/internal/api`) with JWT auth, and the embedded React dashboard.
- Honeypot listener engine (fake SSH/MySQL ports) and the `honeypot` / `port-scan` simulators.
- Python `toolkit/` (AI Analyst, Threat Intel Sync, PDF Reporter) — currently an empty directory placeholder.

### Next Steps
1. `core/internal/detection`: deterministic rule engine (SSH brute force, port scan, web dir scan, path traversal, SQLi/XSS indicators, HTTP flood) sharing the `ScoreBreakdown` risk-scoring approach introduced in the simulator.
2. `core/internal/firewall`: UFW/iptables wrapper with dry-run + fail-safe whitelist + TTL reaper, wired to `FirewallRule`.
3. Flesh out `honeypot` and `port-scan` simulators on top of the shared detection scoring helpers.
4. REST API + JWT auth, then the embedded React frontend (`go:embed`).
5. Python toolkit CLI skeleton (`toolkit/main.py`) — read-only SQLite access, AI Analyst, Threat Intel Sync, PDF Reporter.

## Try It (Step 1 scope)

```bash
cd core
go build -o vanguard ./cmd/vanguard

# List available simulation scenarios
./vanguard simulate ssh-bruteforce -list

# Preview a scenario without touching the database
./vanguard simulate ssh-bruteforce -dry-run -ip 185.220.101.5

# Run for real against a local SQLite file
./vanguard simulate ssh-bruteforce -db vanguard.db -ip 185.220.101.5 -attempts 30 -ban-minutes 60
```

## Data Architecture
- **Storage**: SQLite (single local file, WAL mode), accessed via GORM with a pure-Go driver (no CGO).
- **Models**: `users`, `system_metrics`, `incidents`, `firewall_rules` — see `core/internal/database/models.go` for exact fields.
- **Risk Scoring**: `Base Severity + Frequency + Threat Reputation (+ Escalation)`, clamped to 0-100, bucketed into LOW (0-29) / MEDIUM (30-59) / HIGH (60-79) / CRITICAL (80-100).

## Repository Structure
See `docs/` for the full architecture; top-level layout:

```
VANGUARD/
├── core/       # Go core (single binary) — database, detection, firewall, api, simulator
├── toolkit/    # Python ephemeral CLI — AI analyst, threat intel, PDF reports
├── docs/       # Architecture & setup guides
├── Makefile    # Build commands
└── README.md
```
