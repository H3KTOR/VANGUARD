# VANGUARD v3.0

Lightweight AI-Assisted Linux IDS/IPS & Security Monitoring Platform.

## Project Overview
- **Goal**: A low-footprint, host-based Intrusion Detection/Prevention System for a single Linux server. A single ~25MB Go binary tails auth/web logs, detects attacks with deterministic rules, scores risk dynamically, auto-mitigates via UFW/iptables, and serves a full React dashboard embedded in the same binary. A separate ephemeral Python CLI (run via cron, 0 idle RAM) handles AI analysis, threat-intel sync, and PDF reporting.
- **Architecture**: Go core (always-on daemon + embedded REST API + embedded React dashboard) + Python toolkit (ephemeral CLI) + SQLite (shared local file, WAL mode). See the full design in the original project brief.

> **Deployment note**: VANGUARD is a traditional host-based Linux daemon (log tailing, raw sockets for the honeypot, direct UFW/iptables execution, an embedded static dashboard). It is **not** a Cloudflare Pages/Workers application — there is no serverless deployment story for this project. It is built, tested, and run directly in this sandbox (a Linux environment) and is intended to ultimately run as a systemd service on a real Linux host.

## Current Status: Steps 1–5 + Attack Correlation Engine + Automated Security Test Lab + VANGUARD Mega Expansion Phase 1 (Host Security) + Phase 2 (Process/File/Network Correlation, System Binary Integrity) + Phase 3 (Advanced Web Security Detection) Complete

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

**`core/internal/hostsec` (continued) + `core/internal/detection`** (VANGUARD Mega Expansion, Phase 2: "Process + File + Network Correlation") — adds three more features on top of Phase 1, still following the same Detection → Evidence → Risk → Correlation → Response pipeline and the same zero-duplicate-detection-engine rule:
- **Shared `pathBaselineWatcher` engine** (`path_watcher.go`) — Phase 1's `fim.go` was refactored into a thin, differently-configured wrapper around a new generic path-diffing engine (paths/category/incidentType/scannerName/criticalPaths/notes), so Feature 8 (System Binary Integrity) could reuse the exact same diff/report/baseline machinery as FIM instead of standing up a second near-duplicate detector. All 5 pre-existing FIM tests re-verified passing after the refactor with zero behavioral change.
- **System Binary Integrity** (`binary_integrity.go`, Feature 8) — a second `pathBaselineWatcher` configuration monitoring a small, explicit allowlist of security-critical executables (`/bin/sh`, `/bin/bash`, `/usr/bin/sudo`, `/usr/bin/su`, `/usr/sbin/sshd`, `/usr/bin/passwd`, `/usr/bin/ssh`, `/usr/bin/curl`, `/usr/bin/wget`, `/usr/bin/nc` by default) — deliberately never a filesystem walk of `/bin`, `/sbin`, `/usr/bin`, `/usr/sbin` wholesale, per the mega-prompt's own "do not hash the entire filesystem by default" constraint. Every change raises `SYSTEM_BINARY_INTEGRITY_VIOLATION` (HIGH tier); unlike FIM, no path here is auto-escalated to CRITICAL. Configurable via `-binary-paths` (comma-separated extra paths, env `VANGUARD_BINARY_PATHS`).
- **Process Anomaly Detection** (`process.go`, Feature 6) — a periodic best-effort `/proc` walk building a lightweight process inventory (PID/PPID/UID/command/executable path/best-effort outbound TCP connections via `/proc/net/tcp` + fd-to-socket-inode matching), detecting: an executable unlinked from disk while still running (fileless-malware/anti-forensics indicator, via the kernel's `" (deleted)"` `/proc/<pid>/exe` suffix); a process running from a world-writable/temp directory; a shell/interpreter spawned directly by a network-facing service (classic post-RCE reverse-shell pattern); and an abnormal process-creation burst (period-over-period new-PID-count diff). Every finding raises `SUSPICIOUS_PROCESS` and is explicitly labeled **BEST-EFFORT DETECTION** (no eBPF/kernel visibility, no exec-time hooking, no process ancestry history — a short-lived process invisible to two consecutive scan ticks is simply never seen). Deliberately does NOT duplicate PrivEsc's own "unexpected root process" best-effort check — that stays PrivEsc's exclusive signal. Deduped on composite `(pid, reason)` baseline keys (not just the underlying fact) so a still-running anomalous process is reported once, while a genuinely new occurrence on a freshly-recycled PID still fires; a `cleanupExitedPIDs` sweep prunes baseline rows for PIDs no longer live, keeping storage bounded.
- **Process → File → Network Correlation** (`internal/detection/correlation_hostsec.go`, Feature 7) — `HostCorrelator` tracks a sliding window (`HostCorrelationWindow`, 10 min) of "Sensitive File Activity" timestamps fed by every FIM/Binary-Integrity finding. When a `SUSPICIOUS_PROCESS` finding arrives, `Engine.correlateHostFinding` (in `engine_hostsec.go`) checks for corroborating evidence — recent file activity within the window, and/or a Threat Intelligence hit on any of the finding's discovered outbound `RemoteAddrs` — and, only if at least one is present, raises an additional `HIGH_CONFIDENCE_COMPROMISE` (CRITICAL tier, base severity 85) on top of the standalone Suspicious Process incident. A Suspicious Process finding with neither signal stays exactly what it already is; correlation only fires on the mega-prompt's own worked example ("suspicious process → accesses sensitive file → creates network connection → destination has malicious reputation").
- Both new scanners wired into `hostsec.Manager` (Process every 1 min, Binary Integrity every 2 min) alongside the Phase 1 five.
- 3 new `IncidentType`s (`SUSPICIOUS_PROCESS`, `SYSTEM_BINARY_INTEGRITY_VIOLATION`, `HIGH_CONFIDENCE_COMPROMISE`) and 2 new `HostBaselineCategory`s (`system_binary`, `process`) added to `internal/database/models.go`; 3 new `risk.BaseSeverity` entries.
- 23 new Go unit tests: 5 for `BinaryIntegrityWatcher`, 12+ for `ProcessDetector` (using an `evaluate(procs, firstScan)` dependency-injection seam over a synthetic `[]ProcessInfo` snapshot, since a live PID inventory — unlike a file path — cannot be meaningfully "rooted" under a tmpdir for testing) plus pure-function tests for the `/proc/net/tcp` parsers, and 7 for the new `HostCorrelator`/`correlateHostFinding` logic (no corroboration stays standalone; FIM-sourced and Binary-Integrity-sourced file activity both trigger; a malicious outbound connection alone triggers; a clean outbound connection does not; out-of-window file activity does not; dedupe suppresses repeats).
- Not yet wired into this phase: Docker lab attack scenarios for any of the 7 Phase 1+2 host-security detectors, and a dedicated dashboard summary widget (the generic `/api/incidents?type=...` feed already surfaces all 8 new incident types with no API changes needed). (Still true as of Phase 3 — Phase 3 added lab scenarios for its own 9 web-security detectors + the Web Attack Chain only, not for Phase 1/2's host-security detectors.)

**`core/internal/detection`** (VANGUARD Mega Expansion, Phase 3: "Advanced Web Security Detection") — nine new indicator-based web-attack detectors plus a new attack-chain correlation extension, all wired through the exact same `createIncident()` → Autopilot → notification choke point as every prior rule (no new pipeline, no rewrite, no new infrastructure), and every detector's doc comments explicitly document its **visibility limitation** (what it can and cannot see from log/request data alone — VANGUARD has no packet capture, no WAF, no application-level instrumentation):
- **Password Spraying** (`rules_auth_abuse.go`, `state_auth_abuse.go`) — flags many distinct usernames each receiving only a handful of failed-auth attempts within a sliding window (the "low-and-slow, one-password-many-accounts" shape), backed by `AuthAbuseTracker`, a per-IP rolling (username → attempt-timestamps) map.
- **Credential Stuffing** (same tracker/file) — flags a much larger distinct-username count with a high overall failure ratio within the window (the "many accounts, few attempts each, but a lot of accounts" shape) — a distinct threshold/shape from Password Spraying sharing the same underlying evidence structure, not a duplicate detector.
- **Web Shell Indicators** (`rules_web_shell.go`) — `classifyWebShellRequest` flags suspicious request-path shape via three independent, combinable signals: a web-shell-associated file extension (`.php`, `.jsp`, `.asp`, `.aspx`, etc.), a request path under a known upload/writable directory, and a suspicious query parameter (`cmd`, `exec`, `shell`, etc.). Any single signal is enough to raise the standalone (lenient, LOW/MEDIUM) `web_shell_indicator` incident — this is deliberately path-shape-only, since VANGUARD never inspects file contents, so it cannot and does not claim a shell is actually present, only that the request shape resembles one.
- **SSRF Indicators** (`rules_ssrf.go`) — flags outbound-fetch-style parameters (`url=`, `callback=`, `target=`, etc.) whose value resolves to a private/loopback/link-local/reserved address or the cloud-metadata IP (`169.254.169.254`) — a request-shape indicator only; VANGUARD cannot confirm the server-side fetch actually happened.
- **OAST / Out-of-Band Interaction Indicators** (`rules_oast.go`) — flags outbound-fetch-style parameters pointing at known OAST/interaction-tracking domains (`*.oast.fun`, `*.burpcollaborator.net`, etc.) — again request-shape only; VANGUARD has no visibility into whether the callback actually fired.
- **Host Header/Virtual Host Abuse** (`rules_host_header.go`) — flags a Host header that doesn't match any configured virtual host, or that itself looks like an SSRF/internal target (loopback/private/metadata IP as Host) — requires the optional trailing Host field in the web log line (see the nginx `log_format` note in the lab section below); when that field is absent, this detector is a documented no-op rather than a false negative disguised as coverage.
- **HTTP Protocol Anomaly** (`rules_protocol_anomaly.go`) — flags a burst of requests using non-standard/invalid HTTP methods within a short window (generic tracker shared with Request Smuggling — see below).
- **Request-Smuggling Indicators** (`rules_request_smuggling.go`) — flags a burst of requests carrying both `Transfer-Encoding: chunked` and a `Content-Length` header together (the classic TE.CL/CL.TE desync precondition) — a header-shape indicator only; VANGUARD cannot observe the actual backend/frontend parser disagreement.
- **API Abuse Detection** (`rules_api_abuse.go`, `state_api_abuse.go`) — flags a single IP hitting an abnormally high number of distinct `/api/*`-shaped resource paths within a 1-minute window, backed by `APIAbuseTracker` (per-IP rolling distinct-path set).
- **Web Attack Correlation — Web Attack Chain** (`correlation.go`'s `ChainTracker` extended with a 4th "Exploitation" stage; `engine_websec.go`'s `ruleWebAttackChain`) — extends the *existing* Task 3/Phase 1 correlation architecture (never a new engine) with a 4th ordered stage on top of the original Recon → Web-Probing → Auth-Probing three: Exploitation, fed by SSRF/OAST indicator matches and by **multi-signal-only** Web Shell matches (`sig.count() >= 2`, deliberately stricter than the standalone Web Shell Indicator's own single-signal trigger — see the Docker lab section below for exactly why). A full ordered match (web-probing ≥ 3, auth-failures ≥ 3, exploitation ≥ 1, all within a 10-minute `WebAttackChainWindow` and in that relative order) raises a new `web_attack_chain` incident (base severity 75, `risk.ScoreChain`'s existing 1.5x chain multiplier, clamped to 100) through the same `createIncident()` path as the original `ATTACK_CHAIN`.
- 9 new `IncidentType`s added to `internal/database/models.go` (`password_spraying`, `credential_stuffing`, `web_shell_indicator`, `ssrf_indicator`, `oast_indicator`, `host_header_anomaly`, `http_protocol_anomaly`, `request_smuggling_indicator`, `api_abuse`) plus `web_attack_chain` for the correlation extension, each with a matching `risk.BaseSeverity` entry and dedicated `thresholds.go` constants.
- 207 Go tests now pass in `internal/detection` alone (pure evaluation-function unit tests per detector, engine-integration tests driving each rule through the real `Engine`, and 13 pure `ChainTracker` + 11 engine-integration tests for the Web Attack Chain specifically) — all passing, `gofmt`/`go vet`/`go build` clean, and `go test -race` clean for this entire package.
- **Real bug found via genuine Docker E2E testing** (not just unit tests): the lab's own ordinary web-probing traffic (`/phpmyadmin/index.php`, part of Scenario A's routine recon) happened to match the single weakest Web Shell signal (a bare `.php` extension), and an earlier, unconditional feed-in briefly treated that routine probe as "Exploitation stage" evidence — occurring before the auth-probing stage even started, corrupting the chain's required ordering. Fixed by requiring `sig.count() >= 2` (at least 2 of the 3 independent signals) before a web-shell-shaped request counts as exploitation-stage chain evidence, without changing the standalone Web Shell Indicator incident's own lenient single-signal behavior. Locked in with a dedicated regression test (`TestWebAttackChain_SingleWeakSignalWebShellPath_DuringWebProbing_DoesNotPrematurelyFeedExploitStage`) independent of Docker.
- **`lab/` extended** with 10 new attack scenarios (E through N) in `run-tests.sh` exercising all 9 Phase 3 detectors plus the Web Attack Chain end-to-end against the real VANGUARD binary — genuine `hydra`/`curl` traffic, not synthetic log injection — using calibrated volumes matched against the exact threshold constants (e.g. `AuthAbuseTracker` password-spraying/credential-stuffing shapes, `APIAbuseTracker`'s ≥20-distinct-path threshold answered with 50 requests for safety margin against cross-scenario window noise). Also added a custom nginx `log_format` (`lab/victim/nginx-vhost-log.conf`) appending the `Host` header as an optional trailing quoted field — matching `parser_web.go`'s already-optional 8th capture group — since the stock "combined" format never logs Host at all, which the Host Header Abuse scenario needs. **Verified end-to-end: 18/18 lab scenarios PASS** (`docker compose run --rm attacker ./run-tests.sh` against the rebuilt victim image), including the Web Attack Chain firing correctly (risk=100/CRITICAL) as a side effect of the web-probing + auth-probing + exploitation scenarios run in sequence.

### 🚧 Not Yet Implemented / Known Gaps
- Exact pixel-for-pixel visual match against the originally referenced screenshot could not be verified in this environment (the reference image file was never present in the sandbox); the dashboard was built from the detailed widget spec and is functionally complete, but should be visually spot-checked against the original design if/when it's available.
- 2 npm audit findings (1 moderate, 1 high) in frontend dependencies — not yet triaged.
- Docker lab attack scenarios for the 7 Phase 1+2 Host Security detectors are still not present (Phase 3 only extended the lab for its own 9 web-security detectors + Web Attack Chain).
- No dedicated dashboard widgets for any of the 9 Phase 3 incident types or `web_attack_chain` yet — they are visible today only via the generic `/api/incidents?type=...` feed (same situation Phase 2's 8 new incident types were already in; no API changes were needed to surface them).
- Host Header/Virtual Host Abuse detection is a documented no-op whenever the web log line doesn't carry the optional trailing Host field — operators must apply the `lab/victim/nginx-vhost-log.conf`-style `log_format` change (or equivalent) to their own production nginx config for this detector to have any visibility at all; this is not automatic.
- The mega-prompt's remaining phases beyond Phase 3 (e.g. "PHASE 2 — SYSTEM POSTURE": Configuration Posture Auditing, Configuration Drift Detection, Listening Service Drift, Package Drift Detection, and any phases after that) have not been started.

### Next Steps
1. Visual QA pass against the original reference design once available.
2. Triage npm audit findings; consider further code-splitting if bundle size becomes a concern.
3. Add Docker lab attack scenarios exercising all 7 Phase 1+2 Host Security detectors end-to-end (extending `lab/run-tests.sh` / `lab/victim/entrypoint.sh`), mirroring the pattern Phase 3 just established for its own 9 detectors.
4. Add dedicated dashboard widgets/pages for the Phase 2 (host-security) and Phase 3 (web-security) incident types, beyond the generic incidents feed.
5. Continue into the mega-prompt's next phase(s) after Phase 3 (e.g. "PHASE 2 — SYSTEM POSTURE": Configuration Posture Auditing, Configuration Drift Detection, Listening Service Drift, Package Drift Detection) and onward through the remaining phases of the mega-prompt's recommended implementation order.
6. **Known pre-existing issue (not introduced by Phase 1, 2, or 3)**: `go test -race ./...` flags a data race in `internal/firewall.MockExecutor` (unsynchronized map/bool field access from `TestPanicModeAutoRollbackFiresAfterTimeout`'s background auto-rollback goroutine vs. the main test goroutine) — confirmed present before any Phase 1 changes (reproduced against the prior commit) and reconfirmed unchanged after Phase 3. `go test ./...` (without `-race`) passes cleanly across the whole repo, and `go test -race ./internal/detection/...` (the package Phase 3 touched) also passes cleanly with zero races. Should be fixed by adding a `sync.Mutex` to `MockExecutor` in a future pass.

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
- **Last Updated**: 2026-09-20

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
│   │   └── nginx-vhost-log.conf  # Phase 3: custom nginx log_format appending Host header for Host Header Abuse scenario
│   ├── attacker/            # Dockerfile: Alpine + nmap/hydra/curl/jq toolkit
│   └── run-tests.sh         # synthetic-attack orchestration + REST-API detection assertions
│                            # (Scenarios A-D: Phase 0 correlation/scanner/signature/flood;
│                            #  Scenarios E-N: Phase 3's 9 web-security detectors + Web Attack Chain)
├── docs/                    # Architecture & setup guides
├── Makefile                 # build / build-frontend / build-go / test / vet / fmt / clean / toolkit-install
└── README.md
```
