# Phase 13 — API Security, Authorization & Abuse Resistance

States: **Implemented** · **Tested (Windows)** · **Verified on Linux (none)** · **Blocked**. Nothing here has run on Linux, in Docker, under `-race`, or in CI.

## 13.0 The actual trust boundary

- One HTTP listener serves `/api/*` and the embedded dashboard. **Authentication is a bearer JWT** (`Authorization: Bearer …`, HS256, default 24 h) stored by the dashboard in browser storage. There are **no cookies**, so classic CSRF does not apply (no ambient credential is attached by the browser). No CSRF-token machinery was added.
- Roles: `admin`, `viewer`. There is no user-management API (accounts are created by bootstrap/`register`; disabling or demoting is a database operation).
- TLS is **not** provided by VANGUARD. Anything beyond loopback needs a TLS reverse proxy or an SSH tunnel.
- Before this phase: default bind `:8080` (every interface), CORS `*`, no Host check, no body limits, no server timeouts, no login throttling, a stateless token never re-checked against the account, and the client address taken from forgeable `X-Forwarded-For`.

## 13.1 Defects found by reading the code (each now has a test)

| # | Finding | Impact | Fix |
|---|---|---|---|
| 1 | `POST /api/firewall/block`, `/whitelist`, `/incidents/:id/block` passed the target string straight to `ufw`; the fail-safe whitelist compares exact strings | `"any"`, `"0.0.0.0/0"` or a covering CIDR would (with real UFW) lock out everyone incl. the admin **and** bypass the whitelist; any spelling variant of a whitelisted IP bypassed it | `firewall.NormalizeIP`: one valid unicast address only; canonical form used everywhere (`Ban`, `Whitelist`, Panic Mode preview/enter) |
| 2 | `ReconcileOnStartup` re-applied **every** active rule incl. `source=simulator` rows; `POST /api/simulate/*` accepted any `ip` | an admin-triggered (or CSRF-able) demo could become a real block after a restart, including `0.0.0.0/0` | simulated and non-single-IP rows are skipped (and counted); simulate input validated |
| 3 | CORS `*` + open first-run `register` | any web page could create the first admin on a fresh instance | no CORS by default (explicit `-allowed-origins` only; `*` refused), cross-origin writes refused, Host allow-list, bootstrap only from loopback unless `-allow-remote-bootstrap` |
| 4 | Count-then-create in `register` | two simultaneous first-run requests could both become admin | serialized (test: 12 racing → exactly one admin) |
| 5 | Default bind `:8080` | fresh install reachable from the network with open bootstrap | default `127.0.0.1:8080`; warning when bound wider |
| 6 | `c.RealIP()` trusted `X-Forwarded-For`/`X-Real-IP` | login throttling bypass; Panic Mode's "keep this admin reachable" address was attacker-controlled | `ExtractIPDirect` (TCP peer only; no trusted-proxy model exists) |
| 7 | JWT never re-checked | disabled/demoted/deleted account (or a restore with `--exclude-users`) stayed valid up to 24 h | every request re-reads the account: must exist, be active, email must match; **role comes from the database** |
| 8 | Login: "disabled account" returned 403 before the password check; unknown user skipped bcrypt | account enumeration by status code and by timing | one uniform 401 after equal hashing work |
| 9 | No throttling; unbounded concurrent bcrypt | online guessing; CPU exhaustion | per-address failure limiter (10 / 15 min → 429 + `Retry-After`), ≤ 4 concurrent hashes |
| 10 | No body limit, no HTTP server timeouts | memory/slowloris | 64 KiB body (IOC import: 10 MiB + 64 KiB), `ReadHeaderTimeout` 10 s, read 30 s, write 90 s, idle 120 s, 64 KiB headers |
| 11 | `duration_minutes`, `attempt_count`, … unbounded; `time.Duration(n)*Minute` overflows | negative/instant-expiring bans; huge simulations | explicit ranges (ban ≤ 1 year, simulation ≤ 5 000 events / 24 h) |
| 12 | Malformed list filters silently ignored; `offset` unbounded; firewall rule list unbounded | wrong/huge results, deep scans | 400 on bad filters; limit ≤ 500, offset ≤ 10 000; firewall list paged |
| 13 | Admin errors echoed `err.Error()` (could carry command output/paths/tokens) | information leak | `safeMsg` = secret redaction + path masking + length cap |
| 14 | IOC enable/disable/delete/import, firewall actions, Panic Mode, simulation left no actor record | not auditable | `admin_audits` table (+ `GET /api/audit/admin`) |
| 15 | `-admin-ip` accepted any text; `-jwt-secret` any length | silently protects nothing / guessable signing key | startup refuses non-single-IP admin entries and secrets < 32 chars |

## 13.2 Route inventory (authoritative copy: `routeTable` in `internal/api/routes_matrix_test.go`)

A route that exists but is missing from that table **fails a test**, so the table cannot drift from the code. "Gate" = at most one run at a time (+ minimum gap in the daemon); "Guard" = Phase 12 expensive-read guard (503 when busy). Sensitive = returns data an attacker would value.

| Route | Access | Mutates | Notes |
|---|---|---|---|
| `GET /api/health` | public | no | status + uptime only |
| `POST /api/auth/login` | public | last-login only | throttled; uniform failure |
| `POST /api/auth/register` | public → admin | yes | first run: loopback only (or opt-in); afterwards a **live** admin token; email/password validated; audited (`user.create`) |
| `GET /api/auth/me` | user | no | |
| `GET /api/dashboard/summary` | user | no | Guard |
| `GET /api/incidents`, `/:id`, `/:id/events` | user | no | list: Guard, strict filters |
| `PUT /api/incidents/:id/status` | user | yes | lifecycle transition, actor in `incident_events` |
| `GET /api/incidents/:id/{timeline,graph,export}` | user | no | Guard; export redacted + size-bounded |
| `GET\|POST /api/incidents/:id/notes`, `PUT\|DELETE …/:nid` | user | yes (POST/PUT/DELETE) | author from token; soft delete; not tamper-evident |
| `GET /api/incidents/:id/response-plan` | user | **no** (preview) | tested non-mutating in earlier phases |
| `POST /api/incidents/:id/block` | **admin** | yes | single IP, whitelist applies, audited |
| `GET /api/investigate/incidents`, `GET /api/hunt/matches` | user | no | Guard, bounded |
| `GET /api/detectors/status`, `/api/health/runtime` | user | no | runtime health also answers (signature-checked) when the DB is down |
| `GET\|POST /api/backup`, `GET /api/backup/:name/verify` | **admin** | POST yes | POST gated + audited (`backup_audits`); no download/restore/paths |
| `GET /api/retention`, `GET /api/audit/admin` | **admin** | no | read-only |
| `GET /api/rules`, `/rules/tuning`, `/rules/guidance` | user | no | |
| `POST /api/rules/tuning/preview` | user | **no** | |
| `PUT /api/rules/tuning`, `POST /api/rules/tuning/rollback` | **admin** | yes | CAS revision, own audit table |
| `GET /api/intel/status`, `/iocs`, `/iocs/:id`, `/imports` | user | no | |
| `PUT\|DELETE /api/intel/iocs/:id` | **admin** | yes | audited |
| `POST /api/intel/import` | **admin** | yes | gated, 10 MiB bound, audited without content |
| `GET /api/firewall/rules`, `/status` | user | no | rules paged; status error text sanitized |
| `POST /api/firewall/block`, `/whitelist`, `/unban/:id` | **admin** | yes | validated single IP, audited |
| `GET /api/metrics/latest`, `/history` | user | no | `hours` 1–168 |
| `GET /api/simulate/scenarios` | user | no | |
| `POST /api/simulate/:scenario` | **admin** | yes | bounded, gated, audited; simulated bans never reach the OS firewall |
| `GET /api/panic/preview`, `/status` | user | **no** | |
| `POST /api/panic/enter`, `/exit` | **admin** | yes | `confirmed=true` required, audited |

Authorization semantics were **not** changed for any existing route except where a stricter live check applies (finding 7).

## 13.3 Browser and network controls

- `Host` must be an IP literal, `localhost`, or listed in `-allowed-hosts` (`*` disables). Counter `host_rejected`.
- CORS: none by default. `-allowed-origins https://ops.example.test` adds an **exact** allow-list; `*`, paths, credentials, non-http(s) are refused at startup.
- State-changing methods carrying an `Origin` that is neither same-host nor allow-listed → 403 (defence in depth for login/register).
- Headers: `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, `Cache-Control: no-store` on `/api/*`. **No CSP** was added (risk of breaking the embedded build without a browser to verify).
- No route fetches URLs or accepts a URL to fetch (checked: none exist), so there is no SSRF surface.
- Dev note: the Vite dev server proxies `/api` with a different `Origin`; for `npm run dev` start the daemon with `-allowed-origins http://localhost:5173`.

## 13.4 Rate limits and gates (only where abuse was shown)

| Operation | Control | Why |
|---|---|---|
| login / registration failures | 10 per address per 15 min → 429; ≤ 4 concurrent bcrypt; ≤ 10 000 tracked addresses | online guessing, CPU |
| backup create | one at a time, 30 s gap (daemon) | disk/IO (≤ 50 × ≤ 2 GiB) |
| IOC import | one at a time | CPU/memory/DB writes |
| simulate | one at a time, 1 s gap | writes that look like real incidents |
| expensive reads | Phase 12 guard (4 concurrent, 15 s) | SQLite cannot cancel a running statement |

Deliberately **not** done: per-account lockout (it would let anyone lock the administrator out), a global per-user write budget (would throttle legitimate scripted triage). Sessions already issued keep working during a login lockout. Clients behind one reverse-proxy address share one login budget. Hits are counted (component `api_security` in `GET /api/health/runtime`, plus `refused` rows in the audit trail) and logged as `address + count` only — never emails or passwords.

## 13.5 Audit (`admin_audits`)

Actor (authenticated email), role, action, identifier-level target, `ok | refused | failed`, short detail. Written for: user creation, firewall block/unban/whitelist, incident block, panic enter/exit, IOC enable/disable/delete/import, simulation, and every gate refusal. **Never** stored: bodies, tokens, passwords, feed contents. Append-only by convention, never auto-deleted, **not tamper-evident**. If the audit write itself fails after the operation succeeded, it is logged and the operation is not reported as failed (it already happened). Tuning and backups keep their own earlier audit tables; panic/ban reasons also carry the actor's email.

## 13.6 Verified safeguards that did not change

Admin whitelist (now stricter: canonical addresses), Panic Mode two-step confirmation and preview (preview remains non-mutating; tested), response preview, verification, rollback paths — untouched; existing 564-test baseline still passes.

## 13.7 Tests (this phase)

`routes_matrix_test.go`: inventory completeness; every protected route → 401 for none/garbage token; every admin route → 403 for a viewer **and database/firewall state unchanged**; every mutating route → 403 for a foreign Origin; every route survives hostile path params and garbage bodies without a 5xx. `sectest_test.go`: live-account re-validation, DB-sourced role, forged/mismatched tokens, uniform login failure, throttling (X-Forwarded-For cannot rotate the key; existing sessions unaffected), bootstrap rules + 12-way race, DB-down fail-closed. `sectest2_test.go`: Host/CORS/Origin/headers/body limits, range & "any" refusals, whitelist spelling variants, reason sanitizing, Panic Mode peer address, simulation bounds/gate, gated operations leave no trace when refused, filter/boundary validation, error leakage, audit contents, IOC audit. `ratelimit_test.go`, `firewall/ip_test.go` (incl. reconcile skipping simulated/invalid rows), `cmd/vanguard/serve_security_test.go`.

## 13.8 Results (Windows, Go 1.27.0)

| Command | Result |
|---|---|
| `gofmt -l .`, `GOOS=linux go vet ./...` | clean / clean |
| `go test -json ./...` → `tools/valreport` | **648 passed, 0 failed, 13 skipped** (Phase 12: 606/0/13). Skips are not passes |
| Real binary: weak secret → exit 2; `-admin-ip 10.0.0.0/8` → exit 2; bad `Host` → 403; foreign `Origin` register → 403; local register → 201; 11 wrong logins → 10×401 then 429 | observed as listed |

## 13.9 Compatibility and migration risks (read before upgrading)

1. **Default bind changed** to `127.0.0.1:8080`. Deployments that relied on the default being `:8080` must pass `-http-addr`. (The shipped systemd unit and lab pass it explicitly.)
2. **Host check**: reaching the API by a DNS name (including through a reverse proxy that forwards its public name) now needs `-allowed-hosts name`. IP-literal and `localhost` access is unchanged.
3. **No CORS** unless `-allowed-origins` is set; the embedded dashboard is unaffected.
4. **First-run bootstrap only from the host itself** (or `-allow-remote-bootstrap`). The Docker lab entrypoint was updated (`-allow-remote-bootstrap -allowed-hosts=victim`) — **lab-written, not executed**.
5. **Tokens are re-validated**: a token for a user missing from the database (for example after restoring a backup made with `--exclude-users`) is rejected until that account exists again.
6. **Stricter inputs** now return 400 instead of being ignored (`since_hours`, `limit`, `offset`, `hours`, unknown fields on tuning/backup/simulate/block bodies, ranges/`any` as IPs). The bundled dashboard sends valid values.
7. `-admin-ip` entries and `-jwt-secret` are validated at startup; a CIDR in `-admin-ip` (which never protected anything) or a short secret now stops the daemon with exit 2.
8. A disabled account now gets the same 401 as a wrong password (was 403).

## 13.10 Remaining limitations (not fixed)

- Bearer token lives in browser storage (XSS-readable); no logout/server-side revocation list beyond disabling the account; no password-change or user-management API; no 2FA.
- No TLS in the daemon; no CSP; no trusted-proxy model (behind a proxy, all clients look like the proxy address, and Panic Mode "keep my IP" keeps the proxy).
- The audit trail and all append-only tables are not tamper-evident.
- Login throttling is per address and in memory (reset on restart).
- JWT secret handling: a secret given via `-jwt-secret` is visible in `ps`; prefer `VANGUARD_JWT_SECRET`.
- `PUT /api/incidents/:id/status` and notes accept any authenticated user by design (analyst workflow); there is no finer permission model.
- Not exercised: Linux, real `ufw` (the IP validation prevents bad targets from reaching it, which is unverified against the real binary), Docker lab, `-race`, a browser.

## Acceptance

| Criterion | State |
|---|---|
| Every route has a documented authorization expectation | done; enforced by a failing test |
| High-risk routes have meaningful negative tests that check state | done |
| Input/output bounds enforced | done (body, header, time, filters, durations, pages) |
| Abuse controls justified and observable | done (limits, counters, audit, logs without secrets) |
| Sensitive errors/secrets not exposed | done for the paths found; not a proof of absence |
| Response safeguards unchanged or stronger | done |
| Trust boundary and limits documented | this file |

**Status: Implemented — Verification Pending.**
