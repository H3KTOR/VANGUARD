# Phase 16 — Authentication Lifecycle & Browser Security

States: **Implemented** · **Tested (Windows)** · **Verified on Linux (none)**. A real-browser check of the production dashboard under the new CSP was done on Windows with headless Edge (§16.4).

## 16.1 Threat model of the authentication as found (after Phase 13)

| Element | Reality in the code |
|---|---|
| Token | HS256 JWT (`user_id`, `email`, `role`, `exp` 24 h default), `Authorization: Bearer` header; no cookies |
| Per-request checks (Phase 13) | signature + expiry, live account (exists, active, email matches), role taken from the database |
| Revocation | **none**: until expiry a stolen token worked; "logout" only deleted the browser copy |
| Browser storage | `localStorage` (`vanguard_token`) — readable by any script that runs in the page |
| Cross-origin / Host | no CORS by default, Host allow-list, cross-origin writes refused (Phase 13) |
| TLS | none in the daemon; loopback by default; reverse proxy for remote use |
| Throttling | per TCP-peer address (forwarded headers ignored), 10 failures / 15 min |
| Restore | `--exclude-users` removes accounts; previously a token for a still-existing id kept working after a restore |
| Fonts | the page loaded Google Fonts from a CDN on every visit (third-party call from a local-first console) |

Attack scenarios considered: stolen token (XSS, shared computer, leaked backup of a browser profile, log/proxy leak); stolen token of a since-demoted/disabled user; operator wants to end a suspicious session; backup restored after a compromise; injected script in the dashboard; framing/clickjacking; DNS rebinding; guessing at the login from one or many addresses.

## 16.2 Server-side sessions (`database.Session`, `api/handlers_session.go`)

Design chosen after looking at the code: the token already carries a standard `jti` slot, and every request already reads the account row, so a **bounded session table** fits with one extra indexed lookup. Rejected: a per-account `token_version` (cannot log out one session or list sessions) and a global deny-list of token ids (grows with every revoked token).

- Login creates a row (`id` = random 128-bit hex = the token's `jti`, user, created, expires = token expiry, TCP-peer address) and issues a token bound to it. A token is honoured only if: signature + expiry valid **and** the account is live **and** the session row exists, belongs to that account, is not revoked and has not expired. A token without a `jti` (every token issued before this release) or with an unknown one is refused — **everyone signs in once after upgrading**.
- Bounds: at most **10 active sessions per account** — creating an 11th **deletes** the oldest (so a login loop cannot grow the table); expired sessions (+1 day) and sessions of vanished accounts are purged every minute, ≤ 1000 per pass.
- Routes: `POST /api/auth/logout` (ends this session), `GET /api/auth/sessions` (own sessions, ids shortened to 8 chars, bounded), `POST /api/auth/sessions/revoke-all` (own, optional `keep_current`), `POST /api/users/:id/revoke-sessions` (**admin**; 404 + `failed` audit row for a missing account). Audited as `auth.logout`, `auth.revoke_all`, `admin.revoke_sessions`.
- **Timing:** revocation is checked on every request against the database, so it takes effect on the **next request**, including after a process restart and for in-flight tokens (tested). There is no cache. Maximum delay: one request already past the middleware when the revocation commits.
- Account changes: disabling/deleting an account and demoting a role are enforced by the existing live-account check on the next request (no API changes those; they are database operations). Nothing automatically revokes sessions on those database edits — it does not need to, because the live check already denies them.
- **Backup/restore:** backups **never contain sessions** (removed from the snapshot, manifest shows 0); a restored database therefore has no sessions and every old token is dead. `--exclude-users` plus restore likewise leaves no valid token. Creating a backup does not touch live sessions.
- Registration by an admin also needs a live session (a logged-out admin token can no longer create accounts).

Tests: logout kills exactly that token (privileged action refused, state unchanged); other sessions unaffected; no-`jti`/unknown/other-account/expired-session tokens refused; list shows only own, shortened ids, one `current`; revoke-all with/without `keep_current`; admin revoke (viewer 403, nothing changed; target dead, admin alive; audit); bound of 10 and eviction; second server instance on the same database (restart) honours live sessions and sees revocations; 8×5 concurrent logins + revocations → no 5xx and ≤ 10 active; purge removes expired + orphan only; backup excludes sessions and restore invalidates the pre-restore token.

## 16.3 Where the token lives — decision: bearer in `localStorage`, kept, with mitigations

Considered and **not adopted now**: an `HttpOnly; SameSite=Strict` session cookie. It would remove the token from script reach, but it also needs (a) CSRF protection (token + origin checks across every state-changing route and the frontend), (b) the `Secure` flag, which cannot be decided correctly behind a TLS-terminating proxy because forwarded headers are deliberately not trusted, and (c) a different local-HTTP story. Doing half of that would add a CSRF surface while claiming a protection. The risk is stated instead:

- **Residual risk:** any script that executes in the dashboard origin can read the token. XSS has not been eliminated.
- **Mitigations now in place:** the CSP below (no inline/eval/third-party script, so injected markup is much harder to run); no third-party origin is loaded; server-side revocation and a real logout (the SPA calls `POST /auth/logout` before forgetting the token; if the server is unreachable the local copy is cleared but the token remains valid until expiry or revocation — said in the code and the docs); per-account session cap; live account/role checks; `Cache-Control: no-store` on API responses; `-jwt-ttl` shortens the lifetime (default still 24 h).
- Revisit when a reverse-proxy/TLS deployment model is decided (a cookie mode can then set `Secure` from configuration).

## 16.4 Content Security Policy and browser headers

Dashboard pages: `default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; manifest-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'; object-src 'none'`. API responses: `default-src 'none'; frame-ancestors 'none'`. Also `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, `Cross-Origin-Opener-Policy: same-origin`, `Cross-Origin-Resource-Policy: same-origin`, `Permissions-Policy` (camera, microphone, geolocation, payment off), and `Strict-Transport-Security` **only when the connection itself is TLS** (a proxy must set it otherwise).

- No `unsafe-inline`, no `unsafe-eval`, no wildcards (asserted by a test). The only change the frontend needed: the Google Fonts `<link>`s were removed from `index.html` (they would be blocked, and a local-first console should not call a CDN); the font stack falls back to the system UI font.
- **Verified against the served production build**: (1) Go test serves the real embedded `dist/` through the real router and checks the page — module script from `/assets/`, no inline script/style/event handler, no third-party URL, assets served with `nosniff`, API CSP on API paths (skips with a reason if the dashboard is not built; CI now builds it first); (2) **real browser run (headless Microsoft Edge via DevTools Protocol), recorded here, not automated in CI:** with a freshly issued session token the login page and then the dashboard rendered (Command Center text present, 34 SVG elements from the charts) with **0** console errors / CSP violation reports; as a negative control an injected inline `<script>` did not run and an injected third-party `<script src>` was blocked (**2** CSP violation reports).
- CSP does not prevent XSS and does not protect a token that was already read. Only the pages and assets I exercised were checked; other routes of the SPA were not individually visited.

## 16.5 TLS and deployment modes

Unchanged and now stated explicitly: VANGUARD does **not** terminate TLS. Local use (default `127.0.0.1`) and SSH-tunnel use are plain HTTP over loopback. Remote access = a TLS reverse proxy that you configure, with its public name in `VANGUARD_ALLOWED_HOSTS`. There is no trusted-proxy model: the peer address seen by VANGUARD is the proxy's (login throttling shares one budget; the sessions list shows the proxy address; Panic Mode "keep my IP" keeps the proxy). Native TLS was **not** added: certificate lifecycle (issuance, renewal, validation) would be a fragile subsystem for little gain next to a standard proxy. Network exposure remains an explicit `-http-addr` choice with a startup warning.

## 16.6 Login abuse resistance

Reviewed, no change in the control, extra evidence: per-address limit (10 failures / 15 min, 429 + `Retry-After`), uniform failure responses, forged `X-Forwarded-For` cannot rotate the key, existing sessions keep working during a lockout, no per-account lockout (it would let anyone lock the administrator out), limiter memory bounded. New: **one `auth.lockout` audit row per lockout transition** and `auth.login` rows for successful sign-ins; credentials and authorization headers are never logged or audited. Known limit: clients behind one proxy share a budget and one noisy client can lock the others out of *login* for up to 15 minutes (sessions are not affected); the recovery is to wait, or restart the daemon (the limiter is in memory).

## 16.7 Test inventory (Phase 16)

`api/session_test.go` (9 tests, 10 with the header test) and `backup/session_compat_test.go` (1) — see §16.2; `api` header tests (CSP, COOP, no HSTS over plain HTTP, no `unsafe-*`); `cmd/vanguard/dashboard_csp_test.go` (served production build); frontend `logout.test.js` (server call precedes forgetting; offline still clears); route matrix extended with the four session routes. Existing Phase 13 tests (origin/Host, throttling, concurrent bootstrap, forged tokens, disabled/deleted accounts, role change) continue to pass.

## 16.8 Results (Windows, Go 1.27.0)

| Command | Result |
|---|---|
| `gofmt -l .`; `GOOS=linux go vet ./...` | clean; clean |
| `go test -json ./...` → `tools/valreport` | **695 passed, 0 failed, 16 skipped** (Phase 15: 683/0/16) |
| `npx vitest run`; `npx vite build` | **69 passed** (8 files); OK |
| Headless Edge against the production binary | 0 CSP/console errors on login page and dashboard; negative control blocked (2 reports) |

## 16.9 Compatibility and limits

- **Everyone must sign in again after the upgrade** (old tokens have no session).
- Restoring a backup signs everyone out (by design).
- The Google Fonts CDN request is gone; the UI uses the system font until a font is bundled.
- A test helper that minted tokens for fake users was replaced by one that creates real accounts and sessions (the assertions are unchanged).
- Remaining: token still in `localStorage`; no cookie mode; no TLS; no `Secure`/HSTS behind proxies unless the proxy sets them; no account-management API (so no password change or role change endpoint, and no automatic session revocation on those database edits); session rows record the peer address only; nothing verified on Linux.

**Status: Implemented — Verification Pending.**
