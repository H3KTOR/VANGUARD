# Phase 6 — Local Threat Intelligence, IOC Correlation & Threat Hunting

Progress log. States: `not started` < `in progress` < `implemented` < `tested` < `verified (target env)`; `deferred` carries a reason.

## Milestone 0 — Audit and baseline

- Base revision `ee47077` (Phase 5), branch `main`, clean tree. Environment: Windows 10, Go 1.27, no WSL/Docker/CGO.
- Baseline `go test ./...` (Windows), observed at the base revision: pass — `cmd/vanguard`, `api`, `auth`, `database`, `firewall`, `metrics`, `notify`. Fail (carried over from earlier phases, environmental): 10 attack-chain tests in `detection`, 7 Unix-permission tests in `hostsec`, `TestDecoyListenerReportsConnection` in `honeypot`. No Phase 6 code existed yet, so none of these are Phase 6 failures.

### What already exists (and what does not)

| Item | Finding |
|---|---|
| `detection.ThreatIntelChecker` (`IsMalicious(ip)`) | Interface consulted by ~20 rules for the +15 "reputation" risk bonus. **No Go implementation is wired**: `cmd/vanguard` never sets `Config.ThreatIntel`, so the engine uses `noopThreatIntel` and the bonus never applies. |
| Python `toolkit threat_sync` | Pulls the public `ipsum` feed and inserts **bans** straight into `firewall_rules`. It is a different mechanism (online, ban-oriented, no provenance/expiry/confidence) and is left untouched. |
| IOC storage / import / matching / hunting | **None exist.** |
| `hostsec.Finding.RemoteAddrs` | Process findings already carry outbound `ip:port`; `correlateHostFinding` checks them with `intel.IsMalicious` (so wiring a real checker also activates that path). |

### Observable fields (what IOC types can actually be matched)

| IOC type | Matchable against | Source field | Limitation |
|---|---|---|---|
| `ip` (v4/v6) | every log-driven `Event` (`SourceIP`: auth.log, access log, honeypot, port touch); host process findings' `RemoteAddrs` | `Event.SourceIP`, `Finding.RemoteAddrs` | Source address as logged; behind a proxy/CDN/NAT it is the proxy. |
| `domain` | HTTP requests **only when the access-log format records Host** | `Event.Host` | Stock nginx/Apache "combined" format does not log Host → such events are *not observable*, not "clean". Exact host match only (no subdomain/suffix matching). |
| `url` | same as domain, plus request target | `Event.Host` + `Event.Path` | Needs Host; scheme is not logged so scheme is ignored when matching; query string included (exact). |
| `sha256` | FIM / binary-integrity / config-drift findings (hash VANGUARD itself computed) | new `Finding.SHA256` | Only files already in a monitored set; no filesystem sweep. |
| file paths | **Not supported** (deliberately): a path is not an indicator of compromise without a hash and would collide with FIM semantics. | | |

Hunting needs history, but VANGUARD keeps **no raw event history** (only incidents). Phase 6 therefore records a bounded `ioc_matches` table (indexed, pruned by age and row cap) and hunts over that joined to incidents; it does not introduce unbounded event retention.

### Design decisions

1. **Tables** (additive AutoMigrate): `iocs` (unique on `type,value,source`), `ioc_imports` (one row per import attempt, incl. rejected ones), `ioc_matches` (bounded).
2. **Normalization**: ip → `netip` canonical form (IPv4-mapped IPv6 unmapped to IPv4); domain → lowercase ASCII, trailing dot removed, LDH labels, ≤253 chars, non-ASCII must be supplied as punycode; url → http/https only, host lowercased, default port dropped, fragment dropped, userinfo rejected (secrets), ≤2048 chars; sha256 → 64 lowercase hex.
3. **Import** (`vanguard-ioc` v1, JSON or JSONL, offline, ≤10 MiB, ≤50 000 records, field caps): structural errors (bad header/version/oversize/malformed stream) reject the whole import with nothing written; invalid *records* are rejected individually and reported (or abort everything with `strict`). One DB transaction. Additive by default; `replace_source` can remove a source's stale indicators only if the feed is non-empty, ≥80 % of records valid, and not a >50 % shrink (unless `allow_shrink`). Records already expired at import are counted and not stored. Re-import never re-enables an operator-disabled indicator.
4. **Matching**: immutable snapshot (maps keyed by normalized value) swapped atomically; rebuilt on any change and every 5 min; `expires_at`/`enabled` re-checked at match time. Capped at 100 000 active indicators (excess reported, not silently dropped). No DNS, no network, no substring matching.
5. **Incident integration**: new type `ioc_match` (a match with no behavioral rule firing would otherwise produce nothing). Base 35; confidence adds high +10 / medium +5 / low −10 / unrated 0; the **total is clamped to ≤55**, below the default auto-ban threshold (60), so an IOC alone never triggers Autopilot. Other detectors' incidents from a matching IP are **enriched** (`ioc_matches` in evidence) and get the existing +15 reputation bonus only for `medium`/`high` confidence IOCs. `evidence_kind` = `observed` (a direct exact match), never correlated. Dedup: per (IOC, source, field) with a 1 h cooldown, separate from the 2 min behavioral window.
6. **Hunting**: `GET /api/hunt/matches` over `ioc_matches` ⋈ `incidents`; parameterized GORM, `limit` ≤ 200, `offset` ≤ 10 000, stable `matched_at DESC, id DESC`.
7. **Optional correlation (Workstream H)**: see decision section below.

### Plan and acceptance criteria

| # | Milestone | Acceptance criteria | State |
|---|---|---|---|
| 1 | IOC model + normalization | Tables migrate on a pre-existing DB; normalization table-tested incl. v6, mapped v4, trailing dots, userinfo URLs, bad hashes; dup prevention; enable/disable/delete | not started |
| 2 | Import | v1 format documented + fixtures; limits; per-record vs structural failure; atomic; replace-source guards; provenance rows; failed import leaves prior data intact | not started |
| 3 | Matcher | Exact per type; expired/disabled never match; snapshot swap race-free; bounded; multi-IOC per event | not started |
| 4 | Incident integration | `ioc_match` incident + enrichment; clamp ≤55; confidence semantics; dedup + recurrence; no auto-ban | not started |
| 5 | Hunting API + UI | Bounded/parameterized; malformed filters → 400; UI shows active/expired/disabled honestly; frontend tests | not started |
| 6 | Lab | `lab/run-phase6.sh` deterministic scenarios | not started |
| 7 | Final verification + docs | Honest status | not started |

### Outstanding verification from earlier phases (tracked separately, unchanged)

- Phase 4: `lab/run-phase4.sh` not run. Phase 5: `lab/run-phase5.sh` not run; real-`ufw` verification unexercised.
- `go test -race ./...` never run (no CGO here) — covers Phases 4, 5 and 6.
- Linux execution of the 7 Unix-permission `hostsec` tests; the 10 `detection` failures' root cause is uninvestigated; the `honeypot` failure was never baseline-compared.

### Risks

- Schema: three additive tables. Behavior change: wiring a real `ThreatIntelChecker` makes the previously dormant +15 reputation bonus active (only for medium/high-confidence IP IOCs).
- Imported strings are inert data: never executed, never fetched, never logged raw beyond bounded lengths.
