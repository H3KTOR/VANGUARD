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
| 1 | IOC model + normalization | Tables migrate on a pre-existing DB; normalization table-tested incl. v6, mapped v4, trailing dots, userinfo URLs, bad hashes; dup prevention; enable/disable/delete | tested |
| 2 | Import | v1 format documented + fixtures; limits; per-record vs structural failure; atomic; replace-source guards; provenance rows; failed import leaves prior data intact | tested |
| 3 | Matcher | Exact per type; expired/disabled never match; snapshot swap race-free; bounded; multi-IOC per event | tested |
| 4 | Incident integration | `ioc_match` incident + enrichment; clamp ≤55; confidence semantics; dedup + recurrence; no auto-ban | tested |
| 5 | Hunting API + UI | Bounded/parameterized; malformed filters → 400; UI shows active/expired/disabled honestly; frontend tests | tested |
| 6 | Lab | `lab/run-phase6.sh` deterministic scenarios | lab scripted, not executed |
| 7 | Final verification + docs | Honest status | partially done (see results) |

### Outstanding verification from earlier phases (tracked separately, unchanged)

- Phase 4: `lab/run-phase4.sh` not run. Phase 5: `lab/run-phase5.sh` not run; real-`ufw` verification unexercised.
- `go test -race ./...` never run (no CGO here) — covers Phases 4, 5 and 6.
- Linux execution of the 7 Unix-permission `hostsec` tests; the 10 `detection` failures' root cause is uninvestigated; the `honeypot` failure was never baseline-compared.

### Risks

- Schema: three additive tables. Behavior change: wiring a real `ThreatIntelChecker` makes the previously dormant +15 reputation bonus active (only for medium/high-confidence IP IOCs).
- Imported strings are inert data: never executed, never fetched, never logged raw beyond bounded lengths.

## Workstream H decision (optional correlation) — deferred

Candidate: *IOC match ⇄ behavioral incident from the same source*. The only defensible join key is the source address, and that is already served without a new engine: an unrelated incident from a listed address is **enriched** with the matching indicators (context only) and receives the existing reputation bonus when the source rated the indicator medium/high. Chaining a shared IOC across *different* actors/hosts, or across time proximity alone, would conflate CDN/proxy/NAT/shared hosting and was **not implemented**. An IOC match is never promoted to an attack chain.

## Results (Windows dev machine, Go 1.27; **no Linux, no Docker, no CGO**)

### Delivered

| Area | What exists | Evidence |
|---|---|---|
| Model (M1) | `iocs` (unique `type,value,source`), `ioc_imports`, `ioc_matches` tables (additive AutoMigrate; verified on a pre-existing DB); UTC-normalized times; operator disable pinned | `intel/normalize_test.go` (3 table tests, ~40 cases), `intel/import_test.go` |
| Import (M2) | `vanguard-ioc` v1 JSON/JSONL, limits, per-record vs whole-import rejection, strict, one transaction, replace-source guards, audit row per attempt, `vanguard intel import\|list`, `POST /api/intel/import` | 15 import tests incl. oversize, 50 001 records, 5 000‑record permitted input, mid‑transaction failure rollback, failed import leaves data intact |
| Matcher (M3) | Atomic snapshot, exact ip/domain/url/sha256, expiry re-checked at match time, failed reload keeps snapshot, `IsMalicious` by source confidence | 11 matcher tests (IPv4/6, mapped v4, near-misses, stale-snapshot expiry, concurrency) |
| Incidents (M4) | `ioc_match` incident (direct/observed), graded by source confidence, clamped ≤ 55, 1 h dedupe that still re-reports recurrence, enrichment of unrelated incidents, hash + remote-address matching for host findings, never auto-bans | 16 engine tests (`detection/engine_ioc_test.go`) incl. secret non-leak, multi-indicator, multi-actor, restart |
| Hunting (M5) | `GET /api/hunt/matches` + `/api/intel/*`: parameterized, limit ≤ 200, offset ≤ 10 000, malformed filters → 400, stable order, `[]` not `null` | 5 API tests incl. injection-shaped filter, pagination, auth |
| UI (M5) | “Threat Intel” page: indicators (honest state, warnings), import with per-record report, bounded hunt with plain-language “why it matched”, matcher health | 8 new Vitest tests (42 total) |
| Lab (M6) | `lab/fixtures/ioc-lab-feed.json`, `lab/run-phase6.sh` (scenarios AA–AF) | script `bash -n` OK; the fixture was imported with the real CLI and produced the exact counts the script asserts; **script never executed** |

### Test commands and actual results

| Command | Result |
|---|---|
| `gofmt -l .` (core) | clean |
| `GOOS=linux go vet ./...` | clean |
| `go build ./...` | OK |
| `go test ./...` (Windows) | pass: cmd, api, auth, database, firewall, intel, metrics, notify. Fail: the **same 18 environmental failures as the Phase 6 baseline** (10 attack‑chain in `detection`, 7 Unix‑permission in `hostsec`, 1 `honeypot`). **No new failures.** |
| New Go tests | 50 (intel 29, detection 16, api 5) |
| `npx vitest run` (frontend) | 4 files, 42 tests pass |
| `npx vite build` | OK |

### Defects found by the new tests (and fixed)

- GORM `default:true` silently stored `enabled=false` as `true` (a feed-disabled indicator would have matched).
- Text-compared timestamps in mixed zones would have mis-evaluated expiry → all IOC times forced to UTC on save.
- The repeat-offender count included `ioc_match` incidents, double-counting reputation → excluded.

### False-positive controls

Exact matching only (no substring, no subdomain/suffix); loopback/unspecified/multicast addresses cannot be indicators; scheme‑less URL key requires a logged Host; low‑confidence and unrated IP indicators never raise unrelated incidents’ risk; IOC‑only incidents capped at 55; long dedupe; operator disable; expired never match even from a stale snapshot.

### Known blind spots / limitations

- Domain/URL matching is blind unless the access log records `Host`; the stock combined format does not.
- IP matches are only as good as the logged address (CDN/proxy/NAT).
- Hunting covers recorded matches only (bounded 30 days / 100 000 rows); no raw event history exists, so “no result” is not proof a value was never seen.
- Dedupe is in-memory: a restart can re-raise an already-reported match once.
- The snapshot is capped at 100 000 active indicators; truncation is reported, not silent.
- Redaction/secret hygiene is key-name/field-based: IOC evidence deliberately copies only the listed indicator, source address, method, status and Host — never the raw line, query, user agent or headers — but a hostile `Host` value is stored as logged (bounded).
- Hashes are only those VANGUARD already computes for monitored files; no filesystem sweep.
- `description`/`reference` come from the feed and are shown as text only (React escapes them); they are never fetched or executed.

### Not verified (blockers, not failures)

- `go test -race ./...` — no CGO toolchain (new concurrent code: matcher snapshot swap, dedupe, status board).
- Docker lab: `run-phase4.sh`, `run-phase5.sh`, `run-phase6.sh` — never executed.
- The 7 Unix-permission `hostsec` tests on Linux; the 10 `detection` failures’ root cause remains uninvestigated; the `honeypot` failure was never baseline-compared.
- Real `ufw` response verification (Phase 5).

### Definition of Done

| Item | State |
|---|---|
| Audit + baseline documented | done |
| IOC formats and normalization documented (`docs/intel/FORMAT.md`) | done |
| Import validation + failure behavior tested; prior intelligence survives failed imports | done (tested) |
| Matching exact, bounded, explainable | done (tested) |
| Integration with incident pipeline; risk documented + bounded | done (tested) |
| Hunting parameterized + bounded | done (tested) |
| Frontend tests | pass (42) |
| Regression tests for matches and false positives | done |
| gofmt / vet / build | pass |
| Full tests | partial: all failures classified, all pre-existing/environmental |
| Race tests | **blocked** (no CGO) |
| Docker scenarios | **blocked** (no Docker) |
| Phase 4/5 gaps tracked separately | yes (above and in PHASE5.md) |

**Conclusion: Implemented — Verification Pending.**
