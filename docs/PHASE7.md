# Phase 7 — Behavioral Threat Hunting & Investigation Intelligence

States: `not started` < `in progress` < `implemented` < `tested` < `verified (target env)`; `deferred` carries a reason.

## Milestone 7.0 — Audit and baseline

- Base: `9d93476` (Phase 6), plus `150cc5a` (test-environment fixes, see below). Clean tree at start. Windows 10 / Go 1.27; no WSL, Docker or CGO.
- Baseline `go test ./...` at `9d93476`: 18 failures (10 attack-chain, 7 Unix-permission, 1 honeypot). At `150cc5a` all packages pass on Windows with 7 tests *skipped* (need Unix perms). **Root causes found** (not merely "pre-existing"): the 10 `detection` failures were test helpers formatting syslog timestamps in UTC while the production parser interprets them in the host's local zone (fix verified on this UTC+3 machine); the honeypot failure was a test client that closed with unread data (Windows RST). Neither was a production defect. This does **not** discharge the Linux verification gaps for Phases 4–6.

### What is actually persisted (and therefore usable)

| Record | Fields that exist | Timestamp semantics |
|---|---|---|
| `incidents` | id, type (= detector/rule id), source_ip, severity, risk_score, status, attempt_count, metadata JSON (provenance, score_breakdown, per-detector evidence, `ioc_matches`), detected_at, resolved_at | `detected_at` = event time (UTC); `created_at` = insert time |
| `incident_events` | kind (`status_change`, `response`, `verification`), actor, from/to, outcome, detail, at | UTC, write time |
| `ioc_matches` | ioc_id, incident_id, kind (direct/enrichment), field, context, source_ip, matched_at | event time (UTC) |
| `iocs`, `ioc_imports` | indicator + import provenance | — |
| `firewall_rules` | ip, incident_id (**no index today**), banned_at, unban_at, is_active, source | UTC |

**Not persisted** (so never fabricated): raw events/log lines; scanner-health **history** (status board is in-memory, current state only); per-host identifiers (single-host product — the only actor identity is `source_ip`; host-local findings use the `127.0.0.1` sentinel); constituent incident IDs of correlated incidents (`attack_chain` / `web_attack_chain` / `high_confidence_compromise` store stage *counts* and a textual description, not references); the exact time an automatic ban expired or was lifted.

### Design decisions

1. **Timeline** (`GET /api/incidents/:id/timeline`): merge of bounded per-source queries — incident detection, `incident_events`, the incident's `ioc_matches`, the incident's `firewall_rules`, analyst notes. Each entry: `at` (RFC 3339 UTC), `source` subsystem, `ref` (table + id), `kind`, `provenance` ∈ `observed | derived | correlated | analyst | response`, `summary`, optional bounded `detail`. Order: `at`, then fixed source rank, then id. Paginated (≤200). A `data_gaps` list states what the timeline cannot contain for this incident (no raw events; no scanner-health history; correlation constituents not stored when the incident is correlated; telemetry limitations from provenance).
2. **Graph**: deferred as a visualization; delivered as a small bounded **relationship list** (`GET /api/incidents/:id/graph`) whose edges are only explicit references: `incident —matched→ indicator` (via `ioc_matches`), `incident —triggered_response→ firewall rule` (via `firewall_rules.incident_id`), and `incident —shares_indicator→ other incident` (both matched the same indicator; explicitly *not* a same-actor claim). Node cap 50, ≤10 other incidents per indicator, depth 1. No time-proximity edges; no constituent edges for chain incidents because the data does not exist.
3. **Investigation query** (`GET /api/investigate/incidents`): filters id, status, rule (type), severity, risk_min/max, since/until, ip, ioc_id, has_ioc_match, evidence_kind (mapped to the closed set of correlated types — no JSON scan), response_outcome, verification_outcome. Default window 30 days unless `id`, `ip`, `ioc_id` or an explicit range bounds the scan; the applied window is echoed back. Limit ≤200, offset ≤10 000, stable `detected_at DESC, id DESC`. Response carries `retention` notes so an empty page is not read as "never happened".
4. **Analyst notes** (`incident_notes`): authenticated identity only (claims email; otherwise rejected), ≤2 000 chars, ≤100 live notes per incident, control chars stripped, soft delete, every create/edit/delete also recorded as an `incident_events` entry of kind `note` (without the text). Notes never feed risk, evidence or response. Not tamper-proof.
5. **Export** (`GET /api/incidents/:id/export`): `vanguard-investigation` v1 JSON: incident (metadata redacted), timeline, graph, notes (text redacted), data gaps, export time. Shared redaction (`internal/redact`) is applied to nested metadata and free text; 2 MiB cap with explicit truncation; deterministic order; no integrity claim.
6. **UI**: unified timeline with provenance badges and data-gap list in the incident panel, related-incidents list (not a decorative graph), notes, export button. Investigation query UI deferred (API only).

### Plan and acceptance criteria

| # | Milestone | Acceptance criteria | State |
|---|---|---|---|
| 1 | Shared redaction + notes model | `internal/redact` (keys + free text + PEM); notes CRUD with auth/limits/audit events | tested |
| 2 | Timeline + data gaps | deterministic order, tie-break, pagination bounds, legacy incidents, no fabricated entries | tested |
| 3 | Relationship list | only explicit-reference edges, caps, no proximity edges | tested |
| 4 | Investigation query | validated filters (400), parameterized, bounded, honest retention note | tested |
| 5 | Export | redaction round-trip, size cap, deterministic | tested |
| 6 | Dashboard | provenance/gaps/notes/export, empty + legacy safe, Vitest | tested (Vitest); investigation-query UI deferred |
| 7 | Final verification + docs | honest status | partially done (see results) |

### Explicit non-goals

No raw-event retention; no attack-narrative generation; no cross-actor merging; no external lookups; no case management beyond notes; no new infrastructure.

### Outstanding verification (tracked separately; not changed by Phase 7)

Docker lab scripts for Phases 4, 5, 6 never executed; `go test -race ./...` never run (no CGO here); 7 Unix-permission `hostsec` tests need Linux; real-`ufw` verification outstanding.

## Results (Windows dev machine, Go 1.27; **no Linux, no Docker, no CGO**)

### Delivered

| Workstream | Delivered | Evidence |
|---|---|---|
| 7A Timeline | `GET /api/incidents/:id/timeline`: detection, indicator matches, audit events (status / response / verification / note), ban rules, notes; UTC, deterministic `(time, source rank, source, id)` order, provenance per entry, bounded pages (≤200), per-source caps disclosed, explicit `data_gaps` | `investigate_test.go` (ordering + same-instant ties + mixed time zones, pagination, no fabrication, legacy/empty metadata, correlated + host-local disclosures, cap disclosure, verification failure visible); API test |
| 7B Relationships | Delivered as a **depth-1 relationship list** (`/graph`), not a visualization. Edges: `matched`, `matched_context`, `triggered_response`, `shares_indicator` (disclaims same-actor); every edge cites a stored record; 50-node and 10-per-indicator caps flagged via `truncated`. **Not possible and not claimed:** edges to the constituents of correlated incidents (not stored), actor/host identity edges, time-proximity edges | graph tests incl. same-IP-same-moment incident staying unlinked, duplicate references, fan-out bound |
| 7C Queries | `GET /api/investigate/incidents`: id, rule, status, severity, risk range, since/until, ip, ioc_id, has_ioc_match, evidence_kind (closed type set, no JSON scan), response/verification outcome; default 30-day window echoed back; limit ≤200, offset ≤10 000; retention notes. Scanner failures are **not** queryable (history is not persisted) and this is stated | query tests + 21 invalid-filter API cases (400) |
| 7D Notes | `incident_notes`: authenticated author only, 2 000 chars, 100 live/incident, control chars stripped, soft delete, create/edit/delete audited without text, never touches evidence/risk/status | notes test, API test |
| 7E Export | `GET /api/incidents/:id/export`: `vanguard-investigation` v1, redacted nested metadata and note text (`internal/redact`), only the requested incident, 2 MiB cap with explicit truncation, deterministic, explicit not-signed disclaimer | round-trip, redaction, determinism, size-limit tests |
| 7F Dashboard | Incident panel: provenance-labelled timeline, collapsible data gaps, related incidents (explicit references only), notes (rendered as text), export button, existing response status/plan kept | 6 new Vitest tests (18 in `IncidentEvidence.test.jsx`); `vite build` OK |
| 7G Regression tests | Ordering, ties, time zones, missing fields, duplicate refs, unrelated incidents separate, bounds, invalid filters, nested-secret redaction, export limit, restart persistence, legacy DB without `incident_notes`, verification failure | see above |

### Commands and actual results

| Command | Result |
|---|---|
| `gofmt -l .` (core) | clean |
| `GOOS=linux go vet ./...` | clean |
| `go build ./...` | OK |
| `go test ./...` (Windows) | **all 13 packages pass** (the earlier environment failures were root-caused and fixed in `150cc5a`; 10 `hostsec` tests *skip* on non-Unix and are not counted as passes) |
| New Go tests this phase | 19 test functions (redact 5, investigate 12, api 2; many table-driven) |
| `npx vitest run` | 4 files, 48 tests pass |
| `npx vite build` | OK |

### Defects found while building (fixed)

- Graph fan-out cap was silent → now flagged `truncated`.
- Redaction's per-value truncation was silent in exports → export now discloses it.
- `firewall_rules.incident_id` was unindexed (timeline/graph lookups would scan) → indexed.

### Limitations / deferred

- No investigation-query UI (API only). No graph visualization (no relationships that justify one). No retained raw events, scanner-health history, or correlation constituents — each is disclosed per incident as a data gap.
- Redaction is heuristic (key names + common secret shapes); exports are not signed or tamper-evident; notes are not tamper-evident.
- Authentication: any authenticated analyst may add/edit/delete notes (authorship is recorded, not enforced per-owner).

### Not verified (blockers, tracked separately)

- `go test -race ./...` (no CGO); Linux execution of the 10 Unix-only `hostsec` tests; Docker lab scripts for Phases 4, 5, 6 (none run) — **no Phase 7 lab scenario was written** (Phase 7 behaviour is covered by API-level tests; a lab run adds nothing the unit/API tests do not, and none would be claimed); real-`ufw` verification.

### Definition of Done

| Item | State |
|---|---|
| Audit + baseline recorded (incl. root-caused failures) | done |
| Timeline only defensible persisted data; provenance visible | done (tested) |
| Queries bounded + parameterized; invalid → 400 | done (tested) |
| Missing telemetry honest (data gaps, retention notes) | done (tested) |
| Export bounded + redacted | done (tested) |
| Notes distinct from evidence | done (tested) |
| Dashboard tests | pass (48) |
| gofmt / vet / build | pass |
| Race tests | **blocked** (no CGO) |
| Linux-specific behaviour / Docker scenarios | **unverified** |
| Phase 4–6 gaps remain visible | yes |

**Conclusion: Implemented — Verification Pending.**
