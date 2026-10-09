# Phase 10 — Detection Rule Lifecycle, Explainability, and Safe Tuning

States: Implemented · Tested (automated, Windows) · Verified on Linux (**none**) · Blocked.

## 10.1 Audit: what is configurable today

Base `4bbde6a`. Detection is implemented as one Go function per rule, keyed by `database.IncidentType`; there is **no generic rule engine, rule file format or per-rule on/off switch**, and none was invented. Thresholds are compiled constants in `internal/thresholds`. Operator-controllable today (before this phase): subsystem-level startup flags (`-hostsec`, `-system-posture`, `-intel`, `-honeypot`), the Phase 4 path/allowlist flags, `ExpectedHosts` for Host-header checks. Everything else was fixed at build time.

Design consequence: runtime tuning is offered only for **five simple integer thresholds** that all follow "fires when count > / ≥ value" and are used at exactly one site each in `engine.go`. Making every threshold, window or signature list runtime-configurable would require a broad refactor of ~30 detectors and their tests; that was judged unsafe for this phase and is **deferred**. Windows, signature lists and all Phase 3–6 thresholds remain compiled defaults and are reported as such.

## 10.2 Rule inventory (`GET /api/rules`, read-only, any authenticated user)

Built by `internal/rules` from the implementation, not hand-written claims:

| Field | Source |
|---|---|
| `rule_id`, category, description, prerequisites | static catalog; a test fails if any `IncidentType` declared in `models.go` is missing (or an unknown one is listed) |
| `base_severity` | `risk.BaseSeverity` (test asserts equality) |
| `evidence_kind` | `database.IsCorrelatedType` |
| `limitations` | the same text stored in incident provenance (`detection.LimitationFor`) |
| `settings[]` | effective value, unit, **source** (`compiled default` / `operator tuning revision N`) and `tunable` |
| `enabled`, `disabled_by` | reflects startup flags; `can_disable_individually` is always `false` because no code path supports it |
| `automated_response` | derived from the scoring bounds and Autopilot policy: IOC-only and host-local rules → never; others → "possible in principle" iff `base + 30 + 30 + 25 ≥ threshold`. Explicitly an **upper bound, not a prediction** |

Unknown provenance is never shown as known; secrets are not part of any setting.

## 10.3 Safe configuration changes

`GET /api/rules/tuning` (read) · `POST /api/rules/tuning/preview` (read-only, never mutates) · `PUT /api/rules/tuning` (**admin**) · `POST /api/rules/tuning/rollback` (**admin**).

| Property | Implementation |
|---|---|
| Input surface | five integers by fixed key. Requests are decoded with unknown fields **rejected**, ≤ 4 KiB; there is no expression, script or rule text anywhere |
| Validation | each value inside a fixed range (e.g. SSH 3..500, flood 50..100 000); all-or-nothing — a request with one bad field applies nothing |
| Preview vs applied | preview returns the merged candidate, per-field diff and errors with `applied:false` |
| Weakening protection | any change that **raises** a threshold (rule fires less readily) needs `acknowledge_weakening:true`; lowering is allowed. No range permits a value < 1 |
| Concurrency | compare-and-swap on `expected_revision` inside one transaction → `409 conflict`; a concurrent test shows exactly one of N racing updates wins |
| Audit | append-only `rule_tuning_revisions`: revision, UTC time, authenticated actor (never fabricated), sanitized reason ≤ 256, kind apply/rollback, diff, whether weakening was acknowledged. Not tamper-evident (local SQLite) |
| Rollback | creates a **new** revision that restores the preceding revision's values (history stays linear; first override rolls back to compiled defaults); refused at revision 0 or on a stale revision |
| Persistence / last known valid | active revision loaded at startup. A **corrupt or out-of-range** stored revision is *not applied*: defaults are used, `load_error` is exposed, runtime health shows `rule_tuning` **degraded**, and an operator can still supersede the bad row (no lock-out) |
| Never automatic | nothing is applied, learned or disabled without an explicit admin request; no rule can be turned off |

Engine integration: the five rule sites read `tuning.Values()` per event (atomic snapshot). Defaults are used when no store is configured, so existing behaviour and tests are unchanged.

## 10.4 Boundary / benign testing

Builds on Phase 8's pairs (`validation_pairs_test.go`). New here: the tuned threshold moves the real boundary in **both directions** (exactly-at stays quiet, one-above fires; a relaxed value suppresses the old default boundary) and a tunable affects only its own rule. Tuning does not alter base severities or the IOC-only cap (asserted).

## 10.5 Explainable detections

The five tunable rules now store a `rule` block in incident evidence: `condition`, `comparison`, `observed`, `threshold`, `window_seconds`, `threshold_source`, `tuning_revision`. It is merged with the existing `provenance` (rule id/revision, observed vs correlated, **limitations** = what the detection does not prove). Redaction and the 16 KiB evidence bound still apply; no raw events are stored. For rules outside the five, evidence is unchanged — their conditions are described in the inventory and in `docs/PHASE8.md`.

## 10.6 Tuning guidance (`GET /api/rules/guidance`)

Per tunable rule, over the last 30 days: incident count and count marked `false_positive` by an analyst. Recommendation tiers: *insufficient evidence* (< 20 incidents), *review this threshold* (≥ 50 % analyst-marked false positives; wording says "suggestion only" and that raising it needs acknowledgement), otherwise *no tuning suggested*. Every item carries a `basis` that states the numbers are **not** precision, recall or a false-positive rate; a test asserts no accuracy wording appears. Nothing is learned from traffic and nothing is applied (`applied_automatically:false`).

## 10.7 Dashboard

New **Detection Rules** page: inventory (expandable: settings with provenance, prerequisites, limitations, auto-response statement) and Tuning. Read-only inspection is available to every user; edit fields, Preview, Apply and Rollback are rendered **only for admins**, Apply stays disabled until the preview is clean, a reason is given and (if weakening) the acknowledgement is ticked; conflicts and ignored stored tuning are shown.

## Results (Windows; no Linux/Docker/CGO)

| Command | Result |
|---|---|
| `gofmt -l .` | clean |
| `GOOS=linux go vet ./...` | clean |
| `go build ./...` | OK |
| `go test -json ./...` → `tools/valreport` | **546 passed, 0 failed, 11 skipped** (skips are not passes: 10 Unix-permission `hostsec` tests + 1 tail line-delivery test) |
| `npx vitest run` | 6 files, 61 tests pass |
| `npx vite build` | OK |

New Go tests: tuning 10 (ranges, preview purity, ack, atomicity, concurrent winner, conflicts, rollback, restart/corruption/lock-out) · rules 6 (completeness vs declared types, grounding, provenance, flags, auto-response honesty, guidance gating) · api 5 (admin-only changes, viewer read access, ack/conflict/invalid/unknown-field/oversize, rollback, concurrent applies) · detection 4 (boundary both ways, per-rule isolation, explanation content, cap). Frontend: 8.

## Limitations / deferred / residual risk

- Only 5 thresholds are tunable; windows, signature lists, risk weights, Autopilot threshold and all other rules are compiled. No per-rule disable exists by design.
- Raising a threshold is permitted (with acknowledgement) and genuinely weakens detection; an admin account compromise could do so. The audit trail records it but is local and not tamper-evident.
- Tuning applies to new events only; in-memory sliding-window counts accumulated under an older threshold are not recomputed.
- Guidance rests on analyst labels and says so; it cannot detect missed attacks.
- Multi-instance coordination does not exist (single-host product).
- Linux runtime behaviour, `go test -race` (new concurrency: atomic snapshot swap, CAS apply), Docker lab and real `ufw` remain **pending**; Phases 4–9 stay awaiting Linux verification.

## Acceptance

| Criterion | State |
|---|---|
| Inventory grounded in the real rule set | done (completeness test) |
| Validation rejects malformed/unsafe settings | done, tested |
| Changes auditable, never silently weaken | done, tested |
| Boundary + benign coverage | done for tunables; others per Phase 8 |
| Evidence explains finding and limits | done for the five tunables + provenance everywhere |
| Recommendations explainable and non-automatic | done, tested |
| Concurrency / failure / regression tests | done |

**Status: Implemented — Verification Pending.**
