# Phase 15 — Tamper-Evident Audit & Evidence Integrity

States: **Implemented** · **Tested (Windows)** · **Verified on Linux (none)**.
A local hash chain makes *inconsistent* edits detectable. It does **not** make records immutable, and it does not protect against someone who can write the database file **and** recompute the chain. Read §15.3 before relying on it.

## 15.1 Audit architecture as found

| Record store | Who writes | Deleted / altered by VANGUARD? | In backups |
|---|---|---|---|
| `admin_audits` (Phase 13) | API handlers (actor = authenticated email) | never | yes |
| `backup_audits` | CLI, API, restore | never | yes |
| `retention_runs` (incl. policy changes) | CLI, daemon | never | yes |
| `rule_tuning_revisions` | tuning API | `status` flips active→superseded (by design); rows never deleted | yes |
| `incident_events` (lifecycle, response, verification) | engine, Autopilot, API | **bounded per incident (200) and deleted with an incident by retention** | yes |
| `incident_notes` | analysts | soft delete (flag), hard delete with the incident by retention | yes |
| `ioc_imports` / `ioc_matches` | import, matcher | pruned by age/count | yes |

Facts that shaped the design: all of these are ordinary SQLite rows reachable by anyone with write access to the file (and the API offers no update/delete route for the append-only ones — checked in the route matrix tests); several writers run concurrently (API goroutines, daemon loops, CLI processes); GORM `AutoMigrate` adds tables additively; retention and pruning legitimately delete some audit-like data.

**Consequence:** a ledger over records that are *legitimately deleted* cannot tell a legal deletion from tampering without a second mechanism. So the ledger covers only the four tables VANGUARD never prunes: `admin_audits`, `backup_audits`, `retention_runs`, `rule_tuning_revisions`. **`incident_events`, notes, IOC imports/matches, firewall rules and users are NOT covered** (retention's own audit row records the incident-ID ranges it removed, and that row *is* covered). This is a deliberate narrowing, not an oversight.

## 15.2 Audit coverage matrix

Result vocabulary in `admin_audits`: `ok` (operation completed), `refused` (a safeguard or validation said no; nothing changed), `failed` (attempted and did not complete). A *verified outcome* (e.g. a ban confirmed in `ufw`) lives in `incident_events` (response → verification), unchanged from Phase 5. Rows are written **after** the outcome is known, so there is no "ok" row for an operation that failed; a crash between the operation and its audit row can lose the row (documented gap).

| Action | Recorded | Where |
|---|---|---|
| Login success | ✅ new (Phase 15) | `admin_audits` `auth.login` (no password/token) |
| Login failures | counted + **lockout transition recorded once per address window** (individual failures are deliberately *not* rows: an attacker could otherwise grow the table) | `auth.lockout`, health counters |
| Admin/user creation | ✅ | `user.create` (actor `bootstrap` for first run) |
| Role/account changes | ❌ no API exists (database operation); the next request's live account check applies them but nothing records the change | gap |
| Firewall block / unban / whitelist | ✅ ok / refused / failed | `firewall.*` |
| Panic Mode enter / exit | ✅ | `panic.*` |
| Incident lifecycle | ✅ | `incident_events` (**not ledger-covered**) |
| Response execution & verification | ✅ | `incident_events` (**not ledger-covered**) |
| Incident block via API | ✅ | `incident.block` |
| Rule tuning apply / rollback | ✅ with actor | `rule_tuning_revisions` (ledger-covered) |
| Rule tuning *preview* | ❌ by design (read-only) | — |
| IOC import / enable / disable / delete | ✅ (feed contents never stored) | `ioc.*` |
| Analyst notes | ✅ author + soft-delete markers | `incident_notes` (**not ledger-covered**) |
| Backup create | ✅ | `backup_audits` |
| Backup verify (API) | ✅ new — `ok`, or `failed` when the backup is reported invalid | `backup.verify` |
| Backup restore | ✅ inside the restored DB | `backup_audits` |
| Retention execute / dry run / policy change | ✅ | `retention_runs` |
| Configuration (flags/env) | ❌ not stored in the database | gap |
| Rejected privileged operations | ✅ refusals by gates/safeguards (`refused`); 403s for non-admins are *not* rows | partial |

## 15.3 The mechanism (`database/ledger.go`)

- Table `audit_ledger`: `seq` (1,2,3… gapless), `format` (=1), `sealed_at`, `kind` (source table), `record_id`, `record_digest`, `prev_hash`, `hash`, `legacy`.
- **Canonical form**: every field is written as `uvarint(length) ‖ bytes`, behind a domain-separation tag and a field count — no delimiter exists that content could forge (tested). Entry hash = SHA-256(canon(tag, format, seq, sealed_at, kind, record_id, record_digest, prev_hash, legacy)); record digest = SHA-256(canon(per-table tag, every content column)). Mutable bookkeeping (`rule_tuning_revisions.status`) is excluded.
- **Sealing is deferred, not transactional with the writer**: one serialized sealer (`SealPending`) appends entries for records with ids above each table's sealed frontier, ≤ 2000 per call, in **one transaction** (a failure leaves nothing — tested with a trigger). It runs every minute in the daemon, once more before shutdown, and via `vanguard audit seal`. Why not seal inside each writer's transaction: several unrelated code paths and processes write audit rows; coupling them to a shared hash head would make unrelated operations fail under SQLite write contention.
- **Cost of that choice:** a record can be altered or removed **before it is sealed** (≤ ~1 minute) without detection, and verification reports the not-yet-sealed tail (`unsealed_records`) instead of treating it as a defect.
- **Detected** (tests): modified record, deleted record, forged replacement of a deleted record, record inserted below the frontier without an entry, deleted/reordered ledger entry (gap), edited link, edited entry (digest, time, format), unknown format; a corrupt or unreadable record is a finding, never silently skipped.
- **Not detected by the chain alone** (tested, asserted as the stated limit): history rewritten consistently (edit the record, recompute every later digest/hash), and truncation of the newest entries.
- **Legacy**: the first seal of a database seals pre-existing records with `legacy=true`; integrity *before that moment* is unestablished and the count is reported.

## 15.4 Optional external trust anchor (`ledger_checkpoint.go`, `vanguard audit …`)

`vanguard audit keygen -out K` (32 random bytes, hex, mode 0600, **never overwrites**); `vanguard audit checkpoint -key-file K -out CP` writes the ledger head (seq, hash, time, key id) with an **HMAC-SHA256** under that key, refusing if the ledger does not verify. `vanguard audit verify -checkpoint CP -key-file K` additionally checks the MAC and that the database still holds the same entry at that sequence: a consistent rewrite of earlier history, or truncation to before the checkpoint, is then reported (`checkpoint_mismatch`, `checkpoint_entry_missing`; both tested), a doctored checkpoint is `checkpoint_forged`, a different key is `checkpoint_key_mismatch` (reported as a key problem, not as tampering).

- The key is **never generated into or stored in the database**; nothing is created automatically; ordinary operation does not depend on it.
- It is only an independent anchor if you keep the key and the checkpoints **off the audited host**. Key and checkpoint on the same machine as an attacker with root add nothing. A checkpoint says nothing about entries after it, nor about whether records were true when written.
- Lost key: existing checkpoints can no longer be authenticated; the ledger and verification keep working; make a new key and checkpoint. Rotation: keep old checkpoints with their key; the key id tells them apart. No remote timestamping or cloud storage is used or required.

## 15.5 Verification (read-only, bounded)

- CLI `vanguard audit verify [-from N] [-max N] [-json]` (exit 0 nothing inconsistent in what was examined / 1 discrepancy / 3 could not run) and admin-only `GET /api/audit/integrity?from_seq=&max_entries=` (≤ 100 000 entries per pass, guarded like other expensive reads). Only `SELECT`s; a test proves the database is unchanged, even when damaged.
- Reports: `completed`/`partial` + `next_seq`, `entries_examined`, head seq/hash, `legacy_entries`, `unsealed_records` per table, findings (kind, ledger seq, table, record id — **never record content**, capped at 50), and `ok`.
- `ok:true` means *no inconsistency in the entries examined, under the stated assumptions*. The API response and CLI output carry that sentence, name the tables **not** covered, and the response says it is "not proof of authenticity". A missing record is reported as `missing_record` — never as evidence that an action did not happen.
- **Visible failure:** the daemon verifies hourly and reports component `audit_integrity` in `GET /api/health/runtime`: **failed** on any finding, degraded if sealing fails or the ledger exceeds one pass, `not_yet_observed` until the first verification.

## 15.6 Backups and retention

`audit_ledger` is an ordinary table, so backups carry it (manifest lists it) and restore reproduces the identical head (tested: same seq and hash after restore; the restore's own `backup_audits` row is sealed afterwards and the chain stays valid). A tampered restored copy is detected. Retention cannot make the chain look complete when it is not, because it never deletes covered tables, and its own `retention_runs` rows are sealed. A real legacy database (`legacy_1208a94.db`) gains the new table additively and seals as legacy. Verification is **full-history** for covered tables (bounded per pass). There is no downgrade path; an older build will treat `audit_ledger` as unknown and `doctor` reports "newer VANGUARD".

## 15.7 Tests added

`database/ledger_test.go` (12): valid chain across all four tables, unsealed tail, modified/deleted/forged records, every entry-tampering case, consistent rewrite passes the chain but is caught by a checkpoint (and truncation), checkpoint forgery/key mismatch/key parsing, concurrent writers + sealers (90 records, gapless), all-or-nothing seal, batch cap + partial/windowed verification (incl. tamper at the window boundary), verification is read-only, canonical serialization is unambiguous. `api/audit_integrity_test.go`: admin-only, read-only, detects tampering without echoing content, input bounds, no mutating verb, login/lockout/backup-verify audited with no password stored, failures not row-per-attempt. `backup/ledger_compat_test.go`: ledger through backup → restore → retention, tamper after restore, legacy database. `cmd/vanguard`: the audit loop reports healthy then **failed** after tampering. Route matrix gains `GET /api/audit/integrity`.

## 15.8 Results (Windows, Go 1.27.0)

| Command | Result |
|---|---|
| `gofmt -l .`, `GOOS=linux go vet ./...` | clean, clean |
| `go test -json ./...` → `tools/valreport` | **683 passed, 0 failed, 16 skipped** (Phase 14: 666/0/16); skips are not passes |
| Real binary: `retention set -confirm` → `audit seal` (legacy:true) → `audit keygen` → `audit checkpoint` → `audit verify -checkpoint` | ok:true, exit 0; second `keygen` refused, exit 2 |

## 15.9 Limits and compatibility

- Not proof against a privileged local attacker without an off-host checkpoint/key; unsealed tail (~1 min); `incident_events`, notes, IOC data, firewall rules, users, configuration not covered; no record of role changes (no API); a crash between an operation and its audit row loses the row.
- Cross-process sealing relies on the primary key on `seq`; a CLI `audit seal` racing the daemon fails one side with an error to retry — no corruption (not stress-tested on Linux).
- New table + new audit rows (`auth.login`, `auth.lockout`, `backup.verify`) are additive. Login now writes one row per successful sign-in. Nothing was verified on Linux.

**Status: Implemented — Verification Pending.**
