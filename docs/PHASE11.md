# Phase 11 — Backup, Restore, Upgrade, and Recovery Safety

States: Implemented · Tested (automated, Windows) · Verified on Linux (**none**) · Blocked.

## 11.1 Data audit: what is, and is not, recoverable

| State | Where | In a backup? |
|---|---|---|
| Incidents, incident events (lifecycle / response / verification / note audit), analyst notes (with authors, soft-delete flags), IOCs (incl. `disabled_by_operator`), IOC imports, IOC match history, rule-tuning revisions, firewall rules, host baselines (FIM, posture, drift, listening, package…), system metrics, backup audit | SQLite file (11 tables + `backup_audits`) | **Yes** |
| User accounts incl. bcrypt password hashes | `users` table | Yes by default; `--exclude-users` removes them (and the freed pages are vacuumed). Without them nobody can log in after a restore until a new admin is created |
| `.env`, JWT secret, Telegram token, CLI flags | files / environment | **No, never** — back these up with your secrets tooling. Restoring does not need the JWT secret; sessions simply re-authenticate |
| OS firewall state (UFW rules) | the kernel/ufw | No — firewall *rules are data* in SQLite and `ReconcileOnStartup` re-applies active bans. Rules created outside VANGUARD are untouched and not restored |
| In-memory state: detection windows, dedupe, health registry, scanner status board, honeypot counters, IOC snapshot, Panic Mode flag | process memory | **Not persisted** → not restorable. Windows/dedupe rebuild from new events; the IOC snapshot reloads from the table; **a restore does not resurrect Panic Mode** |
| Raw events / log lines | never stored | n/a |
| Tailer positions | not stored | n/a (tailing starts at end of file) |

Retention: metrics, IOC matches (30 days / 100 000), import history (500), events per incident (200), notes (100), tuning history are bounded; **incidents themselves have no retention policy** (Phase 9 gap R11), so the database and backups grow with them.

## 11.2 Backups (`internal/backup`)

```
<dir>/vanguard-backup-<UTC>[-label]/
    vanguard.db      SQLite VACUUM INTO snapshot
    manifest.json    format, version, UTC time, size, SHA-256, integrity_check result,
                     per-table row counts, schema fingerprint, users_included, notes
```

| Requirement | How |
|---|---|
| Consistent while writing | `VACUUM INTO` runs in one read transaction; a test commits incident+event pairs continuously while 3 backups are taken and asserts `incidents == incident_events` in every snapshot |
| No unsafe file copy | the live file is never copied; only the SQLite-generated snapshot is |
| Bounded | refuses > 2 GiB (`ErrTooLarge`) and ≥ 50 backups per directory (`ErrTooManyBackups`); nothing is auto-deleted. Temporary space needed ≈ database size |
| Atomic, no partial output | built in `<name>.partial/`, validated, then renamed; failures remove it; `*.partial` is never listed or verifies as valid |
| Never overwrites | an existing name → `ErrExists`; names are strict (`^vanguard-backup-<ts>(-label)?$`) so no path separator or `..` can reach the filesystem |
| Restrictive permissions | directory 0700, files 0600 (POSIX; Windows bits are not meaningful and the test skips there) |
| Integrity metadata | SHA-256, size, `PRAGMA integrity_check`, row counts, schema fingerprint |
| Secrets | `.env`/config never included; accounts optional |

## 11.3 Restore (offline CLI only)

`vanguard backup restore -name N [-db F] [-dir D]` is a **preview** (validates, compares live vs backup counts, mutates nothing, creates no files). Adding `-confirm` performs the restore. Sequence:

1. `Verify`: manifest format/version, file name, size, **SHA-256**, `integrity_check`, row counts, **schema compatibility** — any failure aborts with the reason.
2. Live database must not be open anywhere: an `EXCLUSIVE`-locking-mode probe (an idle running daemon also counts; a write-lock-only check would miss it in WAL mode) → `ErrInUse` otherwise.
3. Copy the backup to a staging file next to the live DB, re-check its SHA-256 and integrity, then **open it with the normal migration** so an unmigratable backup is rejected *before* anything is replaced.
4. Rename the live DB (+ `-wal`/`-shm`) to `*.pre-restore-<ts>` — **never deleted**; each restore gets its own name.
5. Rename the staged file into place; if activation fails, the preserved database is moved back (tested with injected failures: byte-identical afterwards, no leftovers).
6. A `restore` row (actor, backup name, checksum, where the previous DB went) is written **into the restored database**.

Not offered over HTTP, deliberately: restore, and backup download. The API/dashboard (**admin only**) can create, list and verify backups; responses contain names only, never paths.

Authenticity: **not provided.** A checksum inside the backup protects against accidental corruption, not against someone who can edit both files. Backups are unsigned and unencrypted; store them with the access controls you would give the live database.

## 11.4 Tests (all isolated temp dirs; no real database touched)

Round trip incl. incidents, events, notes + authorship, operator-disabled IOC, tuning, users, firewall rules, restore audit · consistency during concurrent writes · 11 tamper/corruption cases (truncated, flipped bytes, empty, garbage, missing db/manifest, bad JSON, wrong format, unsupported version, manifest pointing elsewhere, tampered counts) each: `Verify` invalid, `Restore` refused, **live DB byte-identical and no new files** · newer-schema backup refused with the unknown table/column named · preview purity · restore refused while open (active writer **and** idle) and allowed after close · interrupted restore (before activation; corrupted staging) → original restored · repeated restores keep each previous DB · traversal / name validation / no overwrite / label validation · size and count bounds, stale `.partial` handling · `--exclude-users` leaves no hash bytes in the file · restrictive permissions (POSIX) · database failure mid-backup leaves nothing. API: admin-only (403/401), no paths in responses, audit with authenticated actor, strict body (unknown `path` field rejected), no download/restore routes, tamper detection. Frontend: 6 new (helpers 2, panel 4). New Go tests: backup 15, api 4.

## 11.5 Upgrade and migration safety

- Migrations are GORM `AutoMigrate` at every startup. In this codebase they have been **additive** (new tables, columns, indexes); nothing drops data. Caveat: GORM's SQLite migrator can *rebuild* a table when an existing column's declared type/size changes. One such tag change exists in history (`iocs.enabled`, Phase 6, before any tagged release); future column-definition changes must be reviewed and preceded by a backup.
- **Real historical schema**: `internal/backup/testdata/legacy_1208a94.db` was generated by the code of commit `1208a94` (5 models, before incident events/IOC/notes/tuning/audit existed). It restores, passes compatibility (`will_be_added_by_migration` lists the new tables), migrates, keeps all rows (incident status/`resolved_at`/metadata, user, firewall rule, baseline) and then works with the new lifecycle and notes features. No other historical schema was invented.
- There is **no downgrade**. A database containing tables/columns this build does not know is flagged at startup (`WARNING … written by a newer VANGUARD`) and `Verify`/`Restore` refuse such a backup. Startup is not blocked (a harmless extra index must not cause an outage).
- Recommended before any upgrade: `vanguard backup create -label preupg` (safe while running), then upgrade. If the upgrade misbehaves: stop VANGUARD, install the previous binary, `vanguard backup restore -name <preupg> -confirm`. The previous database is kept as `*.pre-restore-*`.

## 11.7 Recovery runbook

1. **Create** (online): `vanguard backup create -db /var/lib/vanguard/vanguard.db [-dir D] [-label L] [--exclude-users]` — or Settings → Backups (admin).
2. **Validate** (online, read-only): `vanguard backup verify -name N` → exit 0 only if `valid:true`.
3. **Restore into a safe target first** (recommended): `vanguard backup restore -name N -db /tmp/trial/vanguard.db -confirm`, start a throw-away instance on it, check.
4. **Restore for real**: stop the daemon → preview `vanguard backup restore -name N` → read the plan (live vs backup row counts, warnings) → `... -confirm` → start the daemon.
5. **After a failed upgrade**: stop, roll the binary back, restore the pre-upgrade backup (step 4).
6. **Incompatible backup**: refused with the unknown tables/columns listed → use a build at least as new as the one that wrote it.
7. **Verify after recovery**: dashboard incident/IOC counts match the preview; `GET /api/health/runtime` healthy; `GET /api/backup` (`recent_activity`) shows the restore with actor and the preserved previous DB name (the panel itself does not display the audit list); log in (or create an admin if the backup excluded users); active bans re-appear at the firewall after startup reconcile; re-enter any Panic Mode you need.
8. **Cleanup**: delete `*.pre-restore-*` files yourself when satisfied — VANGUARD never does.

What the checks mean: SHA-256 + size → file unchanged since creation; `integrity_check` → SQLite structure is sound; row counts → manifest matches content; compatibility → this build can read it. None of them says *who* made it or that its content is trustworthy.

## Results (Windows; no Linux/Docker/CGO)

| Command | Result |
|---|---|
| `gofmt -l .` / `GOOS=linux go vet ./...` / `go build ./...` | clean / clean / OK |
| `go test -json ./...` → `tools/valreport` | **564 passed, 0 failed, 12 skipped** (skips are not passes: 10 Unix-permission `hostsec`, 1 tail line-delivery, 1 POSIX-permission backup test) |
| Manual CLI end-to-end (real binary, temp dir) | create → list → verify (valid) → preview (nothing changed) → `-confirm` (previous DB preserved) → tamper one byte → verify **invalid**, restore **refused** |
| `npx vitest run` / `vite build` | 7 files, 67 tests / OK |

## Not verified / limits

Linux behaviour of: `VACUUM INTO` permissions, the exclusive-lock in-use probe with a real running daemon (verified here only against another in-process connection), atomic directory rename semantics, POSIX modes, sidecar (`-shm`) handling after restore (a `-shm` file was left beside the preserved DB in the manual run — harmless, but unconfirmed on Linux). No cross-filesystem restore tests (rename across devices would fail safely at activation). Restore does not recreate OS firewall rules by itself. `go test -race`, Docker lab, real `ufw`: pending as for earlier phases.

## Acceptance

| Criterion | State |
|---|---|
| Consistent, bounded backups | done, tested |
| Invalid backups cannot replace valid live state | done, tested (11 cases + failure injection) |
| Restore explicit, authorized, auditable | CLI-only with `-confirm`; audit row; API/dashboard cannot restore |
| Data-preservation and failure-safety tests | done |
| Migration/recovery limits documented | done |
| No cloud / new mandatory dependency | none added |
| Recovery workflow tested as far as the environment permits | Windows only |

**Status: Implemented — Verification Pending.**
