#!/usr/bin/env bash
# deploy/upgrade.sh - upgrade an installed VANGUARD to a binary YOU built, with
# a verified backup first and an honest health check after.
#
#   sudo deploy/upgrade.sh --binary core/vanguard [--dry-run] [--health-url http://127.0.0.1:8080]
#
# Order of operations (it stops at the first failure, before touching anything
# that is not yet backed up):
#   1. the NEW binary must run (`version`) and pass `doctor` against the live data
#   2. `backup create -label preupg` with the CURRENT binary, then `backup verify`
#      must report valid
#   3. stop the service; keep the old binary as vanguard.prev; atomically replace
#   4. start; poll GET /api/health; run `doctor` again
#   5. if step 4 fails: put the old binary back and start it ONLY if it can still
#      read the database; otherwise print the explicit restore command. It never
#      restores a database or deletes anything by itself.
#
# Limits, stated plainly: there is NO schema downgrade. After a new binary has
# migrated the database, the only recovery that guarantees a consistent state is
# restoring the verified pre-upgrade backup (docs/PHASE11.md). /api/health only
# proves the HTTP server answers; it does not prove detectors work.
#
# STATUS: syntax-checked (bash -n) only; NOT run on a real Linux host.
set -euo pipefail

BINARY=""
DRY=0
HEALTH_URL="http://127.0.0.1:8080"
BIN_DEST="${VANGUARD_BIN_DEST:-/usr/local/bin/vanguard}"
DATA_DIR="${VANGUARD_DATA_DIR:-/opt/vanguard/data}"
ENV_FILE="${VANGUARD_ENV_FILE:-/etc/vanguard/vanguard.env}"
SVC="${VANGUARD_SERVICE:-vanguard}"
SVC_USER="${VANGUARD_USER:-vanguard}"
DB="$DATA_DIR/vanguard.db"

while [ $# -gt 0 ]; do
  case "$1" in
    --binary) BINARY="${2:-}"; shift 2 ;;
    --dry-run) DRY=1; shift ;;
    --health-url) HEALTH_URL="${2:-}"; shift 2 ;;
    -h|--help) sed -n '2,24p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
done

say() { printf '%s\n' "$*"; }
run() { if [ "$DRY" = 1 ]; then say "[dry-run] $*"; else "$@"; fi; }
as_svc() { # run as the service account when we are root and it exists; choose the tool once, never retry
  if [ "$(id -u)" = 0 ] && id -u "$SVC_USER" >/dev/null 2>&1; then
    if command -v runuser >/dev/null 2>&1; then runuser -u "$SVC_USER" -- "$@"; else sudo -u "$SVC_USER" "$@"; fi
  else
    "$@"
  fi
}
die() { echo "ABORT: $*" >&2; exit 1; }

[ -n "$BINARY" ] || die "--binary PATH is required"
[ -f "$BINARY" ] || die "binary not found: $BINARY"
[ -x "$BIN_DEST" ] || die "$BIN_DEST is not installed; use deploy/install.sh for a first install"
if [ "$DRY" = 0 ]; then
  [ "$(id -u)" = 0 ] || die "run as root (or use --dry-run)"
fi

say "== 1. checking the new binary"
chmod +x "$BINARY" 2>/dev/null || true
say "current: $("$BIN_DEST" version 2>&1 || echo unknown)"
say "new:     $("$BINARY" version 2>&1)" || die "the new binary does not run"
if ! "$BINARY" doctor -db "$DB" -env-file "$ENV_FILE" -backup-dir "$DATA_DIR/backups"; then
  die "doctor reports failed checks with the NEW binary; nothing was changed"
fi

say "== 2. verified backup with the CURRENT binary"
LABEL="preupg"
if [ "$DRY" = 1 ]; then
  say "[dry-run] $BIN_DEST backup create -db $DB -label $LABEL ; backup verify"
else
  out="$(as_svc "$BIN_DEST" backup create -db "$DB" -label "$LABEL")" || die "backup failed; nothing was changed"
  name="$(printf '%s' "$out" | sed -n 's/.*"name": *"\([^"]*\)".*/\1/p' | head -n1)"
  [ -n "$name" ] || die "could not read the backup name from: $out"
  vout="$(as_svc "$BIN_DEST" backup verify -db "$DB" -name "$name")" || die "backup $name did NOT verify; nothing was changed"
  printf '%s' "$vout" | grep -q '"valid": *true' || die "backup $name is not valid; nothing was changed"
  say "backup $name created and verified"
fi

say "== 3. replacing the binary"
run systemctl stop "$SVC"
run cp -p "$BIN_DEST" "$BIN_DEST.prev"
run install -m 0755 -o root -g root "$BINARY" "$BIN_DEST.new"
run mv -f "$BIN_DEST.new" "$BIN_DEST"

say "== 4. starting and checking"
run systemctl start "$SVC"
ok=0
if [ "$DRY" = 1 ]; then
  say "[dry-run] poll $HEALTH_URL/api/health for up to 30s, then run doctor"
  ok=1
else
  for _ in $(seq 1 30); do
    if systemctl is-active --quiet "$SVC" && "$BIN_DEST" doctor -db "$DB" -env-file "$ENV_FILE" -health-url "$HEALTH_URL" >/dev/null 2>&1; then ok=1; break; fi
    sleep 1
  done
fi

if [ "$DRY" = 1 ]; then
  say "[dry-run] complete: nothing was changed. Re-run without --dry-run to upgrade."
  exit 0
fi

if [ "$ok" = 1 ]; then
  say "upgrade finished: the service is active and /api/health answers."
  say "That does not prove detectors work: sign in and review GET /api/health/runtime / the dashboard banner."
  say "The previous binary is kept as $BIN_DEST.prev and the pre-upgrade backup in $DATA_DIR/backups."
  exit 0
fi

echo "== 5. the upgraded service did not become healthy; rolling the BINARY back (data is not touched)" >&2
systemctl stop "$SVC" || true
mv -f "$BIN_DEST.prev" "$BIN_DEST"
if "$BIN_DEST" doctor -db "$DB" -env-file "$ENV_FILE" >/dev/null 2>&1; then
  systemctl start "$SVC" || true
  echo "the previous binary can read the database and was started. Investigate with: journalctl -u $SVC -n 100" >&2
else
  cat >&2 <<EOF
The previous binary can NOT use the database (the new version has already migrated it, and there is no
schema downgrade). The service is stopped. To get back to the pre-upgrade state:

  sudo -u $SVC_USER $BIN_DEST backup restore -db $DB -name <the preupg backup shown above>            # preview
  sudo -u $SVC_USER $BIN_DEST backup restore -db $DB -name <the preupg backup shown above> -confirm   # perform
  sudo systemctl start $SVC

The database that is replaced is kept as $DB.pre-restore-*.
EOF
fi
exit 1
