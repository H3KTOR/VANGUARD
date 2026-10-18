#!/usr/bin/env bash
# deploy/vulncheck.sh - run govulncheck over core/ and report honestly.
#
#   deploy/vulncheck.sh [GOOS]            (default GOOS: linux)
#
# Exit codes (never confuse the last two with a clean result):
#   0  govulncheck ran and reports no vulnerability reachable from VANGUARD's code
#   1  govulncheck ran and FOUND reachable vulnerabilities (details printed)
#   3  BLOCKED: the scan did not complete (tool missing, vulnerability database
#      unreachable, build error). Nothing is known about the result.
#
# Policy: findings (exit 1) fail the CI `vuln` job and therefore the required gate.
# A blocked scan (exit 3) fails it as well, with a different message. Vulnerabilities
# that the code does not call are listed by govulncheck but do not fail the build;
# review them (docs/PHASE17.md). A clean run is not proof the program is secure:
# it only covers known, reported vulnerabilities in Go code reachable by the call graph.
# The scan needs the network (https://vuln.go.dev) unless pointed elsewhere with GOVULNCHECK_ARGS="-db ...".
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GOOS_TARGET="${1:-linux}"
TOOL="${GOVULNCHECK:-$(command -v govulncheck || true)}"
if [ -z "$TOOL" ]; then
  echo "BLOCKED: govulncheck is not installed. Install the pinned version:  go install golang.org/x/vuln/cmd/govulncheck@v1.8.0" >&2
  exit 3
fi
cd "$HERE/../core" || exit 3
out="$(mktemp)"; trap 'rm -f "$out"' EXIT
# GOVULNCHECK_ARGS exists so tests can point the tool at an unreachable database
GOOS="$GOOS_TARGET" "$TOOL" ${GOVULNCHECK_ARGS:-} ./... >"$out" 2>&1
code=$?
cat "$out"
case "$code" in
  0) echo "RESULT: no reachable vulnerabilities reported (database and tool versions are in the output above)"; exit 0 ;;
  3) echo "RESULT: FOUND reachable vulnerabilities (see above)" >&2; exit 1 ;;
  *) echo "RESULT: BLOCKED: govulncheck exited $code before completing. This is NOT a clean result." >&2; exit 3 ;;
esac
