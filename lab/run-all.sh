#!/bin/bash
# lab/run-all.sh -- run every lab suite, report honestly, exit meaningfully.
#
# Suites (each is independent and judged only on its own output):
#   attack     lab/run-tests.sh        network attacks from the attacker container
#   phase4     lab/run-phase4.sh       posture / drift / listening / package
#   phase5     lab/run-phase5.sh       lifecycle / evidence / scanner health
#   phase6     lab/run-phase6.sh       local threat intelligence
#
# Scope and safety
#   * Everything runs against the lab containers on the private
#     172.28.0.0/24 network (victim: vanguard-lab-victim, attacker:
#     vanguard-lab-attacker). Nothing public or third-party is contacted.
#   * Mutated resources (all INSIDE the victim container, restored by the
#     scenarios): /etc/vanguard-lab/*, /var/lib/vanguard-lab/dpkg-status
#     (a COPY of the dpkg database), a temporary nginx listener on :9999,
#     the victim's SQLite DB and (phase 4/5/6) a container restart. The
#     developer host is never modified.
#   * `--teardown` removes the lab containers and volumes afterwards.
#
# Result semantics
#   pass     the suite ran and every scenario assertion passed
#   fail     the suite ran and at least one assertion failed (or it exited
#            non-zero / printed no assertions at all)
#   blocked  a prerequisite was missing (docker, jq, curl, a running or
#            buildable victim) -- the suite did NOT run
#   skipped  deselected with --only
# Exit code: 0 all selected suites passed; 1 any fail; 3 any blocked (and
# none failed). A blocked or skipped suite is never reported as a pass.
#
# Output: lab/results/summary.json (machine readable) + per-suite logs.
set -uo pipefail

LAB_DIR="$(cd "$(dirname "$0")" && pwd)"
RESULTS_DIR="${RESULTS_DIR:-$LAB_DIR/results}"
SUITES_ALL=(attack phase4 phase5 phase6)
ONLY=""
TEARDOWN=0
BRING_UP=1

while [ $# -gt 0 ]; do
    case "$1" in
        --only) ONLY="$2"; shift 2 ;;
        --teardown) TEARDOWN=1; shift ;;
        --no-up) BRING_UP=0; shift ;;
        -h|--help) sed -n 2,40p "$0"; exit 0 ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done

mkdir -p "$RESULTS_DIR"
TSV="$RESULTS_DIR/scenarios.tsv"; : > "$TSV"
SUITES_TSV="$RESULTS_DIR/suites.tsv"; : > "$SUITES_TSV"
STARTED="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

strip_ansi() { sed 's/\x1b\[[0-9;]*m//g'; }

blocked_reason=""
need() { command -v "$1" >/dev/null 2>&1 || blocked_reason="${blocked_reason}missing '$1'; "; }
need docker; need jq; need curl
if command -v docker >/dev/null 2>&1; then
    docker info >/dev/null 2>&1 || blocked_reason="${blocked_reason}docker daemon not reachable; "
    docker compose version >/dev/null 2>&1 || blocked_reason="${blocked_reason}'docker compose' unavailable; "
fi

selected() { [ -z "$ONLY" ] || [[ ",$ONLY," == *",$1,"* ]]; }
record_suite() { printf '%s\t%s\t%s\n' "$1" "$2" "$3" >> "$SUITES_TSV"; }   # suite status detail

if [ -n "$blocked_reason" ]; then
    for s in "${SUITES_ALL[@]}"; do
        if selected "$s"; then record_suite "$s" blocked "$blocked_reason"; else record_suite "$s" skipped "deselected"; fi
    done
else
    if [ "$BRING_UP" -eq 1 ]; then
        echo "[lab] building and starting the victim (docker compose up -d --build victim)..."
        if ! (cd "$LAB_DIR" && docker compose up -d --build victim >"$RESULTS_DIR/up.log" 2>&1); then
            blocked_reason="victim failed to build/start (see results/up.log); "
        fi
    fi
    if [ -z "$blocked_reason" ]; then
        ok=0
        for _ in $(seq 1 40); do
            curl -sf http://localhost:8080/api/health >/dev/null 2>&1 && { ok=1; break; }
            sleep 2
        done
        [ "$ok" -eq 1 ] || blocked_reason="victim API never became healthy; "
    fi
    for s in "${SUITES_ALL[@]}"; do
        if ! selected "$s"; then record_suite "$s" skipped "deselected"; continue; fi
        if [ -n "$blocked_reason" ]; then record_suite "$s" blocked "$blocked_reason"; continue; fi
        log="$RESULTS_DIR/$s.log"
        echo "[lab] running suite: $s"
        case "$s" in
            attack) (cd "$LAB_DIR" && docker compose run --rm attacker ./run-tests.sh) >"$log" 2>&1 ;;
            *)      (cd "$LAB_DIR" && ./run-"$s".sh) >"$log" 2>&1 ;;
        esac
        rc=$?
        strip_ansi < "$log" > "$log.clean"
        pass=$(grep -c '^\[✓\]' "$log.clean"); fail=$(grep -c '^\[✗\]' "$log.clean")
        # scenario lines
        grep '^\[✓\]' "$log.clean" | sed "s/^\[✓\] */pass\t$s\t/" >> "$TSV"
        grep '^\[✗\]' "$log.clean" | sed "s/^\[✗\] */fail\t$s\t/" >> "$TSV"
        if [ "$rc" -ne 0 ] || [ "$fail" -gt 0 ]; then
            record_suite "$s" fail "exit=$rc pass=$pass fail=$fail"
        elif [ "$pass" -eq 0 ]; then
            record_suite "$s" fail "exit=0 but no assertions were reported (script did not really run)"
        else
            record_suite "$s" pass "exit=0 pass=$pass fail=0"
        fi
    done
fi

if [ "$TEARDOWN" -eq 1 ] && command -v docker >/dev/null 2>&1; then
    echo "[lab] tearing down lab containers and volumes..."
    (cd "$LAB_DIR" && docker compose down -v >"$RESULTS_DIR/down.log" 2>&1) || echo "[lab] teardown reported errors (see results/down.log)"
fi

# --- machine-readable summary (jq is required for blocked-free runs; when it
# is missing we still emit a minimal, valid JSON without scenario detail) ---
if command -v jq >/dev/null 2>&1; then
    jq -n --arg started "$STARTED" --arg finished "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
        --rawfile suites "$SUITES_TSV" --rawfile scen "$TSV" '
        def rows(s): s | split("\n") | map(select(length>0) | split("\t"));
        {
          started_at: $started, finished_at: $finished,
          environment: "lab containers on a private Docker network; host untouched",
          suites: (rows($suites) | map({suite: .[0], status: .[1], detail: .[2]})),
          scenarios: (rows($scen) | map({status: .[0], suite: .[1], assertion: .[2]})),
          note: "pass/fail come only from assertions the scripts actually printed; blocked/skipped suites did not run"
        }' > "$RESULTS_DIR/summary.json"
else
    # No jq: write the suite-level summary with plain bash so a blocked run
    # still leaves a machine-readable record of WHY nothing ran.
    esc() { local v=${1//\\/\\\\}; v=${v//\"/\\\"}; printf '%s' "$v"; }
    {
        printf '{"started_at":"%s","finished_at":"%s","note":"jq missing: suite-level detail only","suites":[' "$STARTED" "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
        first=1
        while IFS=$'\t' read -r suite status detail; do
            [ "$first" -eq 1 ] || printf ','
            first=0
            printf '{"suite":"%s","status":"%s","detail":"%s"}' "$(esc "$suite")" "$(esc "$status")" "$(esc "$detail")"
        done < "$SUITES_TSV"
        printf '],"scenarios":[]}\n'
    } > "$RESULTS_DIR/summary.json"
fi

echo
echo "================ LAB SUMMARY ================"
column -t -s$'\t' "$SUITES_TSV" 2>/dev/null || cat "$SUITES_TSV"
echo "details: $RESULTS_DIR/summary.json"

if cut -f2 "$SUITES_TSV" | grep -qx fail; then echo "RESULT: FAIL"; exit 1; fi
if cut -f2 "$SUITES_TSV" | grep -qx blocked; then echo "RESULT: BLOCKED (suites did not run; this is NOT a pass)"; exit 3; fi
if ! cut -f2 "$SUITES_TSV" | grep -qx pass; then echo "RESULT: NOTHING RAN"; exit 3; fi
echo "RESULT: PASS (all selected suites)"
exit 0
