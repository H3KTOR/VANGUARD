#!/bin/bash
# lab/run-phase4.sh
#
# VANGUARD Phase 4 (System Posture & Drift) lab scenarios P-U.
#
# Unlike run-tests.sh (network attacks fired from the attacker container),
# Phase 4 detects changes to the VICTIM HOST's own configuration, listening
# sockets and package database, so these scenarios mutate state INSIDE the
# victim container via `docker exec` (never the developer host) and then
# verify through VANGUARD's REST API. Every scenario restores what it
# changed.
#
# Usage (from the lab/ directory, with the victim up):
#   docker compose up -d --build victim
#   ./run-phase4.sh
#
# The victim runs with -posture-interval=3s so each scan cycle is quick
# (see victim/entrypoint.sh).
set -uo pipefail

VICTIM_CONTAINER="${VICTIM_CONTAINER:-vanguard-lab-victim}"
API_BASE="${API_BASE:-http://localhost:8080/api}"
ADMIN_EMAIL="lab-admin@vanguard.local"
ADMIN_PASSWORD="LabPassword123!"
HOST_IP="127.0.0.1"          # Phase 4 incidents are host-local findings
POLL_TIMEOUT="${POLL_TIMEOUT:-45}"
CYCLE=4                      # seconds: slightly more than one 3s scan tick

PASS_COUNT=0
FAIL_COUNT=0
SKIP_COUNT=0
CLEANUP_FAILURES=0
TOKEN=""

C_GREEN='\033[0;32m'; C_RED='\033[0;31m'; C_YELLOW='\033[1;33m'; C_CYAN='\033[0;36m'; C_RESET='\033[0m'
banner() { echo -e "${C_CYAN}\n==============================================================\n $1\n==============================================================${C_RESET}"; }
log()    { echo -e "${C_YELLOW}[lab-p4]${C_RESET} $*"; }

vexec() { docker exec "$VICTIM_CONTAINER" bash -c "$1"; }

wait_for_api() {
    for _ in $(seq 1 40); do
        curl -sf "${API_BASE}/health" >/dev/null 2>&1 && return 0
        sleep 2
    done
    echo -e "${C_RED}victim API never became healthy${C_RESET}"; exit 1
}

api_login() {
    curl -s -X POST "${API_BASE}/auth/register" -H 'Content-Type: application/json' \
        -d "{\"email\":\"${ADMIN_EMAIL}\",\"password\":\"${ADMIN_PASSWORD}\"}" >/dev/null
    TOKEN=$(curl -s -X POST "${API_BASE}/auth/login" -H 'Content-Type: application/json' \
        -d "{\"email\":\"${ADMIN_EMAIL}\",\"password\":\"${ADMIN_PASSWORD}\"}" | jq -r '.token // empty')
    [ -n "$TOKEN" ] || { echo -e "${C_RED}login failed${C_RESET}"; exit 1; }
}

api_get() { curl -s -H "Authorization: Bearer ${TOKEN}" "${API_BASE}$1"; }

# count_matching TYPE JQ_PREDICATE
#   Counts incidents of TYPE whose decoded metadata satisfies the jq
#   predicate (evaluated with the metadata object as `.`).
count_matching() {
    api_get "/incidents?type=$1&ip=${HOST_IP}&limit=500" \
        | jq "[.incidents[]? | (.metadata | fromjson? // {}) | select($2)] | length" 2>/dev/null || echo 0
}

# first_matching TYPE PRED  -> "id risk severity" of newest matching incident
first_matching() {
    api_get "/incidents?type=$1&ip=${HOST_IP}&limit=500" \
        | jq -r "[.incidents[]? | select((.metadata | fromjson? // {}) | $2)][0] | \"\(.id) \(.risk_score) \(.severity)\"" 2>/dev/null
}

pass() { echo -e "${C_GREEN}[✓]${C_RESET} $*"; PASS_COUNT=$((PASS_COUNT+1)); }
fail() { echo -e "${C_RED}[✗]${C_RESET} $*"; FAIL_COUNT=$((FAIL_COUNT+1)); }

# assert_detected TYPE PRED DESCRIPTION [MIN_SEVERITY_SCORE]
assert_detected() {
    local type="$1" pred="$2" desc="$3" min="${4:-0}" elapsed=0 n info
    while [ "$elapsed" -lt "$POLL_TIMEOUT" ]; do
        n=$(count_matching "$type" "$pred")
        if [ "${n:-0}" -ge 1 ]; then
            info=$(first_matching "$type" "$pred")
            read -r id risk sev <<<"$info"
            if [ "${risk:-0}" -ge "$min" ]; then
                pass "DETECTED ${desc} -- incident #${id}, risk=${risk}/100, severity=${sev}"
            else
                fail "${desc} detected but risk ${risk} < expected minimum ${min}"
            fi
            return
        fi
        sleep 2; elapsed=$((elapsed+2))
    done
    fail "MISSING ${desc} (no ${type} incident matching ${pred} within ${POLL_TIMEOUT}s)"
}

# assert_bounded TYPE PRED DESCRIPTION
#   Records the count, waits several scan cycles, and asserts the count
#   did not grow (deduplication).
assert_bounded() {
    local type="$1" pred="$2" desc="$3" before after
    before=$(count_matching "$type" "$pred")
    sleep $((CYCLE*3))
    after=$(count_matching "$type" "$pred")
    if [ "$before" = "$after" ] && [ "$before" -ge 1 ]; then
        pass "DEDUPLICATED ${desc} -- ${after} incident(s) after 3 extra scan cycles (unchanged)"
    else
        fail "${desc}: incident count went ${before} -> ${after} across extra scan cycles"
    fi
}

cleanup() {
    log "restoring victim fixtures..."
    vexec "chmod 644 /etc/vanguard-lab/posture.conf; rm -f /etc/nginx/conf.d/lab-p4-listener.conf; nginx -s reload >/dev/null 2>&1; true" || CLEANUP_FAILURES=$((CLEANUP_FAILURES+1))
}
trap cleanup EXIT

# ---------------------------------------------------------------------------
scenario_p_posture() {
    banner "SCENARIO P: Configuration Posture (world-writable sensitive config)"
    vexec "chmod 666 /etc/vanguard-lab/posture.conf" || { fail "could not chmod fixture"; return; }
    # severity "high" posture finding -> base 45 should land >= MEDIUM (>=25)
    assert_detected "configuration_posture" \
        '.check_id == "dangerous_permissions" and .resource == "/etc/vanguard-lab/posture.conf" and .severity == "high" and has("observed") and has("expected") and has("reason")' \
        "Configuration Posture (world-writable /etc/vanguard-lab/posture.conf)" 25
    vexec "chmod 644 /etc/vanguard-lab/posture.conf"
}

scenario_q_drift() {
    banner "SCENARIO Q: Configuration Drift (baseline -> modify -> dedupe -> restore)"
    sleep "$CYCLE"                      # let the baseline be established
    local marker="drift-$(date +%s)"
    vexec "echo '${marker}' >> /etc/vanguard-lab/drift.conf"
    assert_detected "configuration_drift" \
        '.resource == "/etc/vanguard-lab/drift.conf" and (.changed_fields | index("content")) != null and .content_hashed == true and has("previous_state") and has("current_state") and has("baseline_age_sec")' \
        "Configuration Drift (content change on drift.conf)"
    assert_bounded "configuration_drift" '.resource == "/etc/vanguard-lab/drift.conf"' "Configuration Drift"
    vexec "sed -i '/${marker}/d' /etc/vanguard-lab/drift.conf"
}

scenario_r_listening() {
    banner "SCENARIO R: Listening Service Drift (new nginx listener on :9999, then removal)"
    sleep 12                              # outlast -listening-grace=10s and baseline a clean state
    vexec "echo 'server { listen 9999; return 200 ok; }' > /etc/nginx/conf.d/lab-p4-listener.conf && nginx -s reload"         || { fail "could not start test listener"; return; }
    assert_detected "listening_service_drift" \
        '.change == "new_listener" and .port == 9999 and .protocol == "tcp" and .local_address == "0.0.0.0" and .address_family == "ipv4" and .newly_observed == true' \
        "Listening Service Drift (new 0.0.0.0:9999/tcp listener)" 40
    assert_bounded "listening_service_drift" '.port == 9999 and .change == "new_listener"' "Listening Service Drift"
    vexec "rm -f /etc/nginx/conf.d/lab-p4-listener.conf && nginx -s reload"
    assert_detected "listening_service_drift" '.change == "removed_listener" and .port == 9999' \
        "Listening Service Drift (listener :9999 removed)"
}

scenario_s_package() {
    banner "SCENARIO S: Package Drift (fixture dpkg status: install -> upgrade -> remove)"
    local f=/var/lib/vanguard-lab/dpkg-status stanza
    sleep "$CYCLE"
    stanza="Package: vanguard-lab-pkg\nStatus: install ok installed\nArchitecture: amd64\nVersion: 1.0-1\nDescription: lab fixture\n\n"
    vexec "printf '${stanza}' >> ${f}"
    assert_detected "package_drift" '.change == "installed" and .package == "vanguard-lab-pkg" and .new_version == "1.0-1"' \
        "Package Drift (fixture package installed)"
    vexec "sed -i 's/^Version: 1.0-1\$/Version: 1.1-1/' ${f}"
    assert_detected "package_drift" '.change == "upgraded" and .package == "vanguard-lab-pkg" and .old_version == "1.0-1" and .new_version == "1.1-1"' \
        "Package Drift (version change 1.0-1 -> 1.1-1)"
    assert_bounded "package_drift" '.package == "vanguard-lab-pkg"' "Package Drift"
    vexec "sed -i '/^Package: vanguard-lab-pkg\$/,/^\$/d' ${f}"
    assert_detected "package_drift" '.change == "removed" and .package == "vanguard-lab-pkg"' \
        "Package Drift (fixture package removed)"
}

scenario_u_restart() {
    banner "SCENARIO U: Restart Persistence (baselines survive a VANGUARD restart)"
    local pred='.resource == "/etc/vanguard-lab/drift.conf"' before after
    before=$(count_matching "configuration_drift" "$pred")
    log "restarting victim container..."
    docker restart "$VICTIM_CONTAINER" >/dev/null && wait_for_api && api_login
    sleep $((CYCLE*3))
    after=$(count_matching "configuration_drift" "$pred")
    if [ "$before" = "$after" ]; then
        pass "PERSISTED baseline survived restart -- unchanged state produced no new drift (${after} incident(s))"
    else
        fail "restart produced spurious drift (${before} -> ${after})"
    fi
    vexec "echo 'post-restart-$(date +%s%N)' >> /etc/vanguard-lab/drift.conf"
    sleep "$CYCLE"
    after=$(count_matching "configuration_drift" "$pred")
    if [ "$after" -gt "$before" ]; then
        pass "DETECTED drift after restart against the persisted baseline (${before} -> ${after})"
    else
        fail "change after restart was not detected against the persisted baseline"
    fi
}

banner "VANGUARD Phase 4 -- System Posture & Drift Lab"
wait_for_api
api_login

scenario_p_posture
scenario_q_drift
scenario_r_listening
scenario_s_package
# Scenario T (deduplication) is asserted inside Q, R and S via
# assert_bounded; the posture detector's own dedup is checked here.
banner "SCENARIO T: Deduplication (Configuration Posture)"
vexec "chmod 666 /etc/vanguard-lab/posture.conf"
sleep "$CYCLE"
assert_bounded "configuration_posture" '.resource == "/etc/vanguard-lab/posture.conf"' "Configuration Posture"
vexec "chmod 644 /etc/vanguard-lab/posture.conf"
scenario_u_restart

banner "RESULTS (Phase 4)"
TOTAL=$((PASS_COUNT+FAIL_COUNT+SKIP_COUNT))
echo "  Scenarios checked: ${TOTAL}"
echo -e "  ${C_GREEN}Passed:${C_RESET}  ${PASS_COUNT}"
echo -e "  ${C_RED}Failed:${C_RESET}  ${FAIL_COUNT}"
echo "  Skipped: ${SKIP_COUNT}"
if [ "$FAIL_COUNT" -gt 0 ] || [ "$CLEANUP_FAILURES" -gt 0 ]; then
    echo -e "${C_RED}PHASE 4 LAB RESULT: FAIL${C_RESET} (cleanup failures: ${CLEANUP_FAILURES})"
    exit 1
fi
echo -e "${C_GREEN}PHASE 4 LAB RESULT: PASS -- every posture/drift scenario was detected by VANGUARD (cleanup OK).${C_RESET}"
