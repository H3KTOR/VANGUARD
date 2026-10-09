#!/bin/bash
# lab/run-phase5.sh
#
# VANGUARD Phase 5 lab scenarios V-Y: incident lifecycle + audit trail,
# evidence provenance, non-mutating response plan, scanner health
# reporting and restart persistence. Same model as run-phase4.sh: the
# orchestrator runs on the host and mutates only the victim container via
# `docker exec`; results are read back through the REST API.
#
# NOT covered here (needs a real or fault-injectable firewall; the lab
# victim uses the in-memory mock executor): response verification
# failure/timeout paths. Those are covered by Go unit tests in
# core/internal/firewall/response_test.go.
#
# Usage (from lab/, victim up):  ./run-phase5.sh
set -uo pipefail

VICTIM_CONTAINER="${VICTIM_CONTAINER:-vanguard-lab-victim}"
API_BASE="${API_BASE:-http://localhost:8080/api}"
ADMIN_EMAIL="lab-admin@vanguard.local"
ADMIN_PASSWORD="LabPassword123!"
POLL_TIMEOUT="${POLL_TIMEOUT:-45}"
CYCLE=4

PASS_COUNT=0; FAIL_COUNT=0; TOKEN=""
C_GREEN='\033[0;32m'; C_RED='\033[0;31m'; C_YELLOW='\033[1;33m'; C_CYAN='\033[0;36m'; C_RESET='\033[0m'
banner() { echo -e "${C_CYAN}\n==============================================================\n $1\n==============================================================${C_RESET}"; }
log()    { echo -e "${C_YELLOW}[lab-p5]${C_RESET} $*"; }
pass()   { echo -e "${C_GREEN}[✓]${C_RESET} $*"; PASS_COUNT=$((PASS_COUNT+1)); }
fail()   { echo -e "${C_RED}[✗]${C_RESET} $*"; FAIL_COUNT=$((FAIL_COUNT+1)); }
vexec()  { docker exec "$VICTIM_CONTAINER" bash -c "$1"; }

wait_for_api() {
    for _ in $(seq 1 40); do curl -sf "${API_BASE}/health" >/dev/null 2>&1 && return 0; sleep 2; done
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
# api_put_status ID JSON -> prints HTTP code
api_put_status() {
    curl -s -o /dev/null -w '%{http_code}' -X PUT -H "Authorization: Bearer ${TOKEN}" \
        -H 'Content-Type: application/json' -d "$2" "${API_BASE}/incidents/$1/status"
}

# wait_incident TYPE -> prints id of newest incident of TYPE from 127.0.0.1
wait_incident() {
    local elapsed=0 id
    while [ "$elapsed" -lt "$POLL_TIMEOUT" ]; do
        id=$(api_get "/incidents?type=$1&ip=127.0.0.1&limit=1" | jq -r '.incidents[0].id // empty')
        [ -n "$id" ] && { echo "$id"; return 0; }
        sleep 2; elapsed=$((elapsed+2))
    done
    return 1
}

scenario_v_lifecycle() {
    banner "SCENARIO V: Evidence provenance + incident lifecycle + audit trail"
    # Percent-encoded UNION SELECT: regression for the encoded-payload gap.
    vexec "curl -s -o /dev/null --path-as-is 'http://localhost/item?id=1%20union%20select%201,2'"
    local id; id=$(wait_incident sqli_xss_probe) || { fail "encoded SQLi probe was not detected"; return; }
    pass "DETECTED percent-encoded UNION SELECT as sqli_xss_probe (incident #${id})"

    local meta; meta=$(api_get "/incidents/${id}" | jq -r '.metadata')
    if echo "$meta" | jq -e '.provenance.rule_id == "sqli_xss_probe" and .provenance.evidence_kind == "observed" and (.provenance.limitations | length) > 0' >/dev/null; then
        pass "provenance present (rule_id, evidence_kind=observed, limitations)"
    else fail "provenance missing/incorrect: ${meta}"; fi

    [ "$(api_put_status "$id" '{"status":"resolved","reason":"lab triage"}')" = "200" ] && pass "open -> resolved accepted" || fail "open -> resolved rejected"
    [ "$(api_put_status "$id" '{"status":"auto_blocked"}')" = "409" ] && pass "resolved -> auto_blocked rejected with 409" || fail "illegal transition was not rejected"
    [ "$(api_put_status "$id" '{"status":"open","reason":"recurred"}')" = "200" ] && pass "resolved -> open (reopen) accepted" || fail "reopen rejected"
    [ "$(api_put_status "$id" '{"status":"bogus"}')" = "400" ] && pass "unknown status rejected with 400" || fail "unknown status accepted"

    local n; n=$(api_get "/incidents/${id}/events" | jq '[.events[] | select(.kind == "status_change")] | length')
    [ "$n" = "2" ] && pass "audit trail holds exactly the 2 successful transitions" || fail "audit trail has ${n} status_change events (want 2)"
    LIFECYCLE_ID="$id"
}

scenario_w_plan() {
    banner "SCENARIO W: Response plan is non-mutating"
    local id; id=$(wait_incident sqli_xss_probe) || { fail "no incident for plan"; return; }
    local before_rules before_events plan after_rules after_events
    before_rules=$(api_get "/firewall/rules" | jq '.rules | length' 2>/dev/null || echo 0)
    before_events=$(api_get "/incidents/${id}/events" | jq '.events | length')
    plan=$(api_get "/incidents/${id}/response-plan")
    after_rules=$(api_get "/firewall/rules" | jq '.rules | length' 2>/dev/null || echo 0)
    after_events=$(api_get "/incidents/${id}/events" | jq '.events | length')
    if echo "$plan" | jq -e '.executed == false and .would_ban == false and .outcome != null' >/dev/null; then
        pass "plan returned executed=false (outcome: $(echo "$plan" | jq -r .outcome))"
    else fail "unexpected plan: ${plan}"; fi
    if [ "$before_rules" = "$after_rules" ] && [ "$before_events" = "$after_events" ]; then
        pass "plan changed neither firewall rules nor the audit trail"
    else fail "plan mutated state (rules ${before_rules}->${after_rules}, events ${before_events}->${after_events})"; fi
}

scenario_x_scanner_health() {
    banner "SCENARIO X: Scanner health - unavailable data is 'skipped', never clean"
    sleep "$CYCLE"
    local st; st=$(api_get "/detectors/status")
    if echo "$st" | jq -e '.enabled == true and ([.detectors[] | select(.name == "package_drift")] | length) == 1' >/dev/null; then
        pass "detector status endpoint lists the Phase 4 scanners"
    else fail "detector status missing package_drift: ${st}"; return; fi

    vexec "mv /var/lib/vanguard-lab/dpkg-status /var/lib/vanguard-lab/dpkg-status.away"
    sleep $((CYCLE*2))
    local row; row=$(api_get "/detectors/status" | jq -c '.detectors[] | select(.name == "package_drift")')
    local clean_during; clean_during=$(echo "$row" | jq -r '.last_clean_scan')
    if [ "$(echo "$row" | jq -r .last_result)" = "skipped" ]; then
        pass "missing package database reported as skipped (not clean)"
    else fail "package_drift not reported skipped: ${row}"; fi
    sleep $((CYCLE*2))
    row=$(api_get "/detectors/status" | jq -c '.detectors[] | select(.name == "package_drift")')
    [ "$(echo "$row" | jq -r .last_clean_scan)" = "$clean_during" ] && pass "last_clean_scan did not advance while skipped" || fail "last_clean_scan advanced during outage"

    vexec "mv /var/lib/vanguard-lab/dpkg-status.away /var/lib/vanguard-lab/dpkg-status"
    sleep $((CYCLE*2))
    row=$(api_get "/detectors/status" | jq -c '.detectors[] | select(.name == "package_drift")')
    [ "$(echo "$row" | jq -r .last_result)" = "ok" ] && pass "scanner recovered to ok after the database returned" || fail "no recovery: ${row}"
    local spurious; spurious=$(api_get "/incidents?type=package_drift&ip=127.0.0.1&limit=500" | jq '[.incidents[] | (.metadata | fromjson? // {}) | select(.change == "removed")] | length')
    [ "$spurious" = "0" ] && pass "outage produced no fabricated 'packages removed' incidents" || fail "${spurious} spurious removal incident(s)"
}

scenario_y_restart() {
    banner "SCENARIO Y: Incident history survives a restart"
    [ -n "${LIFECYCLE_ID:-}" ] || { fail "no lifecycle incident to check"; return; }
    docker restart "$VICTIM_CONTAINER" >/dev/null && wait_for_api && api_login
    local n; n=$(api_get "/incidents/${LIFECYCLE_ID}/events" | jq '[.events[] | select(.kind == "status_change")] | length')
    [ "$n" = "2" ] && pass "audit trail persisted across restart (${n} events)" || fail "audit trail lost/changed after restart (${n})"
}

banner "VANGUARD Phase 5 -- Lifecycle, Evidence & Scanner-Health Lab"
wait_for_api
api_login
scenario_v_lifecycle
scenario_w_plan
scenario_x_scanner_health
scenario_y_restart

banner "RESULTS (Phase 5)"
echo "  Passed: ${PASS_COUNT}   Failed: ${FAIL_COUNT}"
if [ "$FAIL_COUNT" -gt 0 ]; then
    echo -e "${C_RED}PHASE 5 LAB RESULT: FAIL${C_RESET}"; exit 1
fi
echo -e "${C_GREEN}PHASE 5 LAB RESULT: PASS${C_RESET}"
