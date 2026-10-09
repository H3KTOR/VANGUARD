#!/bin/bash
# lab/run-phase6.sh
#
# VANGUARD Phase 6 lab scenarios (AA-AF): local IOC import, exact matching,
# near-miss controls, disabled/expired handling, failed-import safety,
# hunting and restart persistence. Host-side orchestrator like
# run-phase4.sh / run-phase5.sh: it drives the victim through its REST API
# and `docker exec`, using only synthetic indicators in a private lab
# network (the victim's own lab address 172.28.0.10 stands in for the
# "listed" actor; nothing external is contacted).
#
# Usage (from lab/, victim up):  ./run-phase6.sh
set -uo pipefail

VICTIM_CONTAINER="${VICTIM_CONTAINER:-vanguard-lab-victim}"
API_BASE="${API_BASE:-http://localhost:8080/api}"
FEED="${FEED:-$(dirname "$0")/fixtures/ioc-lab-feed.json}"
ADMIN_EMAIL="lab-admin@vanguard.local"
ADMIN_PASSWORD="LabPassword123!"
POLL_TIMEOUT="${POLL_TIMEOUT:-40}"
VICTIM_IP="172.28.0.10"

PASS_COUNT=0; FAIL_COUNT=0; TOKEN=""
C_GREEN='\033[0;32m'; C_RED='\033[0;31m'; C_YELLOW='\033[1;33m'; C_CYAN='\033[0;36m'; C_RESET='\033[0m'
banner() { echo -e "${C_CYAN}\n==============================================================\n $1\n==============================================================${C_RESET}"; }
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
api_get()  { curl -s -H "Authorization: Bearer ${TOKEN}" "${API_BASE}$1"; }
api_post_file() { curl -s -o /tmp/p6_resp.json -w '%{http_code}' -X POST -H "Authorization: Bearer ${TOKEN}" --data-binary @"$2" "${API_BASE}$1"; }

# ioc_incidents FIELD -> count of ioc_match incidents whose evidence matched_field == FIELD
ioc_incidents() {
    api_get "/incidents?type=ioc_match&limit=500" \
        | jq "[.incidents[] | (.metadata | fromjson? // {}) | select(.matched_field == \"$1\")] | length"
}
total_ioc_incidents() { api_get "/incidents?type=ioc_match&limit=500" | jq '.count'; }
wait_ioc() {   # FIELD -> waits until >=1 incident with that matched_field
    local e=0; while [ "$e" -lt "$POLL_TIMEOUT" ]; do
        [ "$(ioc_incidents "$1")" -ge 1 ] && return 0; sleep 2; e=$((e+2)); done; return 1
}

scenario_aa_import() {
    banner "SCENARIO AA: offline import with per-record reporting"
    local code; code=$(api_post_file "/intel/import" "$FEED")
    local rep; rep=$(cat /tmp/p6_resp.json)
    if [ "$code" = "200" ] && echo "$rep" | jq -e '.status == "applied" and .accepted == 4 and .rejected == 1 and .expired == 1 and .disabled == 1' >/dev/null; then
        pass "feed applied: 4 stored (1 disabled), 1 invalid reported, 1 expired reported, not stored"
    else fail "unexpected import result (${code}): ${rep}"; fi
    sleep 1
}

scenario_ab_match() {
    banner "SCENARIO AB: exact IP / domain / URL matches with explainable evidence"
    vexec "curl -s -o /dev/null 'http://${VICTIM_IP}/?password=hunter2&token=abc'"
    vexec "curl -s -o /dev/null -H 'Host: lab-evil.example.test' 'http://${VICTIM_IP}/index.html'"
    vexec "curl -s -o /dev/null -H 'Host: lab-evil.example.test' 'http://${VICTIM_IP}/dl/payload.bin?id=7'"
    wait_ioc source_ip && pass "IP indicator matched (ioc_match, matched_field=source_ip)" || fail "IP indicator did not match"
    wait_ioc host      && pass "domain indicator matched via logged Host header" || fail "domain indicator did not match"
    wait_ioc url       && pass "URL indicator matched (host + path + query)" || fail "URL indicator did not match"

    local inc; inc=$(api_get "/incidents?type=ioc_match&limit=500" | jq -c '[.incidents[] | select((.metadata|fromjson).matched_field=="source_ip")][0]')
    local meta; meta=$(echo "$inc" | jq -r .metadata)
    echo "$meta" | jq -e '.ioc.source == "lab-feed" and .ioc.confidence_from_source == "high" and .match_kind == "direct" and .provenance.evidence_kind == "observed" and (.provenance.limitations | length) > 0' >/dev/null \
        && pass "evidence names the indicator, source, confidence and what a match cannot prove" || fail "evidence incomplete: ${meta}"
    if echo "$meta" | grep -q -e hunter2 -e 'token=abc' -e password; then fail "request secrets leaked into IOC evidence"; else pass "no request secrets in IOC evidence"; fi
    local risk; risk=$(echo "$inc" | jq -r .risk_score)
    [ "$risk" -le 55 ] && pass "IOC-only risk ${risk} <= 55 cap (below auto-response threshold)" || fail "risk ${risk} exceeds the IOC-only cap"
    [ "$(api_get "/firewall/rules" | jq '[.rules[] | select(.ip_address == "'"${VICTIM_IP}"'" and .is_active)] | length')" = "0" ] \
        && pass "no firewall rule was created for the listed address" || fail "an IOC match caused a ban"
}

scenario_ac_controls() {
    banner "SCENARIO AC: near-misses, disabled and expired indicators do not match"
    local before; before=$(total_ioc_incidents)
    for h in lab-evil.example.test.attacker.net notlab-evil.example.test a.lab-evil.example.test; do
        vexec "curl -s -o /dev/null -H 'Host: ${h}' 'http://${VICTIM_IP}/x'"
    done
    vexec "curl -s -o /dev/null -H 'Host: lab-evil.example.test' 'http://${VICTIM_IP}/dl/payload.bin?id=8'"
    sleep 6
    local after; after=$(total_ioc_incidents)
    # The listed source address (the victim) legitimately re-matches by IP, but
    # that is deduplicated for an hour, so nothing new may appear.
    [ "$before" = "$after" ] && pass "near-miss hosts / different URL query / deduplicated IP produced no new incidents" || fail "unexpected new ioc_match incidents (${before} -> ${after})"
    [ "$(api_get "/intel/iocs?state=active&limit=100" | jq '[.indicators[] | select(.value == "198.51.100.200" or .value == "198.51.100.201")] | length')" = "0" ] \
        && pass "disabled-in-feed indicator is not active; expired record was never stored" || fail "disabled/expired indicator appears active"
}

scenario_ad_failed_import() {
    banner "SCENARIO AD: failed imports never damage existing intelligence"
    local n0; n0=$(api_get "/intel/iocs?limit=500" | jq '.count')
    printf '{"format":"vanguard-ioc","version":1,"source":"lab-feed","indicators":[' > /tmp/p6_bad.json
    local code; code=$(api_post_file "/intel/import" /tmp/p6_bad.json)
    [ "$code" = "422" ] && pass "truncated feed rejected with 422" || fail "truncated feed returned ${code}"
    printf '{"format":"vanguard-ioc","version":1,"source":"lab-feed","indicators":[{"type":"ip","value":"bogus"}]}' > /tmp/p6_bad2.json
    code=$(api_post_file "/intel/import" /tmp/p6_bad2.json)
    [ "$code" = "422" ] && pass "feed with no valid record rejected (cannot replace healthy data with nothing)" || fail "all-invalid feed returned ${code}"
    local n1; n1=$(api_get "/intel/iocs?limit=500" | jq '.count')
    [ "$n0" = "$n1" ] && pass "indicator count unchanged (${n1})" || fail "indicator count changed ${n0} -> ${n1}"
    [ "$(api_get "/intel/status" | jq -r '.last_import.status')" = "rejected" ] && pass "failed import is visible in /intel/status" || fail "failed import not surfaced"
}

scenario_ae_hunt() {
    banner "SCENARIO AE: bounded hunting over recorded matches"
    local r; r=$(api_get "/hunt/matches?ioc_type=domain&limit=10")
    echo "$r" | jq -e '.count >= 1 and (.matches[0].context == "lab-evil.example.test") and (.matches[0].incident_type == "ioc_match")' >/dev/null \
        && pass "hunt by indicator type returns the domain match joined to its incident" || fail "hunt result unexpected: ${r}"
    [ "$(curl -s -o /dev/null -w '%{http_code}' -H "Authorization: Bearer ${TOKEN}" "${API_BASE}/hunt/matches?limit=100000")" = "400" ] \
        && pass "oversized limit rejected" || fail "oversized limit accepted"
    [ "$(curl -s -o /dev/null -w '%{http_code}' -H "Authorization: Bearer ${TOKEN}" "${API_BASE}/hunt/matches?ip=bogus")" = "400" ] \
        && pass "malformed filter rejected" || fail "malformed filter accepted"
}

scenario_af_restart() {
    banner "SCENARIO AF: intelligence and match history survive a restart"
    local iocs; iocs=$(api_get "/intel/iocs?limit=500" | jq '.count')
    local hist; hist=$(api_get "/hunt/matches?limit=200" | jq '.count')
    docker restart "$VICTIM_CONTAINER" >/dev/null && wait_for_api && api_login
    sleep 3
    [ "$(api_get "/intel/iocs?limit=500" | jq '.count')" = "$iocs" ] && pass "indicators persisted (${iocs})" || fail "indicators lost across restart"
    [ "$(api_get "/hunt/matches?limit=200" | jq '.count')" = "$hist" ] && pass "match history persisted (${hist})" || fail "match history lost"
    [ "$(api_get "/intel/status" | jq -r '.matcher.loaded')" = "true" ] && pass "matcher reloaded its snapshot after restart" || fail "matcher not loaded after restart"
}

banner "VANGUARD Phase 6 -- Local Threat Intelligence Lab"
wait_for_api
api_login
scenario_aa_import
scenario_ab_match
scenario_ac_controls
scenario_ad_failed_import
scenario_ae_hunt
scenario_af_restart

banner "RESULTS (Phase 6)"
echo "  Passed: ${PASS_COUNT}   Failed: ${FAIL_COUNT}"
[ "$FAIL_COUNT" -gt 0 ] && { echo -e "${C_RED}PHASE 6 LAB RESULT: FAIL${C_RESET}"; exit 1; }
echo -e "${C_GREEN}PHASE 6 LAB RESULT: PASS${C_RESET}"
