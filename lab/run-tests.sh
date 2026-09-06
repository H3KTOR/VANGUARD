#!/bin/bash
# lab/run-tests.sh
#
# VANGUARD Automated Security Test Lab -- attack orchestration + detection
# verification (Task 4).
#
# Fires a sequence of REAL synthetic attacks (genuine nmap/hydra/curl
# traffic, not fabricated test fixtures) from this "attacker" container at
# the "victim" container's real sshd/nginx, then queries VANGUARD's own
# REST API (a thin layer over its SQLite database -- see
# internal/api/handlers_incidents.go) to assert every expected detection
# actually fired, printing a clear "[✓] DETECTED" / "[✗] MISSING" report
# per scenario. Exits non-zero if anything was missed, so this doubles as
# a CI-style regression gate for the whole detection engine.
#
# Usage (from the lab/ directory):
#   docker compose up -d --build victim
#   docker compose run --rm attacker ./run-tests.sh
#
set -uo pipefail

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
VICTIM_HOST="${VICTIM_HOST:-victim}"
VICTIM_IP="${VICTIM_IP:-172.28.0.10}"
API_BASE="http://${VICTIM_HOST}:8080/api"
ATTACKER_IP="${ATTACKER_IP:-172.28.0.20}" # must match docker-compose.yml's static IP for `attacker`

ADMIN_EMAIL="lab-admin@vanguard.local"
ADMIN_PASSWORD="LabPassword123!"

SSH_USER="testuser"
WORDLIST="/tmp/wrong_passwords.txt"

POLL_TIMEOUT=30   # seconds to wait for an expected incident to appear
POLL_INTERVAL=2

PASS_COUNT=0
FAIL_COUNT=0

# Colors (safe no-op if the terminal doesn't support them)
C_GREEN='\033[0;32m'; C_RED='\033[0;31m'; C_YELLOW='\033[1;33m'; C_CYAN='\033[0;36m'; C_RESET='\033[0m'

banner() {
    echo -e "${C_CYAN}"
    echo "=============================================================="
    echo " $1"
    echo "=============================================================="
    echo -e "${C_RESET}"
}

log()  { echo -e "${C_YELLOW}[lab]${C_RESET} $*"; }

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

wait_for_victim() {
    log "waiting for victim's REST API to become healthy..."
    for i in $(seq 1 30); do
        if curl -sf "${API_BASE}/health" > /dev/null 2>&1; then
            log "victim is up."
            return 0
        fi
        sleep 2
    done
    echo -e "${C_RED}victim never became healthy -- aborting.${C_RESET}"
    exit 1
}

# api_bootstrap registers (or, on a re-run, logs into) the lab's admin
# account and populates $TOKEN for every subsequent authenticated request.
api_bootstrap() {
    log "bootstrapping VANGUARD admin account for API verification..."
    curl -s -X POST "${API_BASE}/auth/register" \
        -H 'Content-Type: application/json' \
        -d "{\"email\":\"${ADMIN_EMAIL}\",\"password\":\"${ADMIN_PASSWORD}\"}" > /dev/null

    local resp
    resp=$(curl -s -X POST "${API_BASE}/auth/login" \
        -H 'Content-Type: application/json' \
        -d "{\"email\":\"${ADMIN_EMAIL}\",\"password\":\"${ADMIN_PASSWORD}\"}")

    TOKEN=$(echo "$resp" | jq -r '.token // empty')
    if [ -z "$TOKEN" ]; then
        echo -e "${C_RED}failed to obtain an API token -- login response: ${resp}${C_RESET}"
        exit 1
    fi
    log "authenticated with VANGUARD's REST API."
}

api_get() {
    curl -s -H "Authorization: Bearer ${TOKEN}" "${API_BASE}$1"
}

# assert_incident polls the /api/incidents endpoint (filtered by incident
# type + source IP -- the exact same query the dashboard's incident feed
# uses) until at least one matching row appears or POLL_TIMEOUT elapses.
# This is the script's core "query the victim's DB via the REST API and
# assert detection happened" step.
assert_incident() {
    local incident_type="$1"
    local description="$2"
    local ip="${3:-$ATTACKER_IP}"
    local elapsed=0

    while [ "$elapsed" -lt "$POLL_TIMEOUT" ]; do
        local resp count
        resp=$(api_get "/incidents?type=${incident_type}&ip=${ip}&limit=5")
        count=$(echo "$resp" | jq -r '.count // 0')
        if [ "$count" != "0" ] && [ -n "$count" ]; then
            local risk sev id
            id=$(echo "$resp" | jq -r '.incidents[0].id')
            risk=$(echo "$resp" | jq -r '.incidents[0].risk_score')
            sev=$(echo "$resp" | jq -r '.incidents[0].severity')
            echo -e "${C_GREEN}[✓] DETECTED${C_RESET}  ${description} -- incident #${id}, risk=${risk}/100, severity=${sev} (${count} matching incident(s))"
            PASS_COUNT=$((PASS_COUNT+1))
            return 0
        fi
        sleep "$POLL_INTERVAL"
        elapsed=$((elapsed+POLL_INTERVAL))
    done

    echo -e "${C_RED}[✗] MISSING${C_RESET}   ${description} -- no '${incident_type}' incident found for ${ip} after ${POLL_TIMEOUT}s"
    FAIL_COUNT=$((FAIL_COUNT+1))
    return 1
}

# ---------------------------------------------------------------------------
# Attack scenarios
# ---------------------------------------------------------------------------

# Scenario A: the full coordinated Attack Chain -- Recon (nmap against
# VANGUARD's honeypot decoy ports) -> Web Probing (curl 404s on sensitive
# paths) -> Auth Probing (hydra SSH brute force), run strictly in that
# order, all from this one attacker IP within a few seconds -- well inside
# thresholds.AttackChainWindow (5 min). As a side effect this also
# naturally exercises three of VANGUARD's *standalone* V1 rules (honeypot
# trigger, web directory scan, SSH brute force), so a single scenario
# doubles as the "standard SSH/Web attacks" coverage the task calls for.
scenario_attack_chain() {
    banner "SCENARIO A: Coordinated Attack Chain (Recon -> Web Probing -> Auth Probing)"

    log "[stage 1/3] RECON: nmap TCP-connect scan against VANGUARD's honeypot decoy ports..."
    nmap -sT -Pn -p 21,23,2222,3389,5432,6379,33060,8081 "$VICTIM_HOST" 2>&1 | sed 's/^/    /'

    log "[stage 2/3] WEB PROBING: requesting sensitive paths that don't exist (expect 404s)..."
    for path in "/wp-admin/admin-ajax.php" "/wp-login.php" "/.env" "/.git/config" \
                "/phpmyadmin/index.php" "/config.php" "/.aws/credentials" "/xmlrpc.php"; do
        code=$(curl -s -o /dev/null -w '%{http_code}' "http://${VICTIM_HOST}${path}")
        echo "    GET ${path} -> ${code}"
    done

    log "[stage 3/3] AUTH PROBING: hydra SSH brute force against ${SSH_USER}@${VICTIM_HOST} (wrong passwords only)..."
    printf 'wrong1\nwrong2\nwrong3\nwrong4\nwrong5\nwrong6\nwrong7\nwrong8\nwrong9\nwrong10\nwrong11\nwrong12\nwrong13\nwrong14\nwrong15\n' > "$WORDLIST"
    hydra -l "$SSH_USER" -P "$WORDLIST" -t 4 -f -o /tmp/hydra_chain.log "ssh://${VICTIM_HOST}" 2>&1 | tail -5 | sed 's/^/    /'

    log "attack chain sequence complete; querying VANGUARD for detections..."
    assert_incident "attack_chain"        "Coordinated Attack Chain (Recon -> Web -> Auth)"
    assert_incident "honeypot_trigger"    "Honeypot decoy port trigger (from the nmap recon stage)"
    assert_incident "web_directory_scan"  "Web Directory Scan (from the web-probing stage)"
    assert_incident "ssh_bruteforce"      "SSH Brute Force (from the auth-probing stage)"
}

# Scenario B: Web Scanner Behavior heuristic -- a burst of 404s carrying a
# known-scanner User-Agent string (Nikto), which is NOT a signature match
# by itself; it only fires on the *combination* of high 4xx frequency +
# suspicious/missing UA (see ruleWebScannerBehavior in engine.go).
scenario_web_scanner() {
    banner "SCENARIO B: Web Scanner Behavior Heuristic (404 flood + Nikto User-Agent)"

    log "sending a burst of 404s with a Nikto User-Agent header..."
    for i in $(seq 1 10); do
        code=$(curl -s -o /dev/null -w '%{http_code}' -A "Nikto/2.5.0 (Evasions:None)" \
            "http://${VICTIM_HOST}/scanner-probe-${i}.php")
        echo "    GET /scanner-probe-${i}.php (UA: Nikto/2.5.0) -> ${code}"
    done

    assert_incident "web_scanner_behavior" "Web Scanner Behavior (404 flood + Nikto User-Agent)"
}

# Scenario C: Path Traversal + SQLi/XSS probes -- single-request
# signature matches, no threshold needed.
scenario_web_signatures() {
    banner "SCENARIO C: Path Traversal + SQLi/XSS Signature Probes"

    log "requesting a path-traversal payload..."
    curl -s -o /dev/null "http://${VICTIM_HOST}/../../etc/passwd"
    curl -s -o /dev/null "http://${VICTIM_HOST}/files?path=../../../etc/passwd"

    log "requesting a SQLi/XSS payload..."
    curl -s -o /dev/null "http://${VICTIM_HOST}/search?q=%27%20OR%20%271%27%3D%271"
    curl -s -o /dev/null "http://${VICTIM_HOST}/comment?q=<script>alert(1)</script>"

    assert_incident "path_traversal" "Path Traversal probe"
    assert_incident "sqli_xss_probe" "SQL Injection / XSS probe"
}

# Scenario D: HTTP Flood -- pure volume, no malicious payload at all
# (thresholds.HTTPFloodMaxRequests=300 within thresholds.HTTPFloodWindow=60s).
scenario_http_flood() {
    banner "SCENARIO D: HTTP Flood (>300 requests in under 60 seconds)"

    log "firing 320 rapid GET requests at /ind... (this takes ~20-40s)"
    for i in $(seq 1 320); do
        curl -s -o /dev/null "http://${VICTIM_HOST}/index.html" &
        # Cap concurrency so we don't exhaust the attacker container's
        # own ephemeral ports/file descriptors mid-flood.
        if (( i % 40 == 0 )); then wait; fi
    done
    wait

    assert_incident "http_flood" "HTTP Flood"
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

banner "VANGUARD v3.0 -- Automated Security Test Lab"
log "victim:   http://${VICTIM_HOST}:8080 (${VICTIM_IP})"
log "attacker: ${ATTACKER_IP} (this container)"
echo

wait_for_victim
api_bootstrap

scenario_attack_chain
scenario_web_scanner
scenario_web_signatures
scenario_http_flood

banner "RESULTS"
TOTAL=$((PASS_COUNT+FAIL_COUNT))
echo -e "  ${C_GREEN}Passed:${C_RESET} ${PASS_COUNT} / ${TOTAL}"
if [ "$FAIL_COUNT" -gt 0 ]; then
    echo -e "  ${C_RED}Failed:${C_RESET} ${FAIL_COUNT} / ${TOTAL}"
    echo
    echo -e "${C_RED}LAB RESULT: FAIL -- one or more expected detections did not fire.${C_RESET}"
    exit 1
fi

echo
echo -e "${C_GREEN}LAB RESULT: PASS -- every synthetic attack was detected by VANGUARD.${C_RESET}"
exit 0
