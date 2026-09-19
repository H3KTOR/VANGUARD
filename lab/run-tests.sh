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
# Phase 3 (Mega Expansion): Advanced Web Security Detection scenarios.
#
# Each fires REAL synthetic traffic (genuine hydra/curl requests, not
# fabricated fixtures) at the victim's real sshd/nginx, exactly like
# Scenarios A-D above, then verifies the corresponding Phase 3 incident
# type via VANGUARD's own REST API. Placed immediately after Scenario A
# (Coordinated Attack Chain) so the Web Attack Chain correlation scenario
# (scenario_web_attack_chain below) can piggyback on Scenario A's already-
# completed web-probing + auth-probing stages while still well inside
# thresholds.WebAttackChainWindow (10 minutes).
# ---------------------------------------------------------------------------

# Scenario E: Password Spraying -- many DISTINCT accounts, each tried only
# ONCE (well under thresholds.PasswordSprayingMaxAttemptsPerUser=4), which
# is what distinguishes this from Scenario A's single-account SSH Brute
# Force stage. hydra's default `-L userlist -p singlepassword` behavior
# tries each login exactly once against that one password.
scenario_password_spraying() {
    banner "SCENARIO E: Password Spraying (many distinct accounts, 1 attempt each)"

    printf 'sprayuser1\nsprayuser2\nsprayuser3\nsprayuser4\nsprayuser5\nsprayuser6\n' > /tmp/spray_users.txt
    log "hydra: 6 distinct accounts x 1 wrong-password attempt each..."
    hydra -L /tmp/spray_users.txt -p 'Sprayed_Wr0ngPW!' -t 4 -o /tmp/hydra_spray.log "ssh://${VICTIM_HOST}" 2>&1 | tail -5 | sed 's/^/    /'

    assert_incident "password_spraying" "Password Spraying (6 distinct accounts, 1 attempt each)"
}

# Scenario F: Credential Stuffing -- many distinct accounts (>= 15) AND a
# high total attempt volume (>= 25) AND a high failure ratio (>= 0.7),
# ALL THREE required together (see evaluateCredentialStuffing's doc
# comment). Two hydra passes with two different passwords against the
# SAME 16-account list yields 16 distinct usernames x 2 attempts = 32
# total attempts, all failing.
scenario_credential_stuffing() {
    banner "SCENARIO F: Credential Stuffing (16 accounts x 2 password attempts, 100% failure)"

    printf 'stuffuser1\nstuffuser2\nstuffuser3\nstuffuser4\nstuffuser5\nstuffuser6\nstuffuser7\nstuffuser8\nstuffuser9\nstuffuser10\nstuffuser11\nstuffuser12\nstuffuser13\nstuffuser14\nstuffuser15\nstuffuser16\n' > /tmp/stuffing_users.txt
    log "hydra pass 1/2: 16 accounts x leaked-password-candidate #1..."
    hydra -L /tmp/stuffing_users.txt -p 'StuffedPW_1!' -t 8 -o /tmp/hydra_stuff1.log "ssh://${VICTIM_HOST}" 2>&1 | tail -3 | sed 's/^/    /'
    log "hydra pass 2/2: 16 accounts x leaked-password-candidate #2..."
    hydra -L /tmp/stuffing_users.txt -p 'StuffedPW_2!' -t 8 -o /tmp/hydra_stuff2.log "ssh://${VICTIM_HOST}" 2>&1 | tail -3 | sed 's/^/    /'

    assert_incident "credential_stuffing" "Credential Stuffing (16 accounts x 2 attempts, 100% failure ratio)"
}

# Scenario G: Web Shell Indicators -- a request matching all three
# request-shape signals at once (script extension + upload-path location
# + command-execution-style query param), against the static fixture
# file this Dockerfile plants at /var/www/html/uploads/shell.php (an
# inert placeholder -- VANGUARD only ever inspects the REQUEST PATH,
# never file contents).
scenario_web_shell_indicator() {
    banner "SCENARIO G: Web Shell Indicators (script + upload-path + cmd= query param)"

    log "requesting the upload-path script fixture with a suspicious query param..."
    curl -s -o /dev/null "http://${VICTIM_HOST}/uploads/shell.php?cmd=whoami"

    assert_incident "web_shell_indicator" "Web Shell Indicator (uploads/shell.php?cmd=whoami)"
}

# Scenario H: Web Attack Chain Correlation (Phase 3, Section 14) -- fires
# NO new attack traffic of its own. This is a deliberate demonstration
# that the correlation is a genuine SIDE EFFECT of independently-existing
# detectors, exactly as the mega-prompt requires ("extend existing
# correlation architecture, never a new engine"): Scenario A already
# produced this attacker IP's Web Probing stage (the 404 web-probing
# curls) and Auth Probing stage (the 15-attempt hydra brute force
# against testuser) in that chronological order; Scenario G immediately
# above just produced the Exploitation stage (the web-shell-shaped
# request). All three land well inside thresholds.WebAttackChainWindow
# (10 minutes) of each other, so by the time this scenario runs, VANGUARD
# should already have raised a web_attack_chain incident purely from
# those two earlier scenarios' own independent traffic.
scenario_web_attack_chain() {
    banner "SCENARIO H: Web Attack Chain Correlation (Web Probing -> Auth Probing -> Exploitation)"
    log "no new traffic fired -- verifying this is a SIDE EFFECT of Scenarios A + G..."

    assert_incident "web_attack_chain" "Web Attack Chain (Scenario A's web/auth probing + Scenario G's web-shell exploitation)"
}

# Scenario I: SSRF Indicators -- a request whose path/query references a
# cloud-metadata endpoint, the highest-confidence SSRF target (escalates
# the incident, unlike an ordinary RFC1918/loopback reference alone).
scenario_ssrf_indicator() {
    banner "SCENARIO I: SSRF Indicators (cloud-metadata endpoint reference)"

    log "requesting a URL-fetch-shaped endpoint targeting the AWS/GCP/Azure metadata IP..."
    curl -s -o /dev/null "http://${VICTIM_HOST}/fetch?url=http://169.254.169.254/latest/meta-data/"

    assert_incident "ssrf_indicator" "SSRF Indicator (cloud-metadata endpoint reference)"
}

# Scenario J: OAST / Out-of-Band Interaction Indicators -- a request
# embedding a long, random-looking leftmost DNS label under a known
# commercial OAST provider suffix (reinforcement signal on top of the
# primary length+randomness heuristic).
scenario_oast_indicator() {
    banner "SCENARIO J: OAST / Out-of-Band Interaction Indicators (callback-shaped hostname)"

    log "requesting a webhook-shaped endpoint embedding a callback-shaped hostname..."
    curl -s -o /dev/null "http://${VICTIM_HOST}/webhook?callback=http://a1b2c3d4e5f6g7h8.oast.fun/x"

    assert_incident "oast_indicator" "OAST Indicator (a1b2c3d4e5f6g7h8.oast.fun callback hostname)"
}

# Scenario K: Host Header / Virtual Host Abuse -- a single request whose
# Host header names a loopback IP literal, which escalates the incident
# on the first occurrence (see ruleHostHeaderAbuse's escalate condition)
# rather than requiring sustained enumeration. Only possible because this
# lab's nginx has been given a custom log_format that appends $host (see
# lab/victim/nginx-vhost-log.conf) -- the stock "combined" format never
# logs Host at all.
scenario_host_header_abuse() {
    banner "SCENARIO K: Host Header / Virtual Host Abuse (loopback IP-literal Host header)"

    log "requesting with Host: 127.0.0.1 ..."
    curl -s -o /dev/null -H 'Host: 127.0.0.1' "http://${VICTIM_HOST}/"

    assert_incident "host_header_anomaly" "Host Header Anomaly (loopback IP-literal Host header)"
}

# Scenario L: HTTP Protocol Anomaly Detection -- a SUSTAINED RATE (>=
# thresholds.HTTPProtocolAnomalyMinCount=8) of requests using a
# non-standard HTTP method token, well within thresholds.
# HTTPProtocolAnomalyWindow (1 minute). A single malformed request alone
# must never trigger this (see isProtocolAnomalous's doc comment).
scenario_http_protocol_anomaly() {
    banner "SCENARIO L: HTTP Protocol Anomaly Detection (9x non-standard method token)"

    log "firing 9 requests with a non-standard HTTP method (FOOBAR)..."
    for i in $(seq 1 9); do
        curl -s -o /dev/null -X FOOBAR "http://${VICTIM_HOST}/"
    done

    assert_incident "http_protocol_anomaly" "HTTP Protocol Anomaly (9x non-standard method token)"
}

# Scenario M: Request-Smuggling Indicators -- SYMPTOM-ONLY: a sustained
# burst (>= thresholds.RequestSmugglingMinCount=6) of 400/408/502/503
# responses, produced here by sending conflicting Content-Length /
# Transfer-Encoding headers on the same request -- a genuine front-end/
# back-end-disagreement-shaped malformation nginx itself rejects with a
# real 400, not a fabricated status code.
scenario_request_smuggling_indicator() {
    banner "SCENARIO M: Request-Smuggling Indicators (7x conflicting Content-Length/Transfer-Encoding)"

    log "firing 7 requests with conflicting Content-Length/Transfer-Encoding headers..."
    for i in $(seq 1 7); do
        curl -s -o /dev/null --max-time 3 -H 'Transfer-Encoding: chunked' -H 'Content-Length: 5' \
            -X POST --data 'hello' "http://${VICTIM_HOST}/"
    done

    assert_incident "request_smuggling_indicator" "Request-Smuggling Indicator (7x conflicting-header 400s)"
}

# Scenario N: API Abuse Detection -- HIGH distinct-path diversity (>=
# thresholds.APIAbuseMinDistinctPaths=20) COMBINED WITH a high failure
# ratio (>= thresholds.APIAbuseMinFailureRatioTenths=0.6), within
# thresholds.APIAbuseWindow (1 minute). Deliberately uses 50 (not just
# 21) distinct nonexistent endpoints, all 404: the APIAbuseTracker is a
# single shared per-IP/1-minute-window counter that also saw a handful
# of earlier scenarios' successful ("/", shell.php) requests still
# within that same rolling window, which would otherwise dilute the
# failure ratio below threshold -- the extra volume here gives enough
# margin that this scenario's own traffic dominates the ratio
# regardless of exactly how much earlier noise is still in-window.
scenario_api_abuse() {
    banner "SCENARIO N: API Abuse Detection (50x distinct nonexistent endpoints, 100% failure)"

    log "enumerating 50 distinct nonexistent API-shaped endpoints..."
    for i in $(seq 1 50); do
        curl -s -o /dev/null "http://${VICTIM_HOST}/api/resource${i}"
    done

    assert_incident "api_abuse" "API Abuse (50 distinct endpoints enumerated, high failure ratio)"
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
scenario_password_spraying
scenario_credential_stuffing
scenario_web_shell_indicator
scenario_web_attack_chain
scenario_ssrf_indicator
scenario_oast_indicator
scenario_host_header_abuse
scenario_http_protocol_anomaly
scenario_request_smuggling_indicator
scenario_api_abuse
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
