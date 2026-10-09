// Package thresholds is the single source of truth for every numeric
// trigger condition in the V1 Detection Engine spec. Both the real
// detection engine (internal/detection) and the demo Simulation Engine
// (internal/simulator) import these constants so a simulated attack and a
// real one are held to identical thresholds and never drift apart.
package thresholds

import "time"

// --- Authentication Attacks ---

const (
	// SSHBruteForceMinAttempts: "> 10 failed attempts from one IP in a
	// short window."
	SSHBruteForceMinAttempts = 10
	// SSHBruteForceWindow is the sliding window failed attempts are
	// counted within.
	SSHBruteForceWindow = 2 * time.Minute

	// FailedThenSuccessMinFailed is the minimum number of failures that
	// must precede a successful login for the CRITICAL escalation rule to
	// fire (spec example: "30 failed attempts followed by 1 successful
	// login").
	FailedThenSuccessMinFailed = 10
	// FailedThenSuccessWindow bounds how soon after the failure streak the
	// success must occur to count as the same sequence.
	FailedThenSuccessWindow = 5 * time.Minute
)

// --- Reconnaissance & Web Attacks ---

const (
	// PortScanDistinctPorts: "One IP touching multiple ports rapidly."
	PortScanDistinctPorts = 15
	PortScanWindow        = 30 * time.Second

	// WebDirScanMin404s: "Repeated 404s on sensitive paths."
	WebDirScanMin404s = 8
	WebDirScanWindow  = 1 * time.Minute

	// HTTPFloodMaxRequests: "> 300 requests from one IP within 60 seconds."
	HTTPFloodMaxRequests = 300
	HTTPFloodWindow      = 60 * time.Second
)

// SensitivePaths are web paths whose repeated 404s indicate directory /
// vulnerability scanning rather than normal traffic.
var SensitivePaths = []string{
	"/wp-admin", "/wp-login.php", "/.env", "/.git/config", "/phpmyadmin",
	"/admin", "/administrator", "/config.php", "/.aws/credentials",
	"/server-status", "/actuator/env", "/.ssh/id_rsa", "/xmlrpc.php",
	"/wp-content/debug.log", "/backup.sql", "/db.sql", "/.htpasswd",
}

// PathTraversalPatterns are substrings in a request path/query that
// indicate a path traversal / local file inclusion attempt.
var PathTraversalPatterns = []string{
	"../", "..\\", "%2e%2e", "%2e%2e/", "..%2f", "/etc/passwd", "/etc/shadow",
	"boot.ini", "win.ini", "/proc/self/environ",
}

// SQLiXSSPatterns are substrings indicating an SQL injection or XSS probe
// in a request path/query string. Detection-only, per spec: VANGUARD never
// validates whether the payload actually succeeds against the app.
var SQLiXSSPatterns = []string{
	"<script", "javascript:", "onerror=", "onload=",
	"' or '1'='1", "' or 1=1", "union select", "select * from",
	"drop table", "; drop ", "sleep(", "benchmark(", "xp_cmdshell",
	"/*!", "%27%20or%20", "' --", "\" or \"\"=\"",
}

// --- Deception ---

// HoneypotAnyConnection: "ANY connection to designated fake ports
// (CRITICAL)" -- intentionally no numeric threshold; a single touch is
// always sufficient. Kept here as documentation/reference for the honeypot
// package and honeypot simulator.
const HoneypotAnyConnection = 1

// --- Attack Chain Correlation (Task 3: Smart Detection) ---

const (
	// AttackChainWindow is the sliding window within which all three
	// stages (recon -> web probing -> auth probing) must occur from the
	// same source IP for the correlation engine to escalate to an
	// ATTACK_CHAIN incident. Spec example: 5 minutes.
	AttackChainWindow = 5 * time.Minute

	// AttackChainMinDistinctPorts is the recon-stage trigger: touching
	// this many distinct ports (within AttackChainWindow) counts as the
	// "Port Scan" stage of the chain. Deliberately lower than the
	// standalone PortScanDistinctPorts threshold (which has its own much
	// tighter 30s window) since the chain only needs "recon happened
	// recently", not a full-blown standalone port-scan incident.
	AttackChainMinDistinctPorts = 5

	// AttackChainMinWebProbes is the web-probing-stage trigger: this many
	// 403/404 responses (within AttackChainWindow) counts as the "Web
	// Probing" stage of the chain.
	AttackChainMinWebProbes = 3

	// AttackChainMinAuthFailures is the auth-probing-stage trigger: this
	// many failed SSH logins (within AttackChainWindow) counts as the
	// "Auth Probing" stage of the chain.
	AttackChainMinAuthFailures = 3

	// AttackChainRiskMultiplier is applied to the aggregated base severity
	// of the three composite stages before clamping, per spec: "multiply
	// the incident's aggregated Risk Score by 1.5".
	AttackChainRiskMultiplier = 1.5
)

// --- Web Attack Chain Correlation (Mega Expansion, Phase 3, Section 14) ---
//
// Extends the SAME ChainTracker/ScoreChain correlation architecture as
// Task 3's Attack Chain above to a web-focused multi-stage sequence:
// Web Probing -> Auth Probing -> Exploitation. Deliberately a WIDER
// window than the classic recon->web->auth chain (10 vs 5 minutes),
// since a deliberate web-app attacker chaining recon, credential abuse,
// and a shell/SSRF attempt typically paces the stages further apart
// than an automated network-level scanner does.
const (
	// WebAttackChainWindow is the sliding window within which all three
	// web-attack-chain stages must occur from the same source IP.
	WebAttackChainWindow = 10 * time.Minute

	// WebAttackChainMinWebProbes is the web-probing-stage trigger: this
	// many 403/404 responses OR API-abuse-shaped distinct-path touches
	// (within WebAttackChainWindow) counts as the "Web Probing" stage.
	WebAttackChainMinWebProbes = 3

	// WebAttackChainMinAuthFailures is the auth-probing-stage trigger:
	// this many failed SSH logins (within WebAttackChainWindow) counts
	// as the "Auth Probing" stage.
	WebAttackChainMinAuthFailures = 3

	// WebAttackChainMinExploitSignals is the exploitation-stage trigger:
	// at least this many Web-Shell-Indicator-shaped or SSRF-Indicator-
	// shaped requests (within WebAttackChainWindow) counts as the
	// "Exploitation" stage. Deliberately just 1 -- unlike the recon/auth
	// stages (which need volume to distinguish a real campaign from
	// noise), a single web-shell/SSRF-shaped request occurring AFTER
	// established web-probing and auth-probing stages is already a
	// meaningful escalation signal in context, even though that same
	// single request in isolation (Feature 3/8's own standalone rule)
	// stays a conservative LOW/MEDIUM finding.
	WebAttackChainMinExploitSignals = 1
)

// --- Web Scanner Behavior Detection (heuristic, Task 3) ---

const (
	// WebScannerMin4xx is the minimum number of 403/404 responses from one
	// IP within WebScannerWindow before the heuristic considers the
	// traffic "scanner-like" (frequency component of the heuristic).
	WebScannerMin4xx = 6
	// WebScannerWindow bounds the 4xx-frequency count above.
	WebScannerWindow = 1 * time.Minute
)

// SuspiciousUserAgents are substrings of known automated web
// vulnerability-scanner User-Agent strings. Matching is case-insensitive.
// This list is intentionally small and illustrative -- the heuristic in
// rule WebScannerBehavior does NOT require a match here to fire; a missing
// User-Agent combined with a high 4xx frequency is equally sufficient
// (see the heuristic doc comment in engine.go). Deliberately excludes
// generic HTTP client UAs (curl, python-requests, go-http-client, etc) --
// those are extremely common for legitimate health checks/integrations and
// would otherwise make the heuristic noisy; the "missing UA" signal below
// covers the common "scanner didn't bother setting one" case instead.
var SuspiciousUserAgents = []string{
	"nikto", "dirbuster", "gobuster", "wpscan", "sqlmap", "nmap", "masscan",
	"nuclei", "wfuzz", "feroxbuster", "dirb", "acunetix", "nessus", "zgrab",
	"libwww-perl", "havij", "w3af",
}

// --- Host Security (VANGUARD Mega Expansion, Phase 1) ---
//
// No eBPF / kernel modules are used anywhere below (per Architectural Rule
// #3): every scanner relies on periodic filesystem inspection, /etc parsing,
// and best-effort /proc walks. Intervals are deliberately minutes-scale (not
// seconds) since these are batch filesystem/process scans, not per-request
// hot-path work -- keeping CPU usage negligible on a "~25MB binary, near-zero
// overhead" host per the project's core philosophy (Phase 13: Performance).

const (
	// FIMScanInterval is how often the File Integrity Monitor re-hashes
	// every watched path and diffs against its baseline.
	FIMScanInterval = 2 * time.Minute

	// PersistenceScanInterval is how often cron/systemd/SSH-keys/shell
	// startup files/sudoers are re-read and diffed for new/changed
	// persistence mechanisms.
	PersistenceScanInterval = 3 * time.Minute

	// AccountScanInterval is how often /etc/passwd, /etc/shadow (metadata
	// only, never contents), and /etc/group are re-read and diffed.
	AccountScanInterval = 3 * time.Minute

	// PrivEscScanInterval is how often sudoers/privileged-group membership
	// and (best-effort) running root processes are re-checked.
	PrivEscScanInterval = 2 * time.Minute

	// SUIDScanInterval is how often the filesystem is walked for
	// SUID/SGID-bit binaries. Kept less frequent than the others since a
	// full filesystem walk is the most expensive of these scans; a
	// bounded set of root directories (see hostsec.DefaultSUIDScanRoots)
	// keeps even this manageable.
	SUIDScanInterval = 10 * time.Minute

	// HostScanTimeout bounds how long any single scan tick (one full
	// pass of one scanner) may run before it is abandoned via context
	// cancellation, so a pathological filesystem (e.g. a stuck network
	// mount) can never wedge a scanner goroutine forever.
	HostScanTimeout = 30 * time.Second

	// WritableDirEscalationNote documents the SUID/SGID escalation rule:
	// a SUID/SGID binary discovered under one of these directories (or
	// any directory whose own mode bits are world-writable) is escalated
	// to CRITICAL, since dropping a SUID binary into a writable location
	// is a classic privilege-escalation technique.
	WritableDirEscalationNote = "suid/sgid binary in world-writable or temp directory"
)

// DefaultFIMPaths are the sensitive files/directories monitored by the File
// Integrity Monitor out of the box (feature 1). Operators can extend this
// via -fim-paths.
var DefaultFIMPaths = []string{
	"/etc/passwd",
	"/etc/shadow",
	"/etc/group",
	"/etc/sudoers",
	"/etc/sudoers.d",
	"/etc/ssh/sshd_config",
	"/root/.ssh/authorized_keys",
	"/etc/crontab",
	"/etc/cron.d",
	"/etc/systemd/system",
}

// DefaultSUIDScanRoots are the directories walked by the SUID/SGID
// monitor. Bounded to the standard binary locations (rather than a full "/"
// walk) to keep scan time and I/O negligible, per Phase 13's performance
// requirements.
var DefaultSUIDScanRoots = []string{
	"/bin", "/sbin", "/usr/bin", "/usr/sbin", "/usr/local/bin", "/usr/local/sbin",
}

// WritableScanRoots are additional, smaller directories scanned for SUID
// binaries specifically because *any* SUID/SGID binary appearing here is
// automatically CRITICAL (see WritableDirEscalationNote) -- these are the
// classic locations an attacker drops a privilege-escalation payload.
var WritableScanRoots = []string{
	"/tmp", "/var/tmp", "/dev/shm",
}

// ShellStartupFiles are the shell-profile persistence locations checked by
// the Persistence Detector (feature 2), beyond /etc/profile(.d) and
// per-user authorized_keys (which are enumerated dynamically from
// /etc/passwd home directories, not listed here).
var ShellStartupFiles = []string{
	"/etc/profile",
	"/etc/bash.bashrc",
}

// PrivilegedGroups are the group names whose membership changes are
// treated as privilege-escalation-relevant by the Account/PrivEsc
// detectors (feature 3 & 4).
var PrivilegedGroups = []string{
	"sudo", "wheel", "root", "adm", "docker", "shadow", "disk",
}

// --- Host Security Phase 2 (VANGUARD Mega Expansion): Process Anomaly
// Detection, Process->File->Network Correlation, System Binary Integrity
// (features 6, 7, 8). Same no-eBPF/periodic-/proc-scan constraints as
// Phase 1 above.

const (
	// ProcessScanInterval is how often /proc is walked to rebuild the
	// process inventory and diff it against the previous scan.
	ProcessScanInterval = 1 * time.Minute

	// BinaryIntegrityScanInterval is how often the System Binary
	// Integrity watcher re-hashes its configured binary paths. Kept at
	// the same cadence as FIMScanInterval since it uses the identical
	// underlying diff mechanics.
	BinaryIntegrityScanInterval = 2 * time.Minute

	// ProcessCreationBurstThreshold: more than this many brand-new PIDs
	// observed in a single ProcessScanInterval tick is treated as an
	// "abnormal process creation burst" (e.g. a fork-bomb, a script
	// spawning many short-lived children, or automated post-exploitation
	// tooling). Deliberately generous -- a busy but legitimate host
	// (package manager runs, cron bursts) can easily spawn a few dozen
	// processes in a minute; this threshold targets a genuine anomaly,
	// not routine churn.
	ProcessCreationBurstThreshold = 60

	// HostCorrelationWindow bounds how far apart in time a Suspicious
	// Process finding (with a confirmed malicious-reputation outbound
	// connection) and a sensitive-file FIM change may be while still
	// counting as the same compromise event for
	// IncidentHighConfidenceCompromise (feature 7).
	HostCorrelationWindow = 10 * time.Minute
)

// NetworkFacingServiceNames are process executable basenames considered
// "network-facing" for the suspicious-parent-child heuristic: a shell or
// interpreter spawned by one of these is a classic post-exploitation
// pattern (e.g. a web server executing a reverse-shell payload after a
// successful RCE).
var NetworkFacingServiceNames = []string{
	"nginx", "httpd", "apache2", "sshd", "mysqld", "mariadbd", "postgres",
	"php-fpm", "vsftpd", "proftpd", "redis-server", "memcached",
}

// ShellAndInterpreterNames are process executable basenames considered
// "unexpected children" of a network-facing service in the suspicious
// parent-child heuristic.
var ShellAndInterpreterNames = []string{
	"sh", "bash", "dash", "zsh", "ash", "python", "python3", "perl", "ruby",
	"nc", "ncat", "netcat", "socat", "curl", "wget", "php",
}

// DefaultSystemBinaryPaths are the security-critical executables watched
// by the System Binary Integrity scanner (feature 8) out of the box.
// Deliberately a small, bounded list of the highest-value targets rather
// than every file under /bin -- per the mega-prompt's explicit "do not
// hash the entire filesystem by default" instruction. Operators can
// extend this via -binary-paths.
var DefaultSystemBinaryPaths = []string{
	"/bin/sh", "/bin/bash", "/usr/bin/sudo", "/usr/bin/su",
	"/usr/sbin/sshd", "/usr/bin/passwd", "/usr/bin/ssh",
	"/usr/bin/curl", "/usr/bin/wget", "/usr/bin/nc",
}

// ---------------------------------------------------------------------------
// Web Security (VANGUARD Mega Expansion, Phase 3)
//
// Every detector below is built ENTIRELY from what internal/detection's
// existing AuthLogParser/WebLogParser already expose (source IP, username,
// path, method, status code, User-Agent, Protocol, optional Host). None of
// these thresholds imply payload-level exploit confirmation, packet
// capture, or WAF-grade inline inspection -- see each IncidentType's own
// doc comment in internal/database/models.go for the specific visibility
// limitation of that detector.
// ---------------------------------------------------------------------------

const (
	// --- Password Spraying (feature 5) ---
	//
	// The key distinction from SSH Brute Force (thresholds.
	// SSHBruteForceMinAttempts failures against ONE account) is shape:
	// password spraying is MANY DISTINCT accounts, each receiving
	// relatively FEW attempts, from the same source IP. Deliberately a
	// wider window than brute force's own 2-minute window, since a
	// spraying campaign is typically slower-paced per-account (to dodge
	// per-account lockout policies) even though it touches more accounts
	// overall.
	PasswordSprayingWindow = 10 * time.Minute
	// PasswordSprayingMinDistinctUsernames is the minimum number of
	// DIFFERENT usernames that must each have failed at least once from
	// one source IP within the window before this is spraying rather
	// than ordinary single-account brute force.
	PasswordSprayingMinDistinctUsernames = 5
	// PasswordSprayingMaxAttemptsPerUser caps how many failures against
	// any ONE of those distinct usernames may count toward the spraying
	// signal -- if one username alone has racked up more than this many
	// failures, that username's own failures look like ordinary brute
	// force, not spraying, and are excluded from this correlation (the
	// standalone SSH Brute Force rule already covers that account).
	PasswordSprayingMaxAttemptsPerUser = 4

	// --- Credential Stuffing (feature 6) ---
	//
	// Broader and higher-rate than password spraying: MORE distinct
	// usernames AND a higher overall attempt volume in a comparable
	// window. VANGUARD never claims the attempted credentials were
	// actually sourced from a prior breach -- only that the OBSERVABLE
	// behavior (many accounts, high failure volume, from one source)
	// matches the credential-stuffing shape.
	CredentialStuffingWindow                = 10 * time.Minute
	CredentialStuffingMinDistinctUsernames  = 15
	CredentialStuffingMinTotalAttempts      = 25
	CredentialStuffingMinFailureRatioTenths = 7 // 0.7 as tenths (avoids a float threshold const)

	// --- Web Shell Indicators (feature 3) ---
	//
	// WebShellCorrelationWindow bounds how far apart in time a Web Shell
	// Indicator request and corroborating Phase 1/2 filesystem/process
	// evidence (FIM, System Binary Integrity, Suspicious Process) may be
	// while still counting as the same event for confidence escalation
	// (reuses internal/detection's existing HostCorrelator -- see
	// engine_web_security.go -- rather than a second correlation engine).
	WebShellCorrelationWindow = 10 * time.Minute

	// --- OAST / Out-of-Band Interaction Indicators (feature 9) ---
	//
	// OASTCallbackWindow bounds how long a distinct external
	// callback-shaped hostname observed from one source IP is
	// remembered for the "repeated callback" reinforcement signal.
	OASTCallbackWindow = 15 * time.Minute
	// OASTMinHostnameLabelLength: a callback-shaped subdomain label
	// (the leftmost DNS label) is typically a long random token, e.g.
	// "a1b2c3d4e5f6.oast.fun" -- labels shorter than this are far more
	// likely to be ordinary hostnames (www, api, cdn, static, ...) and
	// are excluded to keep the false-positive rate low.
	OASTMinHostnameLabelLength = 16

	// --- Host Header / Virtual Host Abuse (feature 10) ---
	//
	// HostHeaderEnumerationWindow bounds the sliding window used to
	// detect one source IP cycling through an abnormal number of
	// distinct Host header values (virtual-host enumeration/probing).
	HostHeaderEnumerationWindow = 5 * time.Minute
	// HostHeaderEnumerationMinDistinctHosts is the minimum number of
	// DIFFERENT Host values from one IP within the window before this
	// counts as enumeration, independent of whether any single value
	// looked suspicious on its own.
	HostHeaderEnumerationMinDistinctHosts = 5

	// --- HTTP Protocol Anomaly Detection (feature 11) ---
	//
	// HTTPProtocolAnomalyWindow / MinCount: a single malformed request
	// (bad method, non-standard protocol token, or a 400/414/431
	// response) is never itself an incident -- scanners and broken
	// clients produce these constantly. Only a SUSTAINED rate from one
	// IP within the window counts.
	HTTPProtocolAnomalyWindow   = 1 * time.Minute
	HTTPProtocolAnomalyMinCount = 8

	// --- Request-Smuggling Indicators (feature 12) ---
	//
	// VANGUARD's log-line visibility cannot see raw Content-Length/
	// Transfer-Encoding header values at all (standard Nginx/Apache
	// access-log formats never log request headers) -- this can only
	// watch the downstream SYMPTOM: an abnormal burst of
	// 400/408/502/503 responses from one source in a short window,
	// which is consistent with, but nowhere near proof of, a smuggling
	// attempt against a front-end/back-end pair.
	RequestSmugglingWindow   = 1 * time.Minute
	RequestSmugglingMinCount = 6

	// --- API Abuse Detection (feature 13) ---
	//
	// Endpoint-aware anomaly detection layered on top of (never
	// duplicating) Web Scanner Behavior/HTTP Flood/Web Dir Scan: one
	// source IP touching an abnormal number of DISTINCT paths, with a
	// high 401/403/404 ratio, within the window. Deliberately requires
	// BOTH high path diversity AND a high failure ratio -- "one IP makes
	// 100 normal successful requests to varied endpoints" must NOT
	// trigger this on path-count alone.
	APIAbuseWindow                = 1 * time.Minute
	APIAbuseMinDistinctPaths      = 20
	APIAbuseMinFailureRatioTenths = 6 // 0.6 as tenths
)

// ExpectedHosts is the configurable allowlist of Host header values
// VANGUARD's own deployment legitimately expects (Feature 10: Host Header
// / Virtual Host Abuse). Empty by default -- operators must explicitly
// configure this (via -expected-hosts / VANGUARD_EXPECTED_HOSTS) for
// "unexpected Host value" to be a meaningful signal; VANGUARD never
// requires a hard-coded domain to remain functional, and an empty list
// simply means that specific sub-check is skipped (the IP-address-Host,
// loopback/private-Host, and Host-enumeration checks below remain active
// regardless, since those don't depend on knowing the "real" hostname).
var ExpectedHosts []string

// WebShellExtensions are script/executable file extensions historically
// associated with web-shell payloads. A request path ending in one of
// these is, BY ITSELF, extremely weak evidence (ordinary PHP/JSP/ASP
// applications serve these constantly) -- see IncidentWebShellIndicator's
// doc comment for the corroborating-evidence model that actually drives
// confidence.
var WebShellExtensions = []string{
	".php", ".phtml", ".php3", ".php4", ".php5", ".php7",
	".jsp", ".jspx", ".asp", ".aspx", ".cfm",
}

// WebShellUploadPathHints are path substrings (case-insensitive) that
// suggest an upload/writable directory -- a script request under one of
// these is stronger evidence than the same extension under an ordinary
// application path.
var WebShellUploadPathHints = []string{
	"/upload", "/uploads", "/images", "/img", "/media", "/files",
	"/tmp", "/cache", "/wp-content/uploads", "/attachments",
}

// WebShellSuspiciousQueryParams are query-parameter names commonly used
// by web-shell command-execution interfaces (e.g. "?cmd=whoami").
// Case-insensitive substring match against the raw query string.
var WebShellSuspiciousQueryParams = []string{
	"cmd=", "exec=", "shell=", "command=", "system(", "passthru(",
	"eval(", "assert(", "base64_decode(",
}

// PrivateAndReservedTargets are substrings identifying a request target
// (path/query) that references a loopback, RFC1918/link-local private
// address, or a well-known cloud-metadata endpoint -- the SSRF Indicator
// signal (feature 8). This is a bounded, explicit list, never a full CIDR
// parser applied to arbitrary log text, since the evidence available is
// just a substring inside a path/query string, not a validated URL object.
var PrivateAndReservedTargets = []string{
	"127.0.0.1", "localhost", "::1",
	"169.254.169.254", // cloud metadata (AWS/GCP/Azure/OpenStack all use this)
	"metadata.google.internal",
	"10.", "192.168.",
	// 172.16.0.0/12: only the leading octet-pair patterns are checked
	// programmatically (see isRFC1916SecondOctet in the detector), not
	// listed here as literal strings, since "172.16." through "172.31."
	// all qualify and a flat substring list would be unwieldy/incomplete.
}

// SSRFMetadataEndpoints are the highest-confidence SSRF targets --
// cloud-metadata services that have no legitimate reason to ever appear
// in an external-facing web request's path/query. A hit against one of
// these alone is escalated (Critical) unlike an ordinary RFC1918 hit.
var SSRFMetadataEndpoints = []string{
	"169.254.169.254", "metadata.google.internal",
}

// KnownOASTProviderSuffixes are commercial OAST/interaction-tracking
// service domains, kept ONLY as a small reinforcing signal -- per this
// phase's explicit instruction, detection must NOT rely on this list as
// the sole mechanism. The primary signal is the behavioral heuristic in
// isCallbackShapedHostname (long random-looking leftmost label).
var KnownOASTProviderSuffixes = []string{
	".oast.fun", ".oast.pro", ".oast.live", ".oast.site", ".oast.online",
	".oast.me", ".burpcollaborator.net", ".interact.sh", ".dnslog.cn",
	".requestbin.net", ".webhook.site", ".canarytokens.com",
}

// ValidHTTPMethods are the standard HTTP methods VANGUARD treats as
// well-formed for the HTTP Protocol Anomaly detector (feature 11). A
// method outside this set (empty, lowercase-mismatched already
// normalized upstream, or a garbage token) counts toward the anomaly
// frequency counter.
var ValidHTTPMethods = map[string]bool{
	"GET": true, "POST": true, "PUT": true, "DELETE": true,
	"HEAD": true, "OPTIONS": true, "PATCH": true, "CONNECT": true,
	"TRACE": true,
}

// ProtocolAnomalyStatusCodes are status codes indicating a malformed
// request/response at the HTTP-protocol level (as opposed to an ordinary
// application-level 404/403).
var ProtocolAnomalyStatusCodes = map[int]bool{
	400: true, 414: true, 431: true,
}

// RequestSmugglingSymptomStatusCodes are status codes VANGUARD treats as
// downstream SYMPTOMS potentially consistent with request smuggling
// (front-end/back-end disagreement) -- see IncidentRequestSmugglingIndicator's
// doc comment for why this is the only visibility available.
var RequestSmugglingSymptomStatusCodes = map[int]bool{
	400: true, 408: true, 502: true, 503: true,
}

// AuthEndpointHints are path substrings identifying an authentication or
// otherwise sensitive API endpoint, used by the API Abuse detector to
// weight endpoint-touch diversity more heavily when it concentrates on
// these paths specifically.
var AuthEndpointHints = []string{
	"/login", "/auth", "/token", "/api/", "/oauth", "/signin", "/session",
}

// ---------------------------------------------------------------------------
// System Posture & Drift Detection (VANGUARD Mega Expansion, Phase 4):
// Configuration Posture, Configuration Drift, Listening Service Drift,
// Package Drift. Same no-eBPF/periodic-scan/bounded-target-list
// constraints as Phase 1/2 above -- every list here is a small, explicit
// allowlist, never a filesystem/process/package-database full dump.
// ---------------------------------------------------------------------------

const (
	// ConfigPostureScanInterval is how often the Configuration Posture
	// detector re-evaluates every configured posture check.
	ConfigPostureScanInterval = 5 * time.Minute

	// ConfigDriftScanInterval is how often monitored configuration
	// resources are re-snapshotted and diffed against their baseline.
	ConfigDriftScanInterval = 5 * time.Minute

	// ListeningServiceScanInterval is how often /proc/net/{tcp,tcp6,udp,
	// udp6} is parsed to rebuild the listening-socket inventory.
	ListeningServiceScanInterval = 2 * time.Minute

	// PackageDriftScanInterval is how often /var/lib/dpkg/status is
	// re-read and diffed against the package baseline. Kept relatively
	// infrequent since package state changes are rare, deliberate
	// events (not something that needs sub-minute visibility).
	PackageDriftScanInterval = 10 * time.Minute

	// ConfigDriftMaxHashBytes bounds how large a monitored file may be
	// before Configuration Drift will SHA-256 it. Files larger than
	// this are still compared by size/mode/owner/group metadata alone,
	// with HashSkipped=true explicitly recorded in the baseline entry
	// (never silently treated as unchanged, never read fully into
	// memory just to hash). 8 MiB comfortably covers every realistic
	// text configuration file while categorically excluding logs,
	// archives, or other large files an operator might mistakenly add
	// to the watch list.
	ConfigDriftMaxHashBytes = 8 * 1024 * 1024

	// ListeningServiceGracePeriod: on the very first Listening Service
	// Drift scan after VANGUARD starts, every socket observed is
	// silently seeded into the baseline (exactly like every other
	// hostsec scanner's isFirstScan/markSeeded cold-start pattern) --
	// this is the ADDITIONAL window after process start during which
	// new/removed listeners are silently absorbed into the baseline
	// (a slow-starting service coming up right after VANGUARD itself).
	// Configurable via listening.GracePeriod.
	ListeningServiceGracePeriod = 60 * time.Second

	// PrivilegedPortThreshold: a listening port at or below this value
	// is considered "privileged" (historically required root to bind)
	// for Listening Service Drift's risk contextualization -- a new
	// unexpected listener here is weighted higher than an identical one
	// on a high ephemeral-range port.
	PrivilegedPortThreshold = 1024
)

// DefaultConfigPosturePaths are the security-sensitive files/directories
// checked by the Configuration Posture detector out of the box for
// dangerous permissions (world-writable) and unexpected ownership.
// Deliberately the same high-value targets FIM already watches for
// content/metadata DRIFT -- Posture asks a different question of the
// identical allowlist ("is this currently unsafe"), not a new list.
// Operators can extend this via -posture-paths.
var DefaultConfigPosturePaths = []string{
	"/etc/passwd",
	"/etc/shadow",
	"/etc/group",
	"/etc/sudoers",
	"/etc/ssh/sshd_config",
	"/root/.ssh/authorized_keys",
	"/etc/crontab",
}

// DefaultConfigPostureExpectedOwners maps a monitored path to its
// expected "uid:gid" ownership string. A path with no entry here is
// still permission-checked (world-writable) but is NOT ownership-checked
// -- an explicit baseline is required per the mega-prompt's "never
// assume UID 0 universally" instruction, rather than defaulting every
// unlisted path to root:root.
var DefaultConfigPostureExpectedOwners = map[string]string{
	"/etc/passwd":                "0:0",
	"/etc/shadow":                "0:0",
	"/etc/group":                 "0:0",
	"/etc/sudoers":               "0:0",
	"/etc/ssh/sshd_config":       "0:0",
	"/root/.ssh/authorized_keys": "0:0",
	"/etc/crontab":               "0:0",
}

// DefaultConfigDriftPaths are the configuration resources monitored for
// baseline DRIFT (created/deleted/mode/owner/group/content changes) out
// of the box. A deliberately small, explicit allowlist -- never a
// filesystem walk -- extendable via -drift-paths.
var DefaultConfigDriftPaths = []string{
	"/etc/passwd",
	"/etc/shadow",
	"/etc/group",
	"/etc/sudoers",
	"/etc/ssh/sshd_config",
	"/root/.ssh/authorized_keys",
	"/etc/crontab",
	"/etc/hosts",
	"/etc/nginx/nginx.conf",
}

// CriticalConfigDriftPaths are watched Configuration Drift resources
// whose any change is escalated to Critical=true outright, mirroring
// FIM's criticalFIMPaths pattern -- these are the highest-value
// authentication/access-control targets among DefaultConfigDriftPaths.
var CriticalConfigDriftPaths = map[string]bool{
	"/etc/shadow":                true,
	"/etc/sudoers":               true,
	"/etc/ssh/sshd_config":       true,
	"/root/.ssh/authorized_keys": true,
}

// DefaultExpectedListeners is the out-of-the-box allowlist of listening
// services Listening Service Drift should treat as expected (never
// generating a "new listener" finding), expressed as protocol/address-
// pattern/port triples. "*" matches any address. Operators extend this
// via -expected-listeners; matching is explicit/deterministic, never
// auto-trust-on-first-observation (see hostsec/listening.go).
type ExpectedListener struct {
	Protocol        string // "tcp", "tcp6", "udp", "udp6", or "*" for any
	AddressPattern  string // exact bind address, or "*" for any
	Port            int
	ProcessNameHint string // optional; empty matches any process
}

// DefaultExpectedListeners is deliberately small: VANGUARD's own
// loopback-bound REST API port is the only service this host-security
// subsystem can assume is always present and legitimate without
// operator configuration. SSH/HTTP/etc. are expected to be explicitly
// allowlisted by the operator for their own environment via
// -expected-listeners, since VANGUARD cannot know in advance which of
// those a given deployment legitimately runs.
var DefaultExpectedListeners = []ExpectedListener{
	{Protocol: "*", AddressPattern: "127.0.0.1", Port: 8080},
}

// DefaultIgnoredPackages are dpkg package names Package Drift never
// reports drift for (typically extremely high-churn metadata-only
// packages). Deliberately a tiny list -- no giant distro-specific
// blocklist, per the mega-prompt's explicit instruction.
var DefaultIgnoredPackages = []string{
	"base-files",
}

// DefaultWatchedSecurityPackages are dpkg package names whose REMOVAL or
// DOWNGRADE is escalated to a higher-severity Package Drift finding
// (Critical=true), since losing or regressing one of these has direct
// security impact. Deliberately a small, high-value set, not a full
// distro security-package catalog.
var DefaultWatchedSecurityPackages = []string{
	"openssh-server",
	"openssh-client",
	"sudo",
	"iptables",
	"ufw",
	"libssl3",
	"libssl1.1",
}

// DefaultHighRiskPackagePatterns are path.Match-style glob patterns for
// dpkg package names whose fresh INSTALLATION is weighted higher by
// Package Drift (offensive/dual-use tooling that has no business being
// newly installed on a production server). Deliberately tiny -- a
// pattern list, not a distro-specific package catalogue.
var DefaultHighRiskPackagePatterns = []string{
	"nmap", "ncat", "netcat*", "hydra", "john", "socat", "tcpdump",
}

const (
	// Phase 4 hard state bounds. Every collection a Phase 4 detector
	// holds or persists is capped by one of these so no attacker- or
	// environment-controlled input can grow memory or database usage
	// without limit.
	MaxConfigDriftResources = 256
	MaxListeningSockets     = 2048
	MaxPackages             = 20000
	// MaxProcPIDsScanned bounds the /proc/<pid>/fd walk used to resolve
	// a listening socket's owning process.
	MaxProcPIDsScanned = 8192
	// MaxPackageStatusBytes bounds how much of /var/lib/dpkg/status is
	// ever read.
	MaxPackageStatusBytes = 64 * 1024 * 1024
	// MinPhase4ScanInterval is the floor enforced on an operator-supplied
	// scan interval so a typo cannot turn a scanner into a busy loop.
	MinPhase4ScanInterval = 1 * time.Second
)
