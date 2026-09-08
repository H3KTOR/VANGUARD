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
