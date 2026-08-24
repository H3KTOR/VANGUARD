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
