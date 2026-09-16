package detection

import (
	"strings"

	"vanguard/core/internal/thresholds"
)

// ---------------------------------------------------------------------------
// Web Shell Indicators (Phase 3, feature 3/7).
//
// A single request to a script/executable path is, BY ITSELF, extremely
// weak evidence: ordinary PHP/JSP/ASP applications serve requests to
// .php/.jsp/.aspx paths constantly, and even an upload-directory hit
// alone (e.g. a CMS legitimately serving /wp-content/uploads/foo.php as
// part of normal operation, misconfigured or not) is not proof of a
// planted web shell. This detector therefore combines THREE independent,
// individually-weak request-shape signals -- extension, upload-path
// location, and a suspicious command-execution-style query parameter --
// and treats them as increasing (never conclusive on their own)
// confidence. The actual escalation to a strong finding happens via
// CORRELATION with Phase 1/2 host-security evidence (FIM / System Binary
// Integrity / Suspicious Process, the same HostCorrelator wired up in
// engine_hostsec.go for feature 7), not by inflating this detector's own
// base severity -- a single .php request alone must stay LOW/MEDIUM,
// never CRITICAL, regardless of how many of the three signals it hits.
// ---------------------------------------------------------------------------

// webShellRequestSignals classifies a single HTTP request's path/query
// against the three independent, individually-weak web-shell-indicator
// signals. hasExtension is true when the path ends in one of
// thresholds.WebShellExtensions; inUploadPath is true when the path
// contains one of thresholds.WebShellUploadPathHints; suspiciousParam is
// true when the query portion of the path contains one of
// thresholds.WebShellSuspiciousQueryParams.
type webShellRequestSignals struct {
	hasExtension    bool
	inUploadPath    bool
	suspiciousParam bool
}

// any reports whether at least one of the three signals fired.
func (s webShellRequestSignals) any() bool {
	return s.hasExtension || s.inUploadPath || s.suspiciousParam
}

// count reports how many of the three signals fired, used to keep the
// (still conservative) frequency-style scoring bonus proportional to how
// much of the request shape matched, without ever treating that count as
// confirmed exploitation.
func (s webShellRequestSignals) count() int {
	n := 0
	if s.hasExtension {
		n++
	}
	if s.inUploadPath {
		n++
	}
	if s.suspiciousParam {
		n++
	}
	return n
}

// classifyWebShellRequest inspects path (which, per WebLogParser, already
// includes any query string logged as part of the request-line target)
// for the three web-shell-indicator signals.
func classifyWebShellRequest(path string) webShellRequestSignals {
	if path == "" {
		return webShellRequestSignals{}
	}
	lower := strings.ToLower(path)

	// Extension check applies only to the path portion (before any '?'),
	// so a query string that happens to end in ".php" (e.g.
	// "?redirect=/legit.php") does not itself count as the REQUESTED
	// resource being a script.
	pathOnly := lower
	if i := strings.IndexByte(pathOnly, '?'); i >= 0 {
		pathOnly = pathOnly[:i]
	}

	var sig webShellRequestSignals
	for _, ext := range thresholds.WebShellExtensions {
		if strings.HasSuffix(pathOnly, strings.ToLower(ext)) {
			sig.hasExtension = true
			break
		}
	}
	for _, hint := range thresholds.WebShellUploadPathHints {
		if strings.Contains(lower, strings.ToLower(hint)) {
			sig.inUploadPath = true
			break
		}
	}
	for _, param := range thresholds.WebShellSuspiciousQueryParams {
		if strings.Contains(lower, strings.ToLower(param)) {
			sig.suspiciousParam = true
			break
		}
	}
	return sig
}
