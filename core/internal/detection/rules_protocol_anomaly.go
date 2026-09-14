package detection

import (
	"strings"

	"vanguard/core/internal/thresholds"
)

// ---------------------------------------------------------------------------
// HTTP Protocol Anomaly Detection (Phase 3, feature 11).
//
// A single malformed request (bad method, non-standard protocol token, or
// a 400/414/431 response) is never itself an incident -- scanners and
// broken clients produce these constantly. This detector reuses
// state.State's existing sliding-window counter (RecordHTTPRequest-style
// pattern) via a dedicated small tracker only for the anomalous subset of
// requests, so the SUSTAINED-RATE requirement is enforced by a real
// per-IP window, not a single-event signature match.
// ---------------------------------------------------------------------------

// isProtocolAnomalous reports whether ev's method, protocol token, or
// status code individually looks like an HTTP-protocol-level
// malformation (as opposed to an ordinary application-level 404/403).
func isProtocolAnomalous(ev *Event) bool {
	if ev.Method != "" && !thresholds.ValidHTTPMethods[strings.ToUpper(ev.Method)] {
		return true
	}
	if ev.Protocol != "" && !isWellFormedProtocolToken(ev.Protocol) {
		return true
	}
	if thresholds.ProtocolAnomalyStatusCodes[ev.StatusCode] {
		return true
	}
	return false
}

// isWellFormedProtocolToken reports whether protocol looks like a
// standard "HTTP/x.y" token. Deliberately permissive about the version
// digits (future HTTP versions must not be flagged) -- only the literal
// "HTTP/" prefix is required.
func isWellFormedProtocolToken(protocol string) bool {
	return strings.HasPrefix(protocol, "HTTP/")
}
