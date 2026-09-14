package detection

import (
	"vanguard/core/internal/thresholds"
)

// evaluateAPIAbuse inspects snap and reports whether one source IP's
// request shape within the window matches API Abuse: BOTH high distinct-
// path diversity (>= APIAbuseMinDistinctPaths) AND a high failure ratio
// (>= APIAbuseMinFailureRatioTenths). Requiring both is what keeps a
// client making many legitimate, successful requests to varied endpoints
// from ever triggering this on path-count alone -- a load-testing tool or
// a legitimate SPA's initial page hitting 20+ distinct API routes that
// all return 200 must never match.
func evaluateAPIAbuse(snap APIAbuseSnapshot) (matched bool, failureRatioTenths int) {
	if snap.DistinctPaths < thresholds.APIAbuseMinDistinctPaths {
		return false, 0
	}
	if snap.TotalRequests == 0 {
		return false, 0
	}
	failureRatioTenths = (snap.FailureCount * 10) / snap.TotalRequests
	matched = failureRatioTenths >= thresholds.APIAbuseMinFailureRatioTenths
	return matched, failureRatioTenths
}

// isAPIAbuseFailureStatus reports whether status is one of the
// authentication/authorization/not-found codes counted as a "failure"
// for the API Abuse heuristic (401/403/404). Deliberately narrower than
// ProtocolAnomalyStatusCodes -- those are protocol-level malformations,
// this is application-level access denial/enumeration.
func isAPIAbuseFailureStatus(status int) bool {
	return status == 401 || status == 403 || status == 404
}
