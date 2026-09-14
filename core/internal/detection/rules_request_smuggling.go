package detection

import "vanguard/core/internal/thresholds"

// ---------------------------------------------------------------------------
// Request-Smuggling Indicators (Phase 3, feature 12).
//
// VANGUARD's log-line visibility cannot see raw Content-Length/
// Transfer-Encoding header values at all -- standard Nginx/Apache
// access-log formats never log request headers. This can only watch the
// downstream SYMPTOM: an abnormal burst of 400/408/502/503 responses from
// one source in a short window, which is consistent with, but nowhere
// near proof of, a smuggling attempt against a front-end/back-end pair.
// ---------------------------------------------------------------------------

// isRequestSmugglingSymptomStatus reports whether status is one of the
// symptom-only status codes tracked by this indicator.
func isRequestSmugglingSymptomStatus(status int) bool {
	return thresholds.RequestSmugglingSymptomStatusCodes[status]
}
