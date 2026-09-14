package detection

import (
	"vanguard/core/internal/thresholds"
)

// ---------------------------------------------------------------------------
// Pure evaluation functions for Password Spraying (feature 5) and
// Credential Stuffing (feature 6). Kept separate from the AuthAbuseTracker
// (state_auth_abuse.go) and the Engine wiring (engine.go) so the actual
// "is this shape of evidence suspicious" decision is a deterministic,
// side-effect-free function of an AuthAbuseSnapshot -- fully unit-testable
// without touching the Engine, a database, or any locking.
// ---------------------------------------------------------------------------

// evaluatePasswordSpraying inspects snap and reports how many DISTINCT,
// KNOWN (non-empty) usernames have failed at least once, but no more than
// thresholds.PasswordSprayingMaxAttemptsPerUser times, within the current
// window -- and whether that count meets
// thresholds.PasswordSprayingMinDistinctUsernames.
//
// Usernames that exceed PasswordSprayingMaxAttemptsPerUser are
// deliberately excluded from the qualifying count: a single account with
// many failures already looks like ordinary brute force against that one
// account (covered by ruleSSHBruteForce), not spraying. This is what
// keeps the two detectors from double-counting the same evidence into two
// incidents for the classic "1 heavily brute-forced account + a handful
// of lightly-touched decoys" shape.
//
// An empty username (VANGUARD never invents one when the log line lacks
// it) never counts toward the distinct-username total -- an unknown
// bucket of "some number of unattributed failures" is not evidence of
// multiple distinct accounts being targeted.
func evaluatePasswordSpraying(snap AuthAbuseSnapshot) (qualifyingUsernames int, matched bool) {
	for user, count := range snap.PerUserFailureCounts {
		if user == "" {
			continue
		}
		if count > thresholds.PasswordSprayingMaxAttemptsPerUser {
			continue
		}
		qualifyingUsernames++
	}
	return qualifyingUsernames, qualifyingUsernames >= thresholds.PasswordSprayingMinDistinctUsernames
}

// evaluateCredentialStuffing inspects snap and reports whether the
// OBSERVABLE authentication shape from one source IP matches
// credential-stuffing: many distinct accounts, a high overall attempt
// volume, AND a high failure ratio -- all three conditions are required,
// so a source IP that mostly succeeds (a legitimate high-volume client
// retrying a rate limit, for instance) never qualifies purely on
// distinct-username or volume counts alone.
func evaluateCredentialStuffing(snap AuthAbuseSnapshot) (matched bool, distinctUsernames, totalAttempts, failureRatioTenths int) {
	distinctUsernames = 0
	for user := range snap.PerUserFailureCounts {
		if user != "" {
			distinctUsernames++
		}
	}
	totalAttempts = snap.TotalFailures + snap.TotalSuccesses
	if totalAttempts == 0 {
		return false, distinctUsernames, 0, 0
	}
	failureRatioTenths = (snap.TotalFailures * 10) / totalAttempts

	matched = distinctUsernames >= thresholds.CredentialStuffingMinDistinctUsernames &&
		totalAttempts >= thresholds.CredentialStuffingMinTotalAttempts &&
		failureRatioTenths >= thresholds.CredentialStuffingMinFailureRatioTenths
	return matched, distinctUsernames, totalAttempts, failureRatioTenths
}
