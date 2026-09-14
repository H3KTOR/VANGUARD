package detection

import (
	"testing"

	"vanguard/core/internal/thresholds"
)

// ---------------------------------------------------------------------------
// evaluatePasswordSpraying: pure function unit tests
// ---------------------------------------------------------------------------

func TestEvaluatePasswordSpraying_BelowDistinctUsernameThreshold_NoMatch(t *testing.T) {
	snap := AuthAbuseSnapshot{
		PerUserFailureCounts: map[string]int{
			"alice": 2, "bob": 2, "carol": 2,
		},
	}
	if thresholds.PasswordSprayingMinDistinctUsernames <= 3 {
		t.Fatalf("test assumption invalid: threshold %d <= 3", thresholds.PasswordSprayingMinDistinctUsernames)
	}
	qualifying, matched := evaluatePasswordSpraying(snap)
	if matched {
		t.Fatalf("expected no match with only 3 distinct usernames (threshold %d), got qualifying=%d matched=true",
			thresholds.PasswordSprayingMinDistinctUsernames, qualifying)
	}
}

func TestEvaluatePasswordSpraying_AtThreshold_Matches(t *testing.T) {
	perUser := make(map[string]int)
	for i := 0; i < thresholds.PasswordSprayingMinDistinctUsernames; i++ {
		perUser[itoa(i)+"-user"] = 1
	}
	snap := AuthAbuseSnapshot{PerUserFailureCounts: perUser}
	qualifying, matched := evaluatePasswordSpraying(snap)
	if !matched {
		t.Fatalf("expected match at exactly the threshold (%d distinct usernames), got qualifying=%d",
			thresholds.PasswordSprayingMinDistinctUsernames, qualifying)
	}
	if qualifying != thresholds.PasswordSprayingMinDistinctUsernames {
		t.Errorf("expected qualifying=%d, got %d", thresholds.PasswordSprayingMinDistinctUsernames, qualifying)
	}
}

func TestEvaluatePasswordSpraying_OneAccountOverAttemptCap_ExcludedNotCounted(t *testing.T) {
	// A single heavily-brute-forced account should look like ordinary
	// brute force (handled by ruleSSHBruteForce), not spraying -- so its
	// failures must not count toward the qualifying total even if it
	// pushes the raw distinct-username count over the threshold.
	perUser := make(map[string]int)
	for i := 0; i < thresholds.PasswordSprayingMinDistinctUsernames-1; i++ {
		perUser[itoa(i)+"-user"] = 1
	}
	perUser["heavily-attacked"] = thresholds.PasswordSprayingMaxAttemptsPerUser + 50

	snap := AuthAbuseSnapshot{PerUserFailureCounts: perUser}
	qualifying, matched := evaluatePasswordSpraying(snap)
	if matched {
		t.Fatalf("expected no match: only %d qualifying usernames (the over-cap account must be excluded), got qualifying=%d matched=true",
			thresholds.PasswordSprayingMinDistinctUsernames-1, qualifying)
	}
	if qualifying != thresholds.PasswordSprayingMinDistinctUsernames-1 {
		t.Errorf("expected qualifying=%d (over-cap account excluded), got %d", thresholds.PasswordSprayingMinDistinctUsernames-1, qualifying)
	}
}

func TestEvaluatePasswordSpraying_EmptyUsernameNeverCounted(t *testing.T) {
	perUser := make(map[string]int)
	for i := 0; i < thresholds.PasswordSprayingMinDistinctUsernames-1; i++ {
		perUser[itoa(i)+"-user"] = 1
	}
	perUser[""] = 10 // unattributed failures -- must never count as a "distinct username"

	snap := AuthAbuseSnapshot{PerUserFailureCounts: perUser}
	qualifying, matched := evaluatePasswordSpraying(snap)
	if matched {
		t.Fatalf("expected no match: empty username must never count toward distinct-username total, got qualifying=%d matched=true", qualifying)
	}
}

func TestEvaluatePasswordSpraying_MissingFieldData_EmptySnapshotNoMatch(t *testing.T) {
	// Missing-field-data test: a snapshot with a nil map must not panic
	// and must never match.
	snap := AuthAbuseSnapshot{}
	qualifying, matched := evaluatePasswordSpraying(snap)
	if matched || qualifying != 0 {
		t.Fatalf("expected zero-value snapshot to never match, got qualifying=%d matched=%v", qualifying, matched)
	}
}

// ---------------------------------------------------------------------------
// evaluateCredentialStuffing: pure function unit tests
// ---------------------------------------------------------------------------

func TestEvaluateCredentialStuffing_AllConditionsMet_Matches(t *testing.T) {
	perUser := make(map[string]int)
	total := 0
	for i := 0; i < thresholds.CredentialStuffingMinDistinctUsernames; i++ {
		perUser[itoa(i)+"-user"] = 2
		total += 2
	}
	snap := AuthAbuseSnapshot{
		PerUserFailureCounts: perUser,
		TotalFailures:        total, // ratio = 10/10 = 1.0, well above the 0.7 threshold
		TotalSuccesses:       0,
	}
	if total < thresholds.CredentialStuffingMinTotalAttempts {
		t.Fatalf("test assumption invalid: total=%d below MinTotalAttempts=%d", total, thresholds.CredentialStuffingMinTotalAttempts)
	}
	matched, distinct, attempts, ratio := evaluateCredentialStuffing(snap)
	if !matched {
		t.Fatalf("expected credential-stuffing match, got matched=false (distinct=%d attempts=%d ratio=%d/10)", distinct, attempts, ratio)
	}
}

func TestEvaluateCredentialStuffing_TooFewDistinctUsernames_NoMatch(t *testing.T) {
	perUser := map[string]int{"a": 20, "b": 20} // huge volume, high failure ratio, but only 2 accounts
	snap := AuthAbuseSnapshot{PerUserFailureCounts: perUser, TotalFailures: 40}
	matched, _, _, _ := evaluateCredentialStuffing(snap)
	if matched {
		t.Fatalf("expected no match: only 2 distinct usernames, below MinDistinctUsernames=%d", thresholds.CredentialStuffingMinDistinctUsernames)
	}
}

func TestEvaluateCredentialStuffing_TooFewTotalAttempts_NoMatch(t *testing.T) {
	perUser := make(map[string]int)
	for i := 0; i < thresholds.CredentialStuffingMinDistinctUsernames+5; i++ {
		perUser[itoa(i)+"-user"] = 1 // 1 attempt each -- many accounts, but low overall volume
	}
	total := thresholds.CredentialStuffingMinDistinctUsernames + 5
	if total >= thresholds.CredentialStuffingMinTotalAttempts {
		t.Skip("test assumption invalid for current threshold configuration")
	}
	snap := AuthAbuseSnapshot{PerUserFailureCounts: perUser, TotalFailures: total}
	matched, _, _, _ := evaluateCredentialStuffing(snap)
	if matched {
		t.Fatalf("expected no match: total attempts %d below MinTotalAttempts=%d", total, thresholds.CredentialStuffingMinTotalAttempts)
	}
}

func TestEvaluateCredentialStuffing_LowFailureRatio_NoMatch(t *testing.T) {
	// Many accounts, high volume, but mostly SUCCESSFUL -- a legitimate
	// high-volume client retrying past a rate limit, not stuffing.
	perUser := make(map[string]int)
	for i := 0; i < thresholds.CredentialStuffingMinDistinctUsernames+5; i++ {
		perUser[itoa(i)+"-user"] = 1
	}
	failures := thresholds.CredentialStuffingMinDistinctUsernames + 5
	successes := failures * 10 // ratio well below the 0.7 threshold
	snap := AuthAbuseSnapshot{
		PerUserFailureCounts: perUser,
		TotalFailures:        failures,
		TotalSuccesses:       successes,
	}
	matched, _, _, ratio := evaluateCredentialStuffing(snap)
	if matched {
		t.Fatalf("expected no match: failure ratio %d/10 below MinFailureRatioTenths=%d", ratio, thresholds.CredentialStuffingMinFailureRatioTenths)
	}
}

func TestEvaluateCredentialStuffing_ZeroAttempts_NoMatchNoDivideByZero(t *testing.T) {
	// Malformed/missing-field-data test: a snapshot with zero total
	// attempts must not panic (divide by zero) and must never match.
	snap := AuthAbuseSnapshot{}
	matched, _, attempts, ratio := evaluateCredentialStuffing(snap)
	if matched || attempts != 0 || ratio != 0 {
		t.Fatalf("expected zero-value snapshot to never match, got matched=%v attempts=%d ratio=%d", matched, attempts, ratio)
	}
}

func TestEvaluateCredentialStuffing_BoundaryRatio_ExactlyAtThresholdMatches(t *testing.T) {
	// Construct a case where the integer-tenths ratio lands EXACTLY on
	// thresholds.CredentialStuffingMinFailureRatioTenths, to confirm the
	// boundary is inclusive (>=), not exclusive. Built generically from
	// the actual threshold constants rather than hard-coded numbers, so
	// this stays correct if the thresholds are ever retuned.
	perUser := make(map[string]int)
	for i := 0; i < thresholds.CredentialStuffingMinDistinctUsernames; i++ {
		perUser[itoa(i)+"-user"] = 1
	}
	// total = 10 * k, failures = ratioTenths * k, for the smallest k that
	// makes total >= MinTotalAttempts. This lands the integer-division
	// ratio (failures*10)/total exactly on MinFailureRatioTenths by
	// construction.
	k := 1
	for 10*k < thresholds.CredentialStuffingMinTotalAttempts {
		k++
	}
	total := 10 * k
	failures := thresholds.CredentialStuffingMinFailureRatioTenths * k
	successes := total - failures

	snap := AuthAbuseSnapshot{PerUserFailureCounts: perUser, TotalFailures: failures, TotalSuccesses: successes}
	matched, _, gotTotal, ratio := evaluateCredentialStuffing(snap)
	if ratio != thresholds.CredentialStuffingMinFailureRatioTenths {
		t.Fatalf("expected computed ratio=%d, got %d (total=%d)", thresholds.CredentialStuffingMinFailureRatioTenths, ratio, gotTotal)
	}
	if !matched {
		t.Fatalf("expected an exact-boundary ratio (%d/10) to match (inclusive >=), got matched=false", ratio)
	}
}
