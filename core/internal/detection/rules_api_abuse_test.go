package detection

import (
	"testing"

	"vanguard/core/internal/thresholds"
)

func TestEvaluateAPIAbuse_BelowDistinctPathThreshold_NoMatch(t *testing.T) {
	snap := APIAbuseSnapshot{
		TotalRequests: thresholds.APIAbuseMinDistinctPaths - 1,
		DistinctPaths: thresholds.APIAbuseMinDistinctPaths - 1,
		FailureCount:  thresholds.APIAbuseMinDistinctPaths - 1, // 100% failure, but too few distinct paths
	}
	matched, _ := evaluateAPIAbuse(snap)
	if matched {
		t.Fatalf("expected no match below the distinct-path threshold")
	}
}

func TestEvaluateAPIAbuse_HighDiversityLowFailureRatio_NoMatch(t *testing.T) {
	// A legitimate client (SPA loading many valid endpoints, mostly
	// successful) must never match on path-count alone.
	snap := APIAbuseSnapshot{
		TotalRequests: thresholds.APIAbuseMinDistinctPaths + 10,
		DistinctPaths: thresholds.APIAbuseMinDistinctPaths + 10,
		FailureCount:  0,
	}
	matched, ratio := evaluateAPIAbuse(snap)
	if matched {
		t.Fatalf("expected no match: 0%% failure ratio despite high path diversity, got ratio=%d", ratio)
	}
}

func TestEvaluateAPIAbuse_HighDiversityHighFailureRatio_Matches(t *testing.T) {
	total := thresholds.APIAbuseMinDistinctPaths + 5
	failures := total // 100% failure
	snap := APIAbuseSnapshot{
		TotalRequests: total,
		DistinctPaths: total,
		FailureCount:  failures,
	}
	matched, ratio := evaluateAPIAbuse(snap)
	if !matched {
		t.Fatalf("expected match: high diversity + high failure ratio, got matched=false ratio=%d", ratio)
	}
}

func TestEvaluateAPIAbuse_ZeroRequests_NoMatchNoDivideByZero(t *testing.T) {
	snap := APIAbuseSnapshot{}
	matched, ratio := evaluateAPIAbuse(snap)
	if matched || ratio != 0 {
		t.Fatalf("expected zero-value snapshot to never match, got matched=%v ratio=%d", matched, ratio)
	}
}

func TestEvaluateAPIAbuse_BoundaryAtExactThresholds_Matches(t *testing.T) {
	// Path count exactly at threshold, failure ratio exactly at threshold.
	total := thresholds.APIAbuseMinDistinctPaths
	failures := (thresholds.APIAbuseMinFailureRatioTenths * total) / 10
	// Adjust total so the integer division lands exactly on the ratio.
	for (failures*10)/total != thresholds.APIAbuseMinFailureRatioTenths {
		total++
		failures = (thresholds.APIAbuseMinFailureRatioTenths * total) / 10
	}
	snap := APIAbuseSnapshot{TotalRequests: total, DistinctPaths: thresholds.APIAbuseMinDistinctPaths, FailureCount: failures}
	matched, ratio := evaluateAPIAbuse(snap)
	if ratio != thresholds.APIAbuseMinFailureRatioTenths {
		t.Fatalf("expected computed ratio=%d, got %d", thresholds.APIAbuseMinFailureRatioTenths, ratio)
	}
	if !matched {
		t.Fatalf("expected an exact-boundary match (inclusive >=), got matched=false")
	}
}

func TestIsAPIAbuseFailureStatus(t *testing.T) {
	cases := map[int]bool{
		200: false, 201: false, 301: false, 302: false,
		400: false, // protocol-level, not this heuristic's concern
		401: true, 403: true, 404: true,
		500: false, 502: false,
	}
	for status, want := range cases {
		if got := isAPIAbuseFailureStatus(status); got != want {
			t.Errorf("isAPIAbuseFailureStatus(%d) = %v, want %v", status, got, want)
		}
	}
}
