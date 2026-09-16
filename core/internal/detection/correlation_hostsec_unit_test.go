package detection

import (
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// Direct unit tests for HostCorrelator's process-finding tracking
// (RecordProcessFinding/RecentFindingCount), added alongside Feature 3's
// Web Shell Indicator correlation. The pre-existing RecordFileFinding/
// RecentFileFindingCount pair (Feature 7) is already exercised via
// correlation_hostsec_test.go's engine-level tests.
// ---------------------------------------------------------------------------

func TestHostCorrelator_RecordProcessFinding_WithinWindow_Counted(t *testing.T) {
	c := NewHostCorrelator()
	now := time.Now().UTC()
	c.RecordProcessFinding(now, 10*time.Minute)

	if got := c.RecentFindingCount(now.Add(1*time.Minute), 10*time.Minute); got != 1 {
		t.Fatalf("expected 1 recent finding within window, got %d", got)
	}
}

func TestHostCorrelator_RecordProcessFinding_OutsideWindow_NotCounted(t *testing.T) {
	c := NewHostCorrelator()
	now := time.Now().UTC()
	c.RecordProcessFinding(now, 10*time.Minute)

	if got := c.RecentFindingCount(now.Add(11*time.Minute), 10*time.Minute); got != 0 {
		t.Fatalf("expected 0 findings once outside window, got %d", got)
	}
}

func TestHostCorrelator_RecentFindingCount_CombinesFileAndProcess(t *testing.T) {
	c := NewHostCorrelator()
	now := time.Now().UTC()
	c.RecordFileFinding(now, 10*time.Minute)
	c.RecordProcessFinding(now, 10*time.Minute)

	if got := c.RecentFindingCount(now, 10*time.Minute); got != 2 {
		t.Fatalf("expected RecentFindingCount to combine both file AND process findings, got %d", got)
	}
}

func TestHostCorrelator_NoFindings_ZeroCount(t *testing.T) {
	c := NewHostCorrelator()
	if got := c.RecentFindingCount(time.Now().UTC(), 10*time.Minute); got != 0 {
		t.Fatalf("expected 0 findings on a fresh correlator, got %d", got)
	}
}
