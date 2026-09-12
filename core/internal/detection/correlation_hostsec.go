package detection

import (
	"sync"
	"time"
)

// ---------------------------------------------------------------------------
// Feature 7: Process -> File -> Network Correlation (VANGUARD Mega
// Expansion, Phase 2).
//
// Concept (per the mega-prompt): individual host-security alerts become
// much stronger evidence of active compromise when connected -- a
// Suspicious Process finding that also touches a recently-modified
// sensitive file, and/or reaches out to a network destination with a
// known-malicious reputation, is far more actionable than any one of
// those signals alone.
//
// HostCorrelator holds the one small piece of *shared state* this needs:
// a sliding window of "sensitive file activity" timestamps, fed by
// Feature 1 (FIM) and Feature 8 (System Binary Integrity) findings. It
// is deliberately NOT keyed per source-IP like ChainTracker/
// ScannerTracker -- every host-security finding shares the exact same
// SourceIP (database.HostLocalIP; VANGUARD only ever monitors the one
// host it runs on), so a single global window is the correct shape,
// not a map keyed by a value that never varies.
//
// The actual correlation decision (does THIS Suspicious Process finding
// have enough corroborating evidence to raise HIGH_CONFIDENCE_COMPROMISE)
// is made in engine_hostsec.go's ReportHostFinding/correlateHostFinding,
// which is the one existing choke point that already observes every
// hostsec.Finding as it arrives. Keeping the decision there -- rather
// than introducing a second reporting path -- means this file adds pure
// correlation glue over the existing FIM/BinaryIntegrity/Process
// detectors, not a new/duplicate detection engine, per the mega-prompt's
// explicit "never create duplicate detection engines" rule.
// ---------------------------------------------------------------------------

// HostCorrelator is safe for concurrent use.
type HostCorrelator struct {
	mu    sync.Mutex
	files []time.Time // sensitive-file-activity timestamps, sorted oldest-first
}

// NewHostCorrelator constructs an empty HostCorrelator.
func NewHostCorrelator() *HostCorrelator {
	return &HostCorrelator{}
}

// RecordFileFinding registers a sensitive-file-activity signal (a FIM
// change or System Binary Integrity violation) at ts, pruning entries
// older than window in the same pass.
func (c *HostCorrelator) RecordFileFinding(ts time.Time, window time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.files = append(pruneOlderThan(c.files, ts.Add(-window)), ts)
}

// RecentFileFindingCount reports how many sensitive-file-activity
// signals are still within window of now, pruning stale entries first.
func (c *HostCorrelator) RecentFileFindingCount(now time.Time, window time.Duration) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.files = pruneOlderThan(c.files, now.Add(-window))
	return len(c.files)
}
