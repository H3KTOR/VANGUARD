package detection

import (
	"testing"
	"time"

	"vanguard/core/internal/thresholds"
)

// ---------------------------------------------------------------------------
// ChainTracker unit tests (sliding-window / state-machine logic in
// isolation, no Engine involved).
// ---------------------------------------------------------------------------

func TestChainTracker_NoMatchBelowThresholds(t *testing.T) {
	ct := NewChainTracker(0)
	ip := "198.51.100.1"
	now := time.Now().UTC()

	// One port touch, one web probe, one auth failure -- all below the
	// AttackChainMin* thresholds.
	ct.RecordPortTouch(ip, 22, now, thresholds.AttackChainWindow)
	ct.RecordWebProbe(ip, now.Add(1*time.Second), thresholds.AttackChainWindow)
	ct.RecordAuthFailure(ip, now.Add(2*time.Second), thresholds.AttackChainWindow)

	_, _, _, matched := ct.Evaluate(ip, now.Add(2*time.Second), thresholds.AttackChainWindow)
	if matched {
		t.Fatalf("expected no chain match below per-stage thresholds")
	}
}

func TestChainTracker_MatchesFullSequenceInOrder(t *testing.T) {
	ct := NewChainTracker(0)
	ip := "198.51.100.2"
	base := time.Now().UTC()

	// Stage 1: Recon -- distinct port touches.
	for p := 0; p < thresholds.AttackChainMinDistinctPorts; p++ {
		ct.RecordPortTouch(ip, 1000+p, base, thresholds.AttackChainWindow)
	}
	// Stage 2: Web Probing -- 403/404s, strictly after recon.
	webTS := base.Add(30 * time.Second)
	for i := 0; i < thresholds.AttackChainMinWebProbes; i++ {
		ct.RecordWebProbe(ip, webTS.Add(time.Duration(i)*time.Second), thresholds.AttackChainWindow)
	}
	// Stage 3: Auth Probing -- SSH failures, strictly after web probing.
	authTS := webTS.Add(30 * time.Second)
	for i := 0; i < thresholds.AttackChainMinAuthFailures; i++ {
		ct.RecordAuthFailure(ip, authTS.Add(time.Duration(i)*time.Second), thresholds.AttackChainWindow)
	}

	reconCount, webCount, authCount, matched := ct.Evaluate(ip, authTS.Add(5*time.Second), thresholds.AttackChainWindow)
	if !matched {
		t.Fatalf("expected full recon->web->auth sequence to match")
	}
	if reconCount < thresholds.AttackChainMinDistinctPorts {
		t.Errorf("expected reconCount >= %d, got %d", thresholds.AttackChainMinDistinctPorts, reconCount)
	}
	if webCount < thresholds.AttackChainMinWebProbes {
		t.Errorf("expected webCount >= %d, got %d", thresholds.AttackChainMinWebProbes, webCount)
	}
	if authCount < thresholds.AttackChainMinAuthFailures {
		t.Errorf("expected authCount >= %d, got %d", thresholds.AttackChainMinAuthFailures, authCount)
	}
}

// TestChainTracker_SameSecondSubSecondPrecisionMismatchStillMatches is a
// regression test for a real bug found while running the Task 4 lab
// (lab/run-tests.sh) against a genuine nmap -> curl -> hydra attack chain:
// honeypot/port-touch events are stamped with time.Now() (nanosecond
// precision), while auth.log (syslog "Jan _2 15:04:05") and nginx combined
// access-log timestamps are parsed with only whole-second precision. A
// fast automated attack chain that completes all three stages within the
// same wall-clock second -- exactly what scripted tools produce -- used to
// spuriously fail the sequence check, because the live nanosecond-precision
// recon timestamp compared as "after" the truncated-to-:00 web/auth
// timestamps from the same second. Evaluate must truncate all three stage
// timestamps to second resolution before comparing, so same-second stages
// are correctly treated as tied (see the "Equal timestamps are allowed"
// comment in Evaluate).
func TestChainTracker_SameSecondSubSecondPrecisionMismatchStillMatches(t *testing.T) {
	ct := NewChainTracker(0)
	ip := "198.51.100.9"

	// A whole-second timestamp, as if parsed from a log line with no
	// fractional-second component (auth.log / nginx combined format).
	wholeSecond := time.Date(2026, 9, 7, 7, 53, 45, 0, time.UTC)

	// Recon: a live, nanosecond-precision timestamp landing in the SAME
	// second as the web/auth stages below -- e.g. a honeypot hit recorded
	// via time.Now().UTC() a few hundred milliseconds into that second.
	reconTS := wholeSecond.Add(246998447 * time.Nanosecond)
	for p := 0; p < thresholds.AttackChainMinDistinctPorts; p++ {
		ct.RecordPortTouch(ip, 3000+p, reconTS, thresholds.AttackChainWindow)
	}

	// Web probing: whole-second timestamps parsed from a log, same second
	// as recon (and even the same instant or slightly "before" it at
	// nanosecond resolution, despite happening after in real time).
	for i := 0; i < thresholds.AttackChainMinWebProbes; i++ {
		ct.RecordWebProbe(ip, wholeSecond, thresholds.AttackChainWindow)
	}

	// Auth probing: also whole-second, a few seconds later (still parsed
	// from a log with no sub-second precision).
	authTS := wholeSecond.Add(8 * time.Second)
	for i := 0; i < thresholds.AttackChainMinAuthFailures; i++ {
		ct.RecordAuthFailure(ip, authTS.Add(time.Duration(i)*time.Second), thresholds.AttackChainWindow)
	}

	_, _, _, matched := ct.Evaluate(ip, authTS.Add(5*time.Second), thresholds.AttackChainWindow)
	if !matched {
		t.Fatalf("expected same-second recon/web timestamps (differing only in sub-second precision) to still match as a correctly-ordered chain")
	}
}

func TestChainTracker_OutOfOrderSequenceDoesNotMatch(t *testing.T) {
	ct := NewChainTracker(0)
	ip := "198.51.100.3"
	base := time.Now().UTC()

	// Auth probing happens FIRST (wrong order: should be recon -> web -> auth).
	for i := 0; i < thresholds.AttackChainMinAuthFailures; i++ {
		ct.RecordAuthFailure(ip, base.Add(time.Duration(i)*time.Second), thresholds.AttackChainWindow)
	}
	// Then web probing.
	webTS := base.Add(30 * time.Second)
	for i := 0; i < thresholds.AttackChainMinWebProbes; i++ {
		ct.RecordWebProbe(ip, webTS.Add(time.Duration(i)*time.Second), thresholds.AttackChainWindow)
	}
	// Then recon LAST.
	reconTS := webTS.Add(30 * time.Second)
	for p := 0; p < thresholds.AttackChainMinDistinctPorts; p++ {
		ct.RecordPortTouch(ip, 2000+p, reconTS, thresholds.AttackChainWindow)
	}

	_, _, _, matched := ct.Evaluate(ip, reconTS.Add(5*time.Second), thresholds.AttackChainWindow)
	if matched {
		t.Fatalf("expected out-of-order stages (auth before recon) to NOT match the chain")
	}
}

func TestChainTracker_SequenceOutsideWindowDoesNotMatch(t *testing.T) {
	ct := NewChainTracker(0)
	ip := "198.51.100.4"
	base := time.Now().UTC()

	for p := 0; p < thresholds.AttackChainMinDistinctPorts; p++ {
		ct.RecordPortTouch(ip, 3000+p, base, thresholds.AttackChainWindow)
	}
	// Web probing happens, but well *outside* the correlation window
	// relative to the eventual evaluation time below.
	webTS := base.Add(2 * time.Minute)
	for i := 0; i < thresholds.AttackChainMinWebProbes; i++ {
		ct.RecordWebProbe(ip, webTS.Add(time.Duration(i)*time.Second), thresholds.AttackChainWindow)
	}
	// Auth probing happens far beyond the window from the initial recon --
	// by the time this fires, the recon port touches should have been
	// pruned out of the window entirely.
	authTS := base.Add(thresholds.AttackChainWindow + 1*time.Minute)
	for i := 0; i < thresholds.AttackChainMinAuthFailures; i++ {
		ct.RecordAuthFailure(ip, authTS.Add(time.Duration(i)*time.Second), thresholds.AttackChainWindow)
	}

	_, _, _, matched := ct.Evaluate(ip, authTS.Add(5*time.Second), thresholds.AttackChainWindow)
	if matched {
		t.Fatalf("expected a sequence spanning outside the sliding window to NOT match")
	}
}

func TestChainTracker_PartialSequenceMissingStageDoesNotMatch(t *testing.T) {
	ct := NewChainTracker(0)
	ip := "198.51.100.5"
	base := time.Now().UTC()

	// Only recon + web probing -- no auth-probing stage at all.
	for p := 0; p < thresholds.AttackChainMinDistinctPorts; p++ {
		ct.RecordPortTouch(ip, 4000+p, base, thresholds.AttackChainWindow)
	}
	webTS := base.Add(10 * time.Second)
	for i := 0; i < thresholds.AttackChainMinWebProbes; i++ {
		ct.RecordWebProbe(ip, webTS.Add(time.Duration(i)*time.Second), thresholds.AttackChainWindow)
	}

	_, _, authCount, matched := ct.Evaluate(ip, webTS.Add(5*time.Second), thresholds.AttackChainWindow)
	if matched {
		t.Fatalf("expected a partial (2-of-3-stage) sequence to NOT match")
	}
	if authCount != 0 {
		t.Errorf("expected authCount 0 for a sequence with no auth-probing stage, got %d", authCount)
	}
}

func TestChainTracker_ReapRemovesIdleEntries(t *testing.T) {
	ct := NewChainTracker(1 * time.Minute)
	ip := "198.51.100.6"
	now := time.Now().UTC()
	ct.RecordPortTouch(ip, 22, now, thresholds.AttackChainWindow)

	if got := ct.TrackedIPCount(); got != 1 {
		t.Fatalf("expected 1 tracked IP, got %d", got)
	}
	if n := ct.Reap(now.Add(30 * time.Second)); n != 0 {
		t.Fatalf("expected 0 reaped (not yet idle), got %d", n)
	}
	if n := ct.Reap(now.Add(2 * time.Minute)); n != 1 {
		t.Fatalf("expected 1 reaped after exceeding maxIdle, got %d", n)
	}
	if got := ct.TrackedIPCount(); got != 0 {
		t.Fatalf("expected 0 tracked IPs after reap, got %d", got)
	}
}

func TestChainTracker_DistinctIPsDoNotCrossContaminate(t *testing.T) {
	ct := NewChainTracker(0)
	ipA := "198.51.100.7"
	ipB := "198.51.100.8"
	now := time.Now().UTC()

	for p := 0; p < thresholds.AttackChainMinDistinctPorts; p++ {
		ct.RecordPortTouch(ipA, 5000+p, now, thresholds.AttackChainWindow)
	}
	// ipB only gets web probes + auth failures, never recon -- must not
	// inherit ipA's recon signal.
	webTS := now.Add(10 * time.Second)
	for i := 0; i < thresholds.AttackChainMinWebProbes; i++ {
		ct.RecordWebProbe(ipB, webTS.Add(time.Duration(i)*time.Second), thresholds.AttackChainWindow)
	}
	authTS := webTS.Add(10 * time.Second)
	for i := 0; i < thresholds.AttackChainMinAuthFailures; i++ {
		ct.RecordAuthFailure(ipB, authTS.Add(time.Duration(i)*time.Second), thresholds.AttackChainWindow)
	}

	_, _, _, matchedB := ct.Evaluate(ipB, authTS.Add(5*time.Second), thresholds.AttackChainWindow)
	if matchedB {
		t.Fatalf("expected ipB (no recon stage of its own) to NOT match the chain")
	}
}

// ---------------------------------------------------------------------------
// ScannerTracker unit tests
// ---------------------------------------------------------------------------

func TestScannerTracker_Below4xxThresholdNoSignal(t *testing.T) {
	st := NewScannerTracker(0)
	ip := "198.51.100.20"
	now := time.Now().UTC()

	var total, suspicious int
	for i := 0; i < thresholds.WebScannerMin4xx-1; i++ {
		total, suspicious = st.Record4xx(ip, now.Add(time.Duration(i)*time.Millisecond), thresholds.WebScannerWindow, true)
	}
	if total >= thresholds.WebScannerMin4xx {
		t.Fatalf("expected total below threshold, got %d", total)
	}
	if suspicious != total {
		t.Errorf("expected every recorded hit to be marked suspicious, got suspicious=%d total=%d", suspicious, total)
	}
}

func TestScannerTracker_CombinesFrequencyAndUA(t *testing.T) {
	st := NewScannerTracker(0)
	ip := "198.51.100.21"
	now := time.Now().UTC()

	var total, suspicious int
	for i := 0; i < thresholds.WebScannerMin4xx+2; i++ {
		total, suspicious = st.Record4xx(ip, now.Add(time.Duration(i)*time.Millisecond), thresholds.WebScannerWindow, i%2 == 0)
	}
	if total < thresholds.WebScannerMin4xx {
		t.Fatalf("expected total >= threshold, got %d", total)
	}
	if suspicious == 0 {
		t.Errorf("expected a nonzero suspicious count, got 0")
	}
}

func TestScannerTracker_WindowPruning(t *testing.T) {
	st := NewScannerTracker(0)
	ip := "198.51.100.22"
	now := time.Now().UTC()

	// First burst, well outside the window by the time of the second burst.
	for i := 0; i < thresholds.WebScannerMin4xx; i++ {
		st.Record4xx(ip, now, thresholds.WebScannerWindow, true)
	}
	total, _ := st.Record4xx(ip, now.Add(thresholds.WebScannerWindow+time.Second), thresholds.WebScannerWindow, true)
	if total != 1 {
		t.Fatalf("expected old hits to be pruned out of the window, got total=%d", total)
	}
}

func TestIsMissingOrSuspiciousUA(t *testing.T) {
	cases := []struct {
		ua       string
		expected bool
	}{
		{"", true},
		{"-", true},
		{"   ", true},
		{"Mozilla/5.0 (Windows NT 10.0; Win64; x64)", false},
		{"Nikto/2.5.0", true},
		{"dirbuster", true},
		{"WPScan v3.8", true},
		{"sqlmap/1.7", true},
	}
	for _, c := range cases {
		if got := isMissingOrSuspiciousUA(c.ua); got != c.expected {
			t.Errorf("isMissingOrSuspiciousUA(%q) = %v, want %v", c.ua, got, c.expected)
		}
	}
}
