package detection

import (
	"testing"
	"time"

	"vanguard/core/internal/thresholds"
)

// ---------------------------------------------------------------------------
// Pure ChainTracker unit tests for the Phase 3 Web Attack Chain extension
// (RecordExploitSignal / EvaluateWebAttackChain). These exercise the state
// machine directly -- no Engine, no DB, no locking beyond ChainTracker's
// own -- mirroring the existing pure-function/state-machine test style used
// throughout this phase (e.g. rules_ssrf_test.go, rules_oast_test.go).
// ---------------------------------------------------------------------------

// driveWebAttackChainStages feeds exactly the minimum counts for all three
// stages, in correct order, 10s apart per stage, starting at base.
func driveWebAttackChainStages(c *ChainTracker, ip string, base time.Time, window time.Duration) (webFirst, authFirst, exploitFirst time.Time) {
	webFirst = base
	for i := 0; i < thresholds.WebAttackChainMinWebProbes; i++ {
		c.RecordWebProbe(ip, webFirst.Add(time.Duration(i)*time.Millisecond), window)
	}

	authFirst = base.Add(10 * time.Second)
	for i := 0; i < thresholds.WebAttackChainMinAuthFailures; i++ {
		c.RecordAuthFailure(ip, authFirst.Add(time.Duration(i)*time.Millisecond), window)
	}

	exploitFirst = base.Add(20 * time.Second)
	for i := 0; i < thresholds.WebAttackChainMinExploitSignals; i++ {
		c.RecordExploitSignal(ip, exploitFirst.Add(time.Duration(i)*time.Millisecond), window)
	}
	return webFirst, authFirst, exploitFirst
}

func TestEvaluateWebAttackChain_FullOrderedSequence_Matches(t *testing.T) {
	c := NewChainTracker(0)
	ip := "198.51.100.10"
	base := time.Now().UTC()

	_, _, exploitFirst := driveWebAttackChainStages(c, ip, base, thresholds.WebAttackChainWindow)

	webCount, authCount, exploitCount, matched := c.EvaluateWebAttackChain(ip, exploitFirst, thresholds.WebAttackChainWindow)
	if !matched {
		t.Fatalf("expected the full ordered web/auth/exploit sequence to match")
	}
	if webCount != thresholds.WebAttackChainMinWebProbes {
		t.Errorf("webCount = %d, want %d", webCount, thresholds.WebAttackChainMinWebProbes)
	}
	if authCount != thresholds.WebAttackChainMinAuthFailures {
		t.Errorf("authCount = %d, want %d", authCount, thresholds.WebAttackChainMinAuthFailures)
	}
	if exploitCount != thresholds.WebAttackChainMinExploitSignals {
		t.Errorf("exploitCount = %d, want %d", exploitCount, thresholds.WebAttackChainMinExploitSignals)
	}
}

func TestEvaluateWebAttackChain_MissingWebProbeStage_NoMatch(t *testing.T) {
	c := NewChainTracker(0)
	ip := "198.51.100.11"
	base := time.Now().UTC()

	authFirst := base
	for i := 0; i < thresholds.WebAttackChainMinAuthFailures; i++ {
		c.RecordAuthFailure(ip, authFirst.Add(time.Duration(i)*time.Millisecond), thresholds.WebAttackChainWindow)
	}
	exploitFirst := base.Add(10 * time.Second)
	for i := 0; i < thresholds.WebAttackChainMinExploitSignals; i++ {
		c.RecordExploitSignal(ip, exploitFirst.Add(time.Duration(i)*time.Millisecond), thresholds.WebAttackChainWindow)
	}

	_, _, _, matched := c.EvaluateWebAttackChain(ip, exploitFirst, thresholds.WebAttackChainWindow)
	if matched {
		t.Fatalf("did not expect a match with the web-probing stage entirely missing")
	}
}

func TestEvaluateWebAttackChain_MissingAuthFailureStage_NoMatch(t *testing.T) {
	c := NewChainTracker(0)
	ip := "198.51.100.12"
	base := time.Now().UTC()

	webFirst := base
	for i := 0; i < thresholds.WebAttackChainMinWebProbes; i++ {
		c.RecordWebProbe(ip, webFirst.Add(time.Duration(i)*time.Millisecond), thresholds.WebAttackChainWindow)
	}
	exploitFirst := base.Add(10 * time.Second)
	for i := 0; i < thresholds.WebAttackChainMinExploitSignals; i++ {
		c.RecordExploitSignal(ip, exploitFirst.Add(time.Duration(i)*time.Millisecond), thresholds.WebAttackChainWindow)
	}

	_, _, _, matched := c.EvaluateWebAttackChain(ip, exploitFirst, thresholds.WebAttackChainWindow)
	if matched {
		t.Fatalf("did not expect a match with the auth-probing stage entirely missing")
	}
}

func TestEvaluateWebAttackChain_MissingExploitStage_NoMatch(t *testing.T) {
	c := NewChainTracker(0)
	ip := "198.51.100.13"
	base := time.Now().UTC()

	webFirst := base
	for i := 0; i < thresholds.WebAttackChainMinWebProbes; i++ {
		c.RecordWebProbe(ip, webFirst.Add(time.Duration(i)*time.Millisecond), thresholds.WebAttackChainWindow)
	}
	authFirst := base.Add(10 * time.Second)
	for i := 0; i < thresholds.WebAttackChainMinAuthFailures; i++ {
		c.RecordAuthFailure(ip, authFirst.Add(time.Duration(i)*time.Millisecond), thresholds.WebAttackChainWindow)
	}

	_, _, _, matched := c.EvaluateWebAttackChain(ip, authFirst, thresholds.WebAttackChainWindow)
	if matched {
		t.Fatalf("did not expect a match with the exploitation stage entirely missing")
	}
}

func TestEvaluateWebAttackChain_ThresholdBoundary_OneBelowEachMinimum_NoMatch(t *testing.T) {
	cases := []struct {
		name         string
		webProbes    int
		authFailures int
		exploits     int
	}{
		{"one_below_web_probes", thresholds.WebAttackChainMinWebProbes - 1, thresholds.WebAttackChainMinAuthFailures, thresholds.WebAttackChainMinExploitSignals},
		{"one_below_auth_failures", thresholds.WebAttackChainMinWebProbes, thresholds.WebAttackChainMinAuthFailures - 1, thresholds.WebAttackChainMinExploitSignals},
		{"one_below_exploits", thresholds.WebAttackChainMinWebProbes, thresholds.WebAttackChainMinAuthFailures, thresholds.WebAttackChainMinExploitSignals - 1},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := NewChainTracker(0)
			ip := "198.51.100.20"
			base := time.Now().UTC()

			webFirst := base
			for i := 0; i < tc.webProbes; i++ {
				c.RecordWebProbe(ip, webFirst.Add(time.Duration(i)*time.Millisecond), thresholds.WebAttackChainWindow)
			}
			authFirst := base.Add(10 * time.Second)
			for i := 0; i < tc.authFailures; i++ {
				c.RecordAuthFailure(ip, authFirst.Add(time.Duration(i)*time.Millisecond), thresholds.WebAttackChainWindow)
			}
			exploitFirst := base.Add(20 * time.Second)
			for i := 0; i < tc.exploits; i++ {
				c.RecordExploitSignal(ip, exploitFirst.Add(time.Duration(i)*time.Millisecond), thresholds.WebAttackChainWindow)
			}

			_, _, _, matched := c.EvaluateWebAttackChain(ip, exploitFirst, thresholds.WebAttackChainWindow)
			if matched {
				t.Fatalf("did not expect a match one below the %s threshold", tc.name)
			}
		})
	}
}

func TestEvaluateWebAttackChain_ThresholdBoundary_ExactlyAtEachMinimum_Matches(t *testing.T) {
	c := NewChainTracker(0)
	ip := "198.51.100.21"
	base := time.Now().UTC()

	_, _, exploitFirst := driveWebAttackChainStages(c, ip, base, thresholds.WebAttackChainWindow)

	_, _, _, matched := c.EvaluateWebAttackChain(ip, exploitFirst, thresholds.WebAttackChainWindow)
	if !matched {
		t.Fatalf("expected a match at exactly the minimum count for all three stages")
	}
}

func TestEvaluateWebAttackChain_WrongOrder_ExploitBeforeWebProbe_NoMatch(t *testing.T) {
	c := NewChainTracker(0)
	ip := "198.51.100.30"
	base := time.Now().UTC()

	// Exploitation signal comes FIRST, then web-probing, then auth --
	// the sequence check requires web -> auth -> exploit.
	exploitFirst := base
	for i := 0; i < thresholds.WebAttackChainMinExploitSignals; i++ {
		c.RecordExploitSignal(ip, exploitFirst.Add(time.Duration(i)*time.Millisecond), thresholds.WebAttackChainWindow)
	}
	webFirst := base.Add(10 * time.Second)
	for i := 0; i < thresholds.WebAttackChainMinWebProbes; i++ {
		c.RecordWebProbe(ip, webFirst.Add(time.Duration(i)*time.Millisecond), thresholds.WebAttackChainWindow)
	}
	authFirst := base.Add(20 * time.Second)
	for i := 0; i < thresholds.WebAttackChainMinAuthFailures; i++ {
		c.RecordAuthFailure(ip, authFirst.Add(time.Duration(i)*time.Millisecond), thresholds.WebAttackChainWindow)
	}

	_, _, _, matched := c.EvaluateWebAttackChain(ip, authFirst, thresholds.WebAttackChainWindow)
	if matched {
		t.Fatalf("did not expect a match when the exploitation signal precedes web probing")
	}
}

func TestEvaluateWebAttackChain_WrongOrder_AuthBeforeWebProbe_NoMatch(t *testing.T) {
	c := NewChainTracker(0)
	ip := "198.51.100.31"
	base := time.Now().UTC()

	authFirst := base
	for i := 0; i < thresholds.WebAttackChainMinAuthFailures; i++ {
		c.RecordAuthFailure(ip, authFirst.Add(time.Duration(i)*time.Millisecond), thresholds.WebAttackChainWindow)
	}
	webFirst := base.Add(10 * time.Second)
	for i := 0; i < thresholds.WebAttackChainMinWebProbes; i++ {
		c.RecordWebProbe(ip, webFirst.Add(time.Duration(i)*time.Millisecond), thresholds.WebAttackChainWindow)
	}
	exploitFirst := base.Add(20 * time.Second)
	for i := 0; i < thresholds.WebAttackChainMinExploitSignals; i++ {
		c.RecordExploitSignal(ip, exploitFirst.Add(time.Duration(i)*time.Millisecond), thresholds.WebAttackChainWindow)
	}

	_, _, _, matched := c.EvaluateWebAttackChain(ip, exploitFirst, thresholds.WebAttackChainWindow)
	if matched {
		t.Fatalf("did not expect a match when auth-probing precedes web-probing")
	}
}

func TestEvaluateWebAttackChain_SimultaneousTimestamps_TieToleranceAllows(t *testing.T) {
	c := NewChainTracker(0)
	ip := "198.51.100.32"
	base := time.Now().UTC().Truncate(time.Second)

	// All three stages land within the SAME wall-clock second (but at
	// different sub-second/nanosecond offsets), simulating a fast
	// automated tool chain. The whole-second truncation tie-tolerance
	// must allow this, matching Evaluate()'s documented behavior.
	for i := 0; i < thresholds.WebAttackChainMinWebProbes; i++ {
		c.RecordWebProbe(ip, base.Add(time.Duration(i)*time.Nanosecond), thresholds.WebAttackChainWindow)
	}
	for i := 0; i < thresholds.WebAttackChainMinAuthFailures; i++ {
		c.RecordAuthFailure(ip, base.Add(time.Duration(i)*time.Nanosecond), thresholds.WebAttackChainWindow)
	}
	for i := 0; i < thresholds.WebAttackChainMinExploitSignals; i++ {
		c.RecordExploitSignal(ip, base.Add(time.Duration(i)*time.Nanosecond), thresholds.WebAttackChainWindow)
	}

	_, _, _, matched := c.EvaluateWebAttackChain(ip, base, thresholds.WebAttackChainWindow)
	if !matched {
		t.Fatalf("expected same-second (tie-tolerant) stages to match")
	}
}

func TestEvaluateWebAttackChain_WindowExpiry_StaleStageDropsOut(t *testing.T) {
	c := NewChainTracker(0)
	ip := "198.51.100.40"
	base := time.Now().UTC()

	// Web-probing stage happens, then falls OUTSIDE the window by the
	// time auth+exploit stages complete and Evaluate is called.
	webFirst := base
	for i := 0; i < thresholds.WebAttackChainMinWebProbes; i++ {
		c.RecordWebProbe(ip, webFirst.Add(time.Duration(i)*time.Millisecond), thresholds.WebAttackChainWindow)
	}

	// Move well past the window before recording the remaining stages
	// and evaluating -- the web-probe timestamps should have pruned out.
	later := base.Add(thresholds.WebAttackChainWindow + 5*time.Minute)
	authFirst := later
	for i := 0; i < thresholds.WebAttackChainMinAuthFailures; i++ {
		c.RecordAuthFailure(ip, authFirst.Add(time.Duration(i)*time.Millisecond), thresholds.WebAttackChainWindow)
	}
	exploitFirst := later.Add(10 * time.Second)
	for i := 0; i < thresholds.WebAttackChainMinExploitSignals; i++ {
		c.RecordExploitSignal(ip, exploitFirst.Add(time.Duration(i)*time.Millisecond), thresholds.WebAttackChainWindow)
	}

	webCount, _, _, matched := c.EvaluateWebAttackChain(ip, exploitFirst, thresholds.WebAttackChainWindow)
	if matched {
		t.Fatalf("did not expect a match once the web-probing stage has aged out of the window")
	}
	if webCount != 0 {
		t.Errorf("expected the stale web-probe timestamps to have been pruned (webCount=0), got %d", webCount)
	}
}

func TestEvaluateWebAttackChain_PerIPIsolation(t *testing.T) {
	c := NewChainTracker(0)
	ipA := "198.51.100.50"
	ipB := "198.51.100.51"
	base := time.Now().UTC()

	// Full sequence for ipA only.
	_, _, exploitFirstA := driveWebAttackChainStages(c, ipA, base, thresholds.WebAttackChainWindow)

	// ipB gets only a web-probing stage -- must not borrow ipA's state.
	for i := 0; i < thresholds.WebAttackChainMinWebProbes; i++ {
		c.RecordWebProbe(ipB, base.Add(time.Duration(i)*time.Millisecond), thresholds.WebAttackChainWindow)
	}

	if _, _, _, matched := c.EvaluateWebAttackChain(ipA, exploitFirstA, thresholds.WebAttackChainWindow); !matched {
		t.Fatalf("expected ipA's full sequence to match")
	}
	if _, _, _, matched := c.EvaluateWebAttackChain(ipB, exploitFirstA, thresholds.WebAttackChainWindow); matched {
		t.Fatalf("did not expect ipB (only web-probing stage) to match -- per-IP state must be isolated")
	}
}

func TestEvaluateWebAttackChain_ConcurrentRecordsAcrossIPs_NoRaceNoCorruption(t *testing.T) {
	c := NewChainTracker(0)
	base := time.Now().UTC()
	done := make(chan struct{})

	ips := []string{"198.51.100.60", "198.51.100.61", "198.51.100.62", "198.51.100.63"}
	for _, ip := range ips {
		go func(ip string) {
			driveWebAttackChainStages(c, ip, base, thresholds.WebAttackChainWindow)
			done <- struct{}{}
		}(ip)
	}
	for range ips {
		<-done
	}

	for _, ip := range ips {
		if _, _, _, matched := c.EvaluateWebAttackChain(ip, base.Add(30*time.Second), thresholds.WebAttackChainWindow); !matched {
			t.Errorf("expected ip %s to have matched after concurrent recording", ip)
		}
	}
}
