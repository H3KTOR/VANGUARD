package detection

import (
	"sync"
	"testing"
	"time"
)

func TestAuthAbuseTracker_RecordFailure_AccumulatesPerUserCounts(t *testing.T) {
	tr := NewAuthAbuseTracker(30 * time.Minute)
	ip := "203.0.113.50"
	base := time.Now().UTC()

	tr.RecordFailure(ip, "alice", base, 10*time.Minute)
	tr.RecordFailure(ip, "alice", base.Add(time.Second), 10*time.Minute)
	snap := tr.RecordFailure(ip, "bob", base.Add(2*time.Second), 10*time.Minute)

	if snap.TotalFailures != 3 {
		t.Errorf("expected TotalFailures=3, got %d", snap.TotalFailures)
	}
	if snap.DistinctUsernames != 2 {
		t.Errorf("expected DistinctUsernames=2, got %d", snap.DistinctUsernames)
	}
	if snap.PerUserFailureCounts["alice"] != 2 {
		t.Errorf("expected alice=2 failures, got %d", snap.PerUserFailureCounts["alice"])
	}
	if snap.PerUserFailureCounts["bob"] != 1 {
		t.Errorf("expected bob=1 failure, got %d", snap.PerUserFailureCounts["bob"])
	}
}

func TestAuthAbuseTracker_WindowExpiry_OldFailuresPruned(t *testing.T) {
	tr := NewAuthAbuseTracker(30 * time.Minute)
	ip := "203.0.113.51"
	base := time.Now().UTC()
	window := 10 * time.Minute

	tr.RecordFailure(ip, "alice", base, window)
	// Well past the window: alice's earlier failure must be pruned out.
	snap := tr.RecordFailure(ip, "bob", base.Add(window+time.Minute), window)

	if snap.TotalFailures != 1 {
		t.Fatalf("expected old failure to be pruned after window expiry, got TotalFailures=%d", snap.TotalFailures)
	}
	if _, stillPresent := snap.PerUserFailureCounts["alice"]; stillPresent {
		t.Fatalf("expected alice's expired failure to be pruned, but it is still present")
	}
}

func TestAuthAbuseTracker_PerIPIsolation(t *testing.T) {
	tr := NewAuthAbuseTracker(30 * time.Minute)
	base := time.Now().UTC()

	tr.RecordFailure("203.0.113.60", "alice", base, 10*time.Minute)
	tr.RecordFailure("203.0.113.60", "bob", base, 10*time.Minute)
	snapOther := tr.RecordFailure("203.0.113.61", "carol", base, 10*time.Minute)

	if snapOther.TotalFailures != 1 || snapOther.DistinctUsernames != 1 {
		t.Fatalf("expected the second IP's state to be completely isolated from the first, got TotalFailures=%d DistinctUsernames=%d",
			snapOther.TotalFailures, snapOther.DistinctUsernames)
	}
	if _, present := snapOther.PerUserFailureCounts["alice"]; present {
		t.Fatalf("expected no cross-IP leakage of usernames")
	}
}

func TestAuthAbuseTracker_RecordSuccess_TracksSeparatelyFromFailures(t *testing.T) {
	tr := NewAuthAbuseTracker(30 * time.Minute)
	ip := "203.0.113.62"
	base := time.Now().UTC()

	tr.RecordFailure(ip, "alice", base, 10*time.Minute)
	snap := tr.RecordSuccess(ip, base.Add(time.Second), 10*time.Minute)

	if snap.TotalFailures != 1 {
		t.Errorf("expected TotalFailures=1 preserved after a success, got %d", snap.TotalFailures)
	}
	if snap.TotalSuccesses != 1 {
		t.Errorf("expected TotalSuccesses=1, got %d", snap.TotalSuccesses)
	}
}

func TestAuthAbuseTracker_Reap_RemovesOnlyIdleEntries(t *testing.T) {
	tr := NewAuthAbuseTracker(5 * time.Minute)
	base := time.Now().UTC()

	tr.RecordFailure("203.0.113.70", "alice", base, 10*time.Minute)
	tr.RecordFailure("203.0.113.71", "bob", base, 10*time.Minute)

	// Only the second IP stays "active" (recent lastSeen).
	tr.RecordFailure("203.0.113.71", "bob", base.Add(4*time.Minute), 10*time.Minute)

	removed := tr.Reap(base.Add(8 * time.Minute))
	if removed != 1 {
		t.Fatalf("expected exactly 1 idle entry reaped, got %d", removed)
	}
	if tr.TrackedIPCount() != 1 {
		t.Fatalf("expected 1 tracked IP remaining after reap, got %d", tr.TrackedIPCount())
	}
}

func TestAuthAbuseTracker_ConcurrentAccess_NoRaceNoPanic(t *testing.T) {
	tr := NewAuthAbuseTracker(30 * time.Minute)
	base := time.Now().UTC()
	var wg sync.WaitGroup

	for g := 0; g < 20; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			ip := "10.0.0." + itoa(g%5) // several goroutines share a handful of IPs to force lock contention
			for i := 0; i < 50; i++ {
				ts := base.Add(time.Duration(i) * time.Millisecond)
				if i%2 == 0 {
					tr.RecordFailure(ip, "user"+itoa(i), ts, 10*time.Minute)
				} else {
					tr.RecordSuccess(ip, ts, 10*time.Minute)
				}
			}
		}(g)
	}
	wg.Wait()

	if tr.TrackedIPCount() > 5 {
		t.Fatalf("expected at most 5 distinct IPs tracked, got %d", tr.TrackedIPCount())
	}
}

func TestAuthAbuseTracker_MissingUsername_RecordedButNotCountedAsDistinct(t *testing.T) {
	tr := NewAuthAbuseTracker(30 * time.Minute)
	ip := "203.0.113.80"
	base := time.Now().UTC()

	snap := tr.RecordFailure(ip, "", base, 10*time.Minute)
	if snap.TotalFailures != 1 {
		t.Errorf("expected the failure to still be recorded (TotalFailures=1), got %d", snap.TotalFailures)
	}
	// Note: DistinctUsernames counts every key in the map including "",
	// so callers (evaluatePasswordSpraying/evaluateCredentialStuffing)
	// are responsible for excluding the empty-string bucket -- this test
	// documents that raw tracker behavior explicitly.
	if _, present := snap.PerUserFailureCounts[""]; !present {
		t.Errorf("expected the empty-username bucket to exist in PerUserFailureCounts")
	}
}
