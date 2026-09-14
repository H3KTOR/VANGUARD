package detection

import (
	"sync"
	"testing"
	"time"
)

func TestAPIAbuseTracker_RecordRequest_AccumulatesDistinctPathsAndFailures(t *testing.T) {
	tr := NewAPIAbuseTracker(30 * time.Minute)
	ip := "203.0.113.90"
	base := time.Now().UTC()

	tr.RecordRequest(ip, "/api/users", true, base, time.Minute)
	tr.RecordRequest(ip, "/api/orders", true, base.Add(time.Second), time.Minute)
	snap := tr.RecordRequest(ip, "/api/users", false, base.Add(2*time.Second), time.Minute) // repeat path, success

	if snap.TotalRequests != 3 {
		t.Errorf("expected TotalRequests=3, got %d", snap.TotalRequests)
	}
	if snap.DistinctPaths != 2 {
		t.Errorf("expected DistinctPaths=2 (only 2 unique paths), got %d", snap.DistinctPaths)
	}
	if snap.FailureCount != 2 {
		t.Errorf("expected FailureCount=2, got %d", snap.FailureCount)
	}
}

func TestAPIAbuseTracker_WindowExpiry_OldHitsPruned(t *testing.T) {
	tr := NewAPIAbuseTracker(30 * time.Minute)
	ip := "203.0.113.91"
	base := time.Now().UTC()
	window := time.Minute

	tr.RecordRequest(ip, "/api/old", true, base, window)
	snap := tr.RecordRequest(ip, "/api/new", true, base.Add(window+time.Second), window)

	if snap.TotalRequests != 1 || snap.DistinctPaths != 1 {
		t.Fatalf("expected old hit to be pruned after window expiry, got TotalRequests=%d DistinctPaths=%d",
			snap.TotalRequests, snap.DistinctPaths)
	}
}

func TestAPIAbuseTracker_PerIPIsolation(t *testing.T) {
	tr := NewAPIAbuseTracker(30 * time.Minute)
	base := time.Now().UTC()

	tr.RecordRequest("203.0.113.92", "/api/a", true, base, time.Minute)
	snap := tr.RecordRequest("203.0.113.93", "/api/b", true, base, time.Minute)

	if snap.TotalRequests != 1 || snap.DistinctPaths != 1 {
		t.Fatalf("expected the second IP's state to be isolated, got TotalRequests=%d DistinctPaths=%d",
			snap.TotalRequests, snap.DistinctPaths)
	}
}

func TestAPIAbuseTracker_Reap_RemovesOnlyIdleEntries(t *testing.T) {
	tr := NewAPIAbuseTracker(5 * time.Minute)
	base := time.Now().UTC()

	tr.RecordRequest("203.0.113.94", "/api/a", true, base, time.Minute)
	tr.RecordRequest("203.0.113.95", "/api/b", true, base, time.Minute)
	tr.RecordRequest("203.0.113.95", "/api/b", true, base.Add(4*time.Minute), time.Minute)

	removed := tr.Reap(base.Add(8 * time.Minute))
	if removed != 1 {
		t.Fatalf("expected exactly 1 idle entry reaped, got %d", removed)
	}
	if tr.TrackedIPCount() != 1 {
		t.Fatalf("expected 1 tracked IP remaining, got %d", tr.TrackedIPCount())
	}
}

func TestAPIAbuseTracker_ConcurrentAccess_NoRaceNoPanic(t *testing.T) {
	tr := NewAPIAbuseTracker(30 * time.Minute)
	base := time.Now().UTC()
	var wg sync.WaitGroup

	for g := 0; g < 20; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			ip := "10.1.0." + itoa(g%5)
			for i := 0; i < 50; i++ {
				ts := base.Add(time.Duration(i) * time.Millisecond)
				tr.RecordRequest(ip, "/api/path"+itoa(i%30), i%2 == 0, ts, time.Minute)
			}
		}(g)
	}
	wg.Wait()

	if tr.TrackedIPCount() > 5 {
		t.Fatalf("expected at most 5 distinct IPs tracked, got %d", tr.TrackedIPCount())
	}
}
