package detection

import (
	"sync"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// WindowCounterTracker tests
// ---------------------------------------------------------------------------

func TestWindowCounterTracker_Record_AccumulatesWithinWindow(t *testing.T) {
	tr := NewWindowCounterTracker(30 * time.Minute)
	ip := "203.0.113.100"
	base := time.Now().UTC()

	tr.Record(ip, base, time.Minute)
	tr.Record(ip, base.Add(time.Second), time.Minute)
	count := tr.Record(ip, base.Add(2*time.Second), time.Minute)

	if count != 3 {
		t.Errorf("expected count=3, got %d", count)
	}
}

func TestWindowCounterTracker_WindowExpiry_OldEventsPruned(t *testing.T) {
	tr := NewWindowCounterTracker(30 * time.Minute)
	ip := "203.0.113.101"
	base := time.Now().UTC()
	window := time.Minute

	tr.Record(ip, base, window)
	count := tr.Record(ip, base.Add(window+time.Second), window)

	if count != 1 {
		t.Fatalf("expected old event to be pruned after window expiry, got count=%d", count)
	}
}

func TestWindowCounterTracker_PerIPIsolation(t *testing.T) {
	tr := NewWindowCounterTracker(30 * time.Minute)
	base := time.Now().UTC()

	tr.Record("203.0.113.102", base, time.Minute)
	tr.Record("203.0.113.102", base, time.Minute)
	count := tr.Record("203.0.113.103", base, time.Minute)

	if count != 1 {
		t.Fatalf("expected the second IP's state to be isolated, got count=%d", count)
	}
}

func TestWindowCounterTracker_Reap_RemovesOnlyIdleEntries(t *testing.T) {
	tr := NewWindowCounterTracker(5 * time.Minute)
	base := time.Now().UTC()

	tr.Record("203.0.113.104", base, time.Minute)
	tr.Record("203.0.113.105", base, time.Minute)
	tr.Record("203.0.113.105", base.Add(4*time.Minute), time.Minute)

	removed := tr.Reap(base.Add(8 * time.Minute))
	if removed != 1 {
		t.Fatalf("expected exactly 1 idle entry reaped, got %d", removed)
	}
	if tr.TrackedIPCount() != 1 {
		t.Fatalf("expected 1 tracked IP remaining, got %d", tr.TrackedIPCount())
	}
}

func TestWindowCounterTracker_ConcurrentAccess_NoRaceNoPanic(t *testing.T) {
	tr := NewWindowCounterTracker(30 * time.Minute)
	base := time.Now().UTC()
	var wg sync.WaitGroup

	for g := 0; g < 20; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			ip := "10.2.0." + itoa(g%5)
			for i := 0; i < 50; i++ {
				ts := base.Add(time.Duration(i) * time.Millisecond)
				tr.Record(ip, ts, time.Minute)
			}
		}(g)
	}
	wg.Wait()

	if tr.TrackedIPCount() > 5 {
		t.Fatalf("expected at most 5 distinct IPs tracked, got %d", tr.TrackedIPCount())
	}
}

// ---------------------------------------------------------------------------
// DistinctValueTracker tests
// ---------------------------------------------------------------------------

func TestDistinctValueTracker_Record_CountsDistinctValues(t *testing.T) {
	tr := NewDistinctValueTracker(30 * time.Minute)
	ip := "203.0.113.110"
	base := time.Now().UTC()

	tr.Record(ip, "a.example.com", base, 5*time.Minute)
	tr.Record(ip, "a.example.com", base.Add(time.Second), 5*time.Minute) // repeat
	count := tr.Record(ip, "b.example.com", base.Add(2*time.Second), 5*time.Minute)

	if count != 2 {
		t.Fatalf("expected 2 distinct values (repeats not double-counted), got %d", count)
	}
}

func TestDistinctValueTracker_WindowExpiry_OldValuesPruned(t *testing.T) {
	tr := NewDistinctValueTracker(30 * time.Minute)
	ip := "203.0.113.111"
	base := time.Now().UTC()
	window := 5 * time.Minute

	tr.Record(ip, "old.example.com", base, window)
	count := tr.Record(ip, "new.example.com", base.Add(window+time.Second), window)

	if count != 1 {
		t.Fatalf("expected old value to be pruned after window expiry, got count=%d", count)
	}
}

func TestDistinctValueTracker_PerIPIsolation(t *testing.T) {
	tr := NewDistinctValueTracker(30 * time.Minute)
	base := time.Now().UTC()

	tr.Record("203.0.113.112", "a.example.com", base, 5*time.Minute)
	count := tr.Record("203.0.113.113", "b.example.com", base, 5*time.Minute)

	if count != 1 {
		t.Fatalf("expected the second IP's state to be isolated, got count=%d", count)
	}
}

func TestDistinctValueTracker_Reap_RemovesOnlyIdleEntries(t *testing.T) {
	tr := NewDistinctValueTracker(5 * time.Minute)
	base := time.Now().UTC()

	tr.Record("203.0.113.114", "a.example.com", base, 5*time.Minute)
	tr.Record("203.0.113.115", "b.example.com", base, 5*time.Minute)
	tr.Record("203.0.113.115", "c.example.com", base.Add(4*time.Minute), 5*time.Minute)

	removed := tr.Reap(base.Add(8 * time.Minute))
	if removed != 1 {
		t.Fatalf("expected exactly 1 idle entry reaped, got %d", removed)
	}
	if tr.TrackedIPCount() != 1 {
		t.Fatalf("expected 1 tracked IP remaining, got %d", tr.TrackedIPCount())
	}
}

func TestDistinctValueTracker_ConcurrentAccess_NoRaceNoPanic(t *testing.T) {
	tr := NewDistinctValueTracker(30 * time.Minute)
	base := time.Now().UTC()
	var wg sync.WaitGroup

	for g := 0; g < 20; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			ip := "10.3.0." + itoa(g%5)
			for i := 0; i < 50; i++ {
				ts := base.Add(time.Duration(i) * time.Millisecond)
				tr.Record(ip, "host"+itoa(i%10)+".example.com", ts, 5*time.Minute)
			}
		}(g)
	}
	wg.Wait()

	if tr.TrackedIPCount() > 5 {
		t.Fatalf("expected at most 5 distinct IPs tracked, got %d", tr.TrackedIPCount())
	}
}
