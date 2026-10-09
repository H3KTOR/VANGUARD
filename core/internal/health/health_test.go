package health

import (
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

var t0 = time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)

func clocked() (*Registry, *time.Time) {
	now := t0
	r := New()
	r.SetClock(func() time.Time { return now })
	return r, &now
}

func state(r *Registry, name string) Component {
	for _, c := range r.Snapshot() {
		if c.Name == name {
			return c
		}
	}
	return Component{}
}

func TestNeverObservedIsNotHealthy(t *testing.T) {
	r, _ := clocked()
	r.Register("scanner", time.Minute)
	if c := state(r, "scanner"); c.State != NotYetObserved || c.LastSuccess != nil {
		t.Fatalf("%+v", c)
	}
	if Overall(r.Snapshot()) == Healthy {
		t.Fatal("a never-observed component must keep the overall state from being healthy")
	}
}

func TestSuccessFailureAndSeparateTimestamps(t *testing.T) {
	r, now := clocked()
	r.Register("c", time.Minute)
	r.Success("c")
	*now = now.Add(10 * time.Second)
	r.Failure("c", Failed, "open /var/log/auth.log: permission denied")
	c := state(r, "c")
	if c.State != Failed || c.Attempts != 2 || c.Failures != 1 {
		t.Fatalf("%+v", c)
	}
	if !c.LastSuccess.Equal(t0) || !c.LastAttempt.Equal(t0.Add(10*time.Second)) {
		t.Fatalf("last success and last attempt must be tracked separately: %+v", c)
	}
	if strings.Contains(c.Detail, "/var/log") || !strings.Contains(c.Detail, "<path>") {
		t.Fatalf("filesystem path leaked: %q", c.Detail)
	}
	r.Success("c")
	if state(r, "c").State != Healthy || state(r, "c").Detail != "" {
		t.Fatal("recovery must clear the failure")
	}
}

func TestStaleBecomesUnknownNotHealthy(t *testing.T) {
	r, now := clocked()
	r.Register("c", time.Minute)
	r.Success("c")
	*now = now.Add(2 * time.Minute)
	if state(r, "c").State != Healthy {
		t.Fatal("within tolerance")
	}
	*now = now.Add(2 * time.Minute) // 4 min > 3 x 1 min
	c := state(r, "c")
	if c.State != Unknown || !strings.Contains(c.Detail, "missing telemetry") {
		t.Fatalf("%+v", c)
	}
}

func TestStaleDoesNotMaskFailure(t *testing.T) {
	r, now := clocked()
	r.Register("c", time.Minute)
	r.Failure("c", TimedOut, "deadline")
	*now = now.Add(time.Hour)
	if state(r, "c").State != TimedOut {
		t.Fatal("a failed component must stay failed, not decay to unknown")
	}
}

func TestDisabledAndDegradeAndOverall(t *testing.T) {
	r, _ := clocked()
	for _, n := range []string{"a", "b", "c", "d"} {
		r.Register(n, 0)
	}
	r.Success("a")
	r.Disable("b", "off by flag")
	r.Success("c")
	r.Degrade("c", "shedding load")
	r.Success("d")
	if state(r, "b").State != Disabled || state(r, "c").State != Degraded {
		t.Fatal("states")
	}
	if Overall(r.Snapshot()) != Degraded {
		t.Fatalf("overall = %s", Overall(r.Snapshot()))
	}
	r.Failure("d", Failed, "x")
	if Overall(r.Snapshot()) != Failed {
		t.Fatal("failed must dominate")
	}
	r2, _ := clocked()
	r2.Register("only", 0)
	r2.Success("only")
	r2.Register("off", 0)
	r2.Disable("off", "flag")
	if Overall(r2.Snapshot()) != Healthy {
		t.Fatal("healthy + intentionally disabled is healthy")
	}
	if Overall(nil) != Healthy {
		t.Fatal("empty registry has nothing unhealthy (callers register what they run)")
	}
}

func TestBounds(t *testing.T) {
	r, _ := clocked()
	for i := 0; i < MaxComponents; i++ {
		if !r.Register(fmt.Sprintf("c%d", i), 0) {
			t.Fatalf("component %d refused early", i)
		}
	}
	if r.Register("one-too-many", 0) {
		t.Fatal("registry must be bounded")
	}
	for i := 0; i < 50; i++ {
		r.Count("c0", fmt.Sprintf("k%d", i), 1)
	}
	if n := len(state(r, "c0").Counters); n > 8 {
		t.Fatalf("counter set unbounded: %d", n)
	}
	r.Failure("c1", Failed, strings.Repeat("x", 1000))
	if len(state(r, "c1").Detail) > maxDetail {
		t.Fatal("detail unbounded")
	}
	// unknown names are ignored, not created
	r.Success("ghost")
	r.Failure("ghost", Failed, "x")
	for _, c := range r.Snapshot() {
		if c.Name == "ghost" {
			t.Fatal("unregistered component materialized")
		}
	}
}

func TestSnapshotIsACopyAndConcurrencySafe(t *testing.T) {
	r, _ := clocked()
	r.Register("c", time.Minute)
	r.Count("c", "dropped", 1)
	snap := r.Snapshot()
	snap[0].Counters["dropped"] = 999
	if state(r, "c").Counters["dropped"] != 1 {
		t.Fatal("snapshot aliases internal counters")
	}
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				if i%2 == 0 {
					r.Success("c")
					r.Count("c", "n", 1)
				} else {
					r.Failure("c", Degraded, "x")
					_ = r.Snapshot()
				}
			}
		}(i)
	}
	wg.Wait()
}
