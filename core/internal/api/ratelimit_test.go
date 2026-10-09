package api

import (
	"fmt"
	"testing"
	"time"
)

func TestFailureLimiter_WindowBlockResetAndExpiry(t *testing.T) {
	now := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	l := newFailureLimiter(3, 10*time.Minute, 100)
	l.now = func() time.Time { return now }

	for i := 0; i < 2; i++ {
		l.fail("a")
	}
	if b, _ := l.blocked("a"); b {
		t.Fatal("below the maximum must not block")
	}
	l.fail("a")
	b, wait := l.blocked("a")
	if !b || wait <= 0 || wait > 10*time.Minute {
		t.Fatalf("blocked=%v wait=%s", b, wait)
	}
	if b, _ := l.blocked("other"); b {
		t.Fatal("keys are independent")
	}
	// success clears the counter
	l.reset("a")
	if b, _ := l.blocked("a"); b {
		t.Fatal("reset must unblock")
	}
	// the block expires with the window, and a stale window restarts the count
	for i := 0; i < 3; i++ {
		l.fail("b")
	}
	now = now.Add(10*time.Minute + time.Second)
	if b, _ := l.blocked("b"); b {
		t.Fatal("an expired window must not block")
	}
	l.fail("b")
	if b, _ := l.blocked("b"); b {
		t.Fatal("the count must restart after the window")
	}
}

func TestFailureLimiter_MemoryIsBounded(t *testing.T) {
	now := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	l := newFailureLimiter(3, time.Minute, 50)
	l.now = func() time.Time { return now }
	for i := 0; i < 5000; i++ { // an address-spraying client
		l.fail(fmt.Sprintf("10.0.%d.%d", i/250, i%250))
		now = now.Add(time.Millisecond)
	}
	if n := l.len(); n > 50 {
		t.Fatalf("tracked entries %d exceed the cap of 50", n)
	}
}

func TestOpGate_OneAtATimeAndMinimumGap(t *testing.T) {
	now := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	g := newOpGate(30 * time.Second)
	g.now = func() time.Time { return now }

	rel, _, ok := g.enter()
	if !ok {
		t.Fatal("first entry must succeed")
	}
	if _, wait, ok := g.enter(); ok || wait <= 0 {
		t.Fatalf("a second concurrent run must be refused (ok=%v wait=%s)", ok, wait)
	}
	rel()
	if _, wait, ok := g.enter(); ok || wait <= 0 || wait > 30*time.Second {
		t.Fatalf("within the minimum gap: ok=%v wait=%s", ok, wait)
	}
	now = now.Add(31 * time.Second)
	rel, _, ok = g.enter()
	if !ok {
		t.Fatal("after the gap the operation may run again")
	}
	rel()

	// zero gap = only mutual exclusion
	z := newOpGate(0)
	r1, _, ok := z.enter()
	if !ok {
		t.Fatal()
	}
	r1()
	if _, _, ok := z.enter(); !ok {
		t.Fatal("no gap configured: immediately reusable")
	}
}
