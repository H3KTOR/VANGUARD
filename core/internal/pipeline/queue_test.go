package pipeline

import (
	"context"
	"fmt"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(2 * time.Millisecond)
	}
}

func TestOrderPreservedPerQueue(t *testing.T) {
	var mu sync.Mutex
	var got []string
	q := New(Config{Name: "a", Size: 8}, func(s string) { mu.Lock(); got = append(got, s); mu.Unlock() })
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { q.Run(ctx); close(done) }()
	for i := 0; i < 500; i++ {
		if !q.Submit(fmt.Sprintf("l%03d", i)) {
			t.Fatalf("line %d rejected", i)
		}
	}
	waitFor(t, "all processed", func() bool { return q.Stats().Processed == 500 })
	cancel()
	<-done
	for i, s := range got {
		if s != fmt.Sprintf("l%03d", i) {
			t.Fatalf("order broken at %d: %s", i, s)
		}
	}
	st := q.Stats()
	if st.Lost() != 0 || st.Enqueued != 500 {
		t.Fatalf("unexpected loss/enqueue: %+v", st)
	}
}

func TestBackpressureBlocksProducerWithoutLoss(t *testing.T) {
	gate := make(chan struct{})
	var mu sync.Mutex
	n := 0
	entered := make(chan struct{}, 8)
	q := New(Config{Name: "bp", Size: 2}, func(string) { entered <- struct{}{}; <-gate; mu.Lock(); n++; mu.Unlock() })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go q.Run(ctx)

	// 1 in the handler + 2 buffered = 3 accepted without blocking.
	q.Submit("x")
	<-entered // the worker now holds the first line
	q.Submit("x")
	q.Submit("x")
	if st := q.Stats(); st.Depth != 2 || st.Waits != 0 {
		t.Fatalf("expected a full queue and no waits yet: %+v", st)
	}

	returned := make(chan bool, 1)
	go func() { returned <- q.Submit("blocked") }()
	select {
	case <-returned:
		t.Fatal("Submit must block while the queue is full")
	case <-time.After(100 * time.Millisecond):
	}
	waitFor(t, "wait counted", func() bool { return q.Stats().Waits == 1 })

	close(gate) // release the worker
	if ok := <-returned; !ok {
		t.Fatal("blocked line was lost instead of accepted")
	}
	waitFor(t, "all 4 processed", func() bool { return q.Stats().Processed == 4 })
	if st := q.Stats(); st.Lost() != 0 {
		t.Fatalf("backpressure must not lose lines: %+v", st)
	}
}

func TestMemoryBoundIsCapacity(t *testing.T) {
	gate := make(chan struct{})
	q := New(Config{Name: "cap", Size: 4}, func(string) { <-gate })
	ctx, cancel := context.WithCancel(context.Background())
	go q.Run(ctx)
	defer func() { close(gate); cancel() }()
	before := runtime.NumGoroutine()
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ { // far more producers than capacity
		wg.Add(1)
		go func() { defer wg.Done(); q.Submit("x") }()
	}
	time.Sleep(100 * time.Millisecond)
	st := q.Stats()
	if st.Depth > 4 || st.HighWater > 4 {
		t.Fatalf("depth exceeded capacity: %+v", st)
	}
	// The queue creates no goroutines of its own per line.
	if g := runtime.NumGoroutine(); g > before+60 {
		t.Fatalf("goroutines grew unexpectedly: %d -> %d", before, g)
	}
	cancel()
	wg.Wait() // blocked producers must be released by shutdown
}

func TestOversizeLineDroppedAndCounted(t *testing.T) {
	var got int
	var mu sync.Mutex
	q := New(Config{Name: "o", MaxLineBytes: 10}, func(string) { mu.Lock(); got++; mu.Unlock() })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go q.Run(ctx)
	if q.Submit(strings.Repeat("a", 11)) {
		t.Fatal("oversize line must be refused")
	}
	if !q.Submit(strings.Repeat("a", 10)) {
		t.Fatal("line at the limit must be accepted")
	}
	waitFor(t, "processed", func() bool { return q.Stats().Processed == 1 })
	st := q.Stats()
	if st.Oversize != 1 || st.LastLossKind != "oversize_line" || st.LastLoss.IsZero() || st.Lost() != 1 {
		t.Fatalf("loss not recorded: %+v", st)
	}
}

func TestPanicIsContainedAndCounted(t *testing.T) {
	var mu sync.Mutex
	var seen []string
	q := New(Config{Name: "p"}, func(s string) {
		if s == "boom" {
			panic("poison")
		}
		mu.Lock()
		seen = append(seen, s)
		mu.Unlock()
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go q.Run(ctx)
	q.Submit("a")
	q.Submit("boom")
	q.Submit("b")
	waitFor(t, "b processed", func() bool { mu.Lock(); defer mu.Unlock(); return len(seen) == 2 })
	st := q.Stats()
	if st.Failed != 1 || !strings.Contains(st.LastError, "poison") || st.Processed != 2 || st.Lost() != 1 {
		t.Fatalf("panic not contained/accounted: %+v", st)
	}
	if !st.Running {
		t.Fatal("worker must survive a handler panic")
	}
}

func TestShutdownDrainsQueuedLines(t *testing.T) {
	var mu sync.Mutex
	n := 0
	q := New(Config{Name: "d", Size: 100}, func(string) { mu.Lock(); n++; mu.Unlock() })
	for i := 0; i < 50; i++ { // queued before the worker ever runs
		q.Submit("x")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // shutdown begins immediately
	q.Run(ctx)
	mu.Lock()
	defer mu.Unlock()
	if n != 50 {
		t.Fatalf("drain processed %d of 50", n)
	}
	st := q.Stats()
	if st.Abandoned != 0 || st.Running {
		t.Fatalf("unexpected state: %+v", st)
	}
}

func TestDrainDeadlineAbandonsAndCounts(t *testing.T) {
	q := New(Config{Name: "dl", Size: 100, DrainTimeout: 30 * time.Millisecond}, func(string) { time.Sleep(20 * time.Millisecond) })
	for i := 0; i < 40; i++ {
		q.Submit("x")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	start := time.Now()
	q.Run(ctx)
	if time.Since(start) > 2*time.Second {
		t.Fatalf("drain was not bounded: %s", time.Since(start))
	}
	st := q.Stats()
	if st.Abandoned == 0 || st.LastLossKind != "abandoned_at_shutdown" {
		t.Fatalf("abandoned lines must be counted: %+v", st)
	}
	if st.Processed+st.Abandoned != 40 {
		t.Fatalf("every line must be accounted for: processed=%d abandoned=%d", st.Processed, st.Abandoned)
	}
	if st.Depth != 0 {
		t.Fatalf("queue must be empty after Run: %+v", st)
	}
}

func TestSubmitAfterShutdownIsRejectedAndCounted(t *testing.T) {
	q := New(Config{Name: "r"}, func(string) {})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	q.Run(ctx)
	if q.Submit("late") {
		t.Fatal("a line offered after shutdown must be refused, not silently queued")
	}
	if st := q.Stats(); st.RejectedShutdown != 1 {
		t.Fatalf("rejection not counted: %+v", st)
	}
}

func TestRunTwiceIsNoop(t *testing.T) {
	q := New(Config{Name: "t"}, func(string) {})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { q.Run(ctx); close(done) }()
	waitFor(t, "running", func() bool { return q.Stats().Running })
	second := make(chan struct{})
	go func() { q.Run(ctx); close(second) }()
	select {
	case <-second:
	case <-time.After(time.Second):
		t.Fatal("second Run must return immediately")
	}
	cancel()
	<-done
}

func TestConfigBoundsClamped(t *testing.T) {
	if q := New(Config{Size: 10_000_000}, func(string) {}); q.Stats().Capacity != MaxSize {
		t.Fatal("size must be clamped to MaxSize")
	}
	if q := New(Config{}, func(string) {}); q.Stats().Capacity != DefaultSize {
		t.Fatal("default size expected")
	}
}
