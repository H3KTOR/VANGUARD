package database

import (
	"context"
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestGuard_ReturnsResultAndReleasesSlot(t *testing.T) {
	g := NewQueryGuard(1, 50*time.Millisecond, time.Second)
	var got int
	if err := g.Do(context.Background(), func() error { got = 42; return nil }); err != nil || got != 42 {
		t.Fatalf("err=%v got=%d", err, got)
	}
	if st := g.Stats(); st.InFlight != 0 || st.Started != 1 {
		t.Fatalf("slot not released: %+v", st)
	}
	want := errors.New("boom")
	if err := g.Do(context.Background(), func() error { return want }); !errors.Is(err, want) {
		t.Fatalf("error not propagated: %v", err)
	}
}

func TestGuard_TimeoutAbandonsButKeepsSlotUntilWorkEnds(t *testing.T) {
	g := NewQueryGuard(1, 20*time.Millisecond, 50*time.Millisecond)
	release := make(chan struct{})
	start := time.Now()
	err := g.Do(context.Background(), func() error { <-release; return nil })
	if !errors.Is(err, ErrTimeout) {
		t.Fatalf("want ErrTimeout, got %v", err)
	}
	if time.Since(start) > time.Second {
		t.Fatalf("caller was not released promptly: %s", time.Since(start))
	}
	st := g.Stats()
	if st.Abandoned != 1 || st.InFlight != 1 || st.TimedOut != 1 {
		t.Fatalf("abandoned work must still hold its slot: %+v", st)
	}
	// While the abandoned statement runs, new work is rejected, not piled up.
	if err := g.Do(context.Background(), func() error { return nil }); !errors.Is(err, ErrBusy) {
		t.Fatalf("want ErrBusy while the slot is held by abandoned work, got %v", err)
	}
	close(release)
	deadline := time.Now().Add(2 * time.Second)
	for g.Stats().InFlight != 0 || g.Stats().Abandoned != 0 {
		if time.Now().After(deadline) {
			t.Fatalf("slot never freed: %+v", g.Stats())
		}
		time.Sleep(5 * time.Millisecond)
	}
	if err := g.Do(context.Background(), func() error { return nil }); err != nil {
		t.Fatalf("guard must work again after the abandoned work ended: %v", err)
	}
}

func TestGuard_ConcurrencyNeverExceedsLimit(t *testing.T) {
	const limit = 3
	g := NewQueryGuard(limit, time.Second, time.Second)
	var mu sync.Mutex
	cur, max := 0, 0
	var wg sync.WaitGroup
	for i := 0; i < 30; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = g.Do(context.Background(), func() error {
				mu.Lock()
				cur++
				if cur > max {
					max = cur
				}
				mu.Unlock()
				time.Sleep(5 * time.Millisecond)
				mu.Lock()
				cur--
				mu.Unlock()
				return nil
			})
		}()
	}
	wg.Wait()
	if max > limit {
		t.Fatalf("concurrency %d exceeded limit %d", max, limit)
	}
}

func TestGuard_CallerContextCancelReleasesCaller(t *testing.T) {
	g := NewQueryGuard(2, 20*time.Millisecond, 10*time.Second)
	ctx, cancel := context.WithCancel(context.Background())
	release := make(chan struct{})
	res := make(chan error, 1)
	go func() { res <- g.Do(ctx, func() error { <-release; return nil }) }()
	time.Sleep(30 * time.Millisecond)
	cancel()
	select {
	case err := <-res:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("want context.Canceled, got %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("caller not released on cancel")
	}
	close(release)
}

func TestGuard_PanicInsideIsContained(t *testing.T) {
	g := NewQueryGuard(1, time.Second, time.Second)
	if err := g.Do(context.Background(), func() error { panic("x") }); err == nil {
		t.Fatal("a panic must surface as an error")
	}
	if st := g.Stats(); st.InFlight != 0 {
		t.Fatalf("slot leaked after panic: %+v", st)
	}
}

// Real SQLite: documents the property the guard is built around. The caller is
// released at the guard timeout while the statement is still executing, and
// the slot is only freed when SQLite finishes.
func TestGuard_RealSlowSQLiteStatement(t *testing.T) {
	db, err := Open(Config{Path: filepath.Join(t.TempDir(), "g.db")})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	g := NewQueryGuard(1, 10*time.Millisecond, 100*time.Millisecond)
	var n int64
	start := time.Now()
	err = g.Do(context.Background(), func() error {
		return db.Raw("WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM c WHERE x < 1500000) SELECT count(*) FROM c").Scan(&n).Error
	})
	if !errors.Is(err, ErrTimeout) {
		t.Skipf("statement finished inside the guard timeout on this machine (err=%v); nothing to demonstrate", err)
	}
	if time.Since(start) > 900*time.Millisecond {
		t.Fatalf("caller was held for %s", time.Since(start))
	}
	if st := g.Stats(); st.Abandoned != 1 {
		t.Fatalf("expected one abandoned statement: %+v", st)
	}
	deadline := time.Now().Add(30 * time.Second)
	for g.Stats().InFlight != 0 {
		if time.Now().After(deadline) {
			t.Fatal("slot never freed after SQLite finished")
		}
		time.Sleep(20 * time.Millisecond)
	}
}
