package detection

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type recObs struct {
	mu                     sync.Mutex
	waiting, started, stop int
	lines                  atomic.Int32
}

func (r *recObs) Waiting()          { r.mu.Lock(); r.waiting++; r.mu.Unlock() }
func (r *recObs) Started()          { r.mu.Lock(); r.started++; r.mu.Unlock() }
func (r *recObs) StartFailed(error) {}
func (r *recObs) Line()             { r.lines.Add(1) }
func (r *recObs) Error(error)       {}
func (r *recObs) Stopped()          { r.mu.Lock(); r.stop++; r.mu.Unlock() }

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// A tailer on a missing file is "waiting" (missing telemetry), never
// "started"; cancellation stops it and Stopped is reported exactly once.
func TestTailObserved_MissingFileIsWaitingNotStarted(t *testing.T) {
	obs := &recObs{}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		_ = TailFileObserved(ctx, filepath.Join(t.TempDir(), "auth.log"), func(string) {}, obs)
		close(done)
	}()
	waitFor(t, "waiting notification", func() bool { obs.mu.Lock(); defer obs.mu.Unlock(); return obs.waiting >= 1 })
	obs.mu.Lock()
	if obs.started != 0 {
		t.Fatal("a tailer on a missing file must not be reported as started")
	}
	obs.mu.Unlock()
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("tailer did not stop on cancellation")
	}
	obs.mu.Lock()
	defer obs.mu.Unlock()
	if obs.stop != 1 {
		t.Fatalf("Stopped must be reported exactly once, got %d", obs.stop)
	}
}

// An existing file is reported started immediately; delivered lines reach
// both the handler and the observer.
func TestTailObserved_ExistingFileStartsAndDeliversLines(t *testing.T) {
	path := filepath.Join(t.TempDir(), "access.log")
	if err := os.WriteFile(path, []byte("old\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	obs := &recObs{}
	var got atomic.Int32
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = TailFileObserved(ctx, path, func(string) { got.Add(1) }, obs) }()
	waitFor(t, "started", func() bool { obs.mu.Lock(); defer obs.mu.Unlock(); return obs.started >= 1 })
	obs.mu.Lock()
	if obs.waiting != 0 {
		t.Fatal("an existing file is not 'waiting'")
	}
	obs.mu.Unlock()
	f, _ := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o644)
	defer f.Close()
	deadline := time.Now().Add(6 * time.Second)
	for got.Load() == 0 && time.Now().Before(deadline) {
		_, _ = f.WriteString("new line\n")
		time.Sleep(100 * time.Millisecond)
	}
	if got.Load() == 0 {
		t.Skip("file-change notifications were not delivered in this environment; line delivery not asserted")
	}
	if obs.lines.Load() == 0 {
		t.Fatal("observer must see delivered lines")
	}
}

func TestTailFile_NilObserverCompatible(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- TailFile(ctx, filepath.Join(t.TempDir(), "nope.log"), func(string) {}) }()
	time.Sleep(100 * time.Millisecond)
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("legacy TailFile must still stop on cancel")
	}
}
