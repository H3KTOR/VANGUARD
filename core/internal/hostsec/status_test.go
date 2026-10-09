package hostsec

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func statusOf(m *Manager, name string) ScanStatus {
	for _, s := range m.Status() {
		if s.Name == name {
			return s
		}
	}
	return ScanStatus{}
}

func newStatusManager(t *testing.T) *Manager {
	t.Helper()
	cfg := DefaultConfig()
	cfg.SystemPosture = DefaultSystemPostureConfig()
	m := NewManager(testDB(t), &fakeReporter{}, cfg)
	m.board.Register("probe", time.Minute)
	return m
}

func TestStatus_RegisteredScannerStartsNeverRun(t *testing.T) {
	m := newStatusManager(t)
	if s := statusOf(m, "probe"); s.LastResult != ResultNever || s.LastCleanScan != nil || s.Runs != 0 {
		t.Fatalf("%+v", s)
	}
}

func TestStatus_OKAdvancesLastCleanScan(t *testing.T) {
	m := newStatusManager(t)
	m.runScan(context.Background(), "probe", func(context.Context) {})
	s := statusOf(m, "probe")
	if s.LastResult != ResultOK || s.LastCleanScan == nil || s.Runs != 1 || s.LastFinished == nil {
		t.Fatalf("%+v", s)
	}
}

func TestStatus_FailedAndSkippedAreNeverClean(t *testing.T) {
	m := newStatusManager(t)
	m.runScan(context.Background(), "probe", func(context.Context) { m.board.report("probe", ResultSkipped, "db absent") })
	s := statusOf(m, "probe")
	if s.LastResult != ResultSkipped || s.LastCleanScan != nil || s.Skips != 1 || s.LastNote != "db absent" {
		t.Fatalf("skipped: %+v", s)
	}
	m.runScan(context.Background(), "probe", func(context.Context) {
		m.board.report("probe", ResultFailed, "boom")
		m.board.report("probe", ResultSkipped, "ignored: less severe")
	})
	s = statusOf(m, "probe")
	if s.LastResult != ResultFailed || s.LastNote != "boom" || s.Failures != 1 || s.LastCleanScan != nil {
		t.Fatalf("failed (worst wins): %+v", s)
	}
	m.runScan(context.Background(), "probe", func(context.Context) {})
	if s = statusOf(m, "probe"); s.LastResult != ResultOK || s.LastCleanScan == nil {
		t.Fatalf("recovery: %+v", s)
	}
}

func TestStatus_PanicIsContainedAndRecorded(t *testing.T) {
	m := newStatusManager(t)
	m.runScan(context.Background(), "probe", func(context.Context) { panic("scanner bug") })
	s := statusOf(m, "probe")
	if s.LastResult != ResultFailed || s.Failures != 1 {
		t.Fatalf("%+v", s)
	}
}

func TestStatus_TimeoutRecorded(t *testing.T) {
	m := newStatusManager(t)
	m.scanTimeout = 30 * time.Millisecond
	start := time.Now()
	m.runScan(context.Background(), "probe", func(ctx context.Context) { <-ctx.Done() })
	if time.Since(start) > 2*time.Second {
		t.Fatal("scan was not bounded by its deadline")
	}
	if s := statusOf(m, "probe"); s.LastResult != ResultTimeout || s.Timeouts != 1 || s.LastCleanScan != nil {
		t.Fatalf("%+v", s)
	}
}

func TestStatus_UnknownNamesIgnoredBoundedCardinality(t *testing.T) {
	b := NewStatusBoard()
	b.Register("a", time.Second)
	for i := 0; i < 1000; i++ {
		b.report("attacker-controlled-"+string(rune(i)), ResultFailed, "x")
		b.begin("nope", time.Now())
	}
	if n := len(b.Snapshot()); n != 1 {
		t.Fatalf("board grew to %d entries", n)
	}
}

func TestStatus_ConcurrentUse(t *testing.T) {
	m := newStatusManager(t)
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			m.runScan(context.Background(), "probe", func(context.Context) { m.board.report("probe", ResultSkipped, "c") })
			_ = m.Status()
		}(i)
	}
	wg.Wait()
}

// Phase 4 detectors must report a failed/skipped scan -- not a clean one --
// when their data source is unavailable.
func TestStatus_Phase4DetectorsReportUnavailableSources(t *testing.T) {
	cfg := DefaultConfig()
	sp := DefaultSystemPostureConfig()
	sp.Packages.StatusPath = filepath.Join(t.TempDir(), "does-not-exist")
	cfg.SystemPosture = sp
	m := NewManager(testDB(t), &fakeReporter{}, cfg)
	m.board.Register("package_drift", time.Minute)
	m.board.Register("listening", time.Minute)

	m.runScan(context.Background(), "package_drift", m.packages.Scan)
	if s := statusOf(m, "package_drift"); s.LastResult != ResultSkipped || s.LastCleanScan != nil {
		t.Fatalf("missing dpkg db must be 'skipped', not clean: %+v", s)
	}

	m.listening = m.listening.WithProcRoot(filepath.Join(t.TempDir(), "no-proc"))
	m.listening.rep = m.reporterFor("listening")
	m.runScan(context.Background(), "listening", m.listening.Scan)
	if s := statusOf(m, "listening"); s.LastResult != ResultFailed || s.LastCleanScan != nil {
		t.Fatalf("unreadable /proc must be 'failed', not clean: %+v", s)
	}
}

func TestStatus_HealthyPhase4ScanIsClean(t *testing.T) {
	dir := t.TempDir()
	status := filepath.Join(dir, "status")
	if err := os.WriteFile(status, []byte(stanza("curl", "1-1", "amd64", installed)), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := DefaultConfig()
	sp := DefaultSystemPostureConfig()
	sp.Packages.StatusPath = status
	cfg.SystemPosture = sp
	m := NewManager(testDB(t), &fakeReporter{}, cfg)
	m.board.Register("package_drift", time.Minute)
	m.runScan(context.Background(), "package_drift", m.packages.Scan)
	if s := statusOf(m, "package_drift"); s.LastResult != ResultOK || s.LastCleanScan == nil {
		t.Fatalf("%+v", s)
	}
}

// A scan that ignores its context (stuck syscall) must not wedge the
// scanner loop, must be reported as a timeout, and must never be
// overlapped by a second run of the same scanner.
func TestStatus_WedgedScanIsAbandonedAndNeverOverlapped(t *testing.T) {
	m := newStatusManager(t)
	m.scanTimeout = 20 * time.Millisecond
	m.abandonGrace = 30 * time.Millisecond
	release := make(chan struct{})
	var started atomic.Int32
	wedged := func(context.Context) { started.Add(1); <-release } // ignores ctx on purpose

	t0 := time.Now()
	m.runScan(context.Background(), "probe", wedged)
	if time.Since(t0) > 2*time.Second {
		t.Fatal("the loop must not wait for a wedged scan forever")
	}
	if s := statusOf(m, "probe"); s.LastResult != ResultTimeout || !strings.Contains(s.LastNote, "abandoned") || s.LastCleanScan != nil {
		t.Fatalf("%+v", s)
	}
	// next tick while the old goroutine is still stuck: no overlap
	m.runScan(context.Background(), "probe", wedged)
	if started.Load() != 1 {
		t.Fatalf("a second scan was started while the first is still in flight (%d starts)", started.Load())
	}
	if s := statusOf(m, "probe"); s.LastResult != ResultTimeout || !strings.Contains(s.LastNote, "still running") {
		t.Fatalf("%+v", s)
	}
	// once the stuck scan finally returns, the scanner works again
	close(release)
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		m.inflightMu.Lock()
		busy := m.inflight["probe"]
		m.inflightMu.Unlock()
		if !busy {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	m.runScan(context.Background(), "probe", func(context.Context) {})
	if s := statusOf(m, "probe"); s.LastResult != ResultOK || s.LastCleanScan == nil {
		t.Fatalf("scanner must recover after the stuck scan returns: %+v", s)
	}
}

func TestManagerRunRefusesDoubleStart(t *testing.T) {
	m := newStatusManager(t)
	m.running.Store(true) // simulate an already-running manager
	done := make(chan struct{})
	go func() { m.Run(context.Background()); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("a second Run must return immediately instead of starting duplicate workers")
	}
	if !m.running.Load() {
		t.Fatal("the refused Run must not clear the running flag of the live one")
	}
}
