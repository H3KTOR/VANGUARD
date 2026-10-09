package hostsec

import (
	"context"
	"os"
	"path/filepath"
	"sync"
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
