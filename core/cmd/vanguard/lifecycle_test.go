package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"

	"vanguard/core/internal/database"
)

// Repeated shutdown requests (signal plus an error path) must be harmless
// and must never hang or double-close the database.
func TestShutdownIsIdempotent(t *testing.T) {
	cfg := parseServeFlags([]string{
		"-db", filepath.Join(t.TempDir(), "s.db"),
		"-auth-log", "", "-honeypot=false", "-hostsec=false", "-intel=false",
		"-jwt-secret", "test-secret-test-secret-test-secret",
	})
	cfg.ShutdownTimeout = 2 * time.Second
	a, err := buildApp(cfg)
	if err != nil {
		t.Fatalf("buildApp: %v", err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); a.shutdown() }()
	}
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("concurrent shutdown calls hung")
	}
	a.shutdown() // and once more after completion
}

func TestHealthRegistryReflectsConfiguration(t *testing.T) {
	cfg := parseServeFlags([]string{"-auth-log", "", "-web-log", "/a.log,/b.log", "-jwt-secret", "x-x-x-x-x-x-x-x-x-x-x-x"})
	reg := newRuntimeRegistry(cfg)
	got := map[string]string{}
	for _, c := range reg.Snapshot() {
		got[c.Name] = string(c.State)
	}
	if got["log:auth"] != "disabled" {
		t.Errorf("a source disabled by configuration must be 'disabled': %v", got)
	}
	if got["log:web1"] != "not_yet_observed" || got["log:web2"] != "not_yet_observed" || got["maintenance"] != "not_yet_observed" {
		t.Errorf("nothing observed yet must not read as healthy: %v", got)
	}
}

// A retention tick with the default policy deletes nothing and reports the
// component as disabled (not healthy); with a policy it deletes only what the
// policy allows, and Panic Mode suspends it.
func TestRetentionTickBehaviour(t *testing.T) {
	cfg := parseServeFlags([]string{
		"-db", filepath.Join(t.TempDir(), "r.db"),
		"-auth-log", "", "-honeypot=false", "-hostsec=false", "-intel=false",
		"-jwt-secret", "test-secret-test-secret-test-secret",
	})
	a, err := buildApp(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer a.shutdown()
	old := time.Now().UTC().AddDate(-2, 0, 0)
	inc := &database.Incident{Type: database.IncidentPortScan, SourceIP: "203.0.113.4", Status: database.StatusResolved, DetectedAt: old, ResolvedAt: &old}
	if err := a.db.Create(inc).Error; err != nil {
		t.Fatal(err)
	}
	state := func() string {
		for _, c := range a.health.Snapshot() {
			if c.Name == retentionComponent {
				return string(c.State)
			}
		}
		return "missing"
	}
	a.retention.Skip = func() string { return "" }
	a.retentionTick(context.Background())
	var n int64
	a.db.Model(&database.Incident{}).Count(&n)
	if n != 1 || state() != "disabled" {
		t.Fatalf("default policy must keep data and read as disabled: n=%d state=%s", n, state())
	}

	pol := database.RetentionPolicy{IncidentRetentionDays: 90, BatchSize: 50, MaxBatchesPerRun: 2, KeepWithNotes: true}
	if _, err := a.db.SetRetentionPolicy(pol, 0, "cli:test", time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	a.retention.Skip = func() string { return "Panic Mode is active" }
	a.retentionTick(context.Background())
	a.db.Model(&database.Incident{}).Count(&n)
	if n != 1 || state() != "degraded" {
		t.Fatalf("a skipped run must delete nothing and degrade: n=%d state=%s", n, state())
	}

	a.retention.Skip = func() string { return "" }
	a.retentionTick(context.Background())
	a.db.Model(&database.Incident{}).Count(&n)
	if n != 0 || state() != "healthy" {
		t.Fatalf("policy run: n=%d state=%s", n, state())
	}
}

// End to end through the real tailer, queue, engine and database: lines
// appended to the auth log become an incident, and a clean shutdown leaves no
// queued line unaccounted for.
func TestIngestPipelineEndToEnd(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the tail library does not reliably deliver file-change notifications on Windows; run on Linux")
	}
	dir := t.TempDir()
	logPath := filepath.Join(dir, "auth.log")
	if err := os.WriteFile(logPath, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := parseServeFlags([]string{
		"-db", filepath.Join(dir, "e.db"), "-auth-log", logPath,
		"-honeypot=false", "-hostsec=false", "-intel=false", "-jwt-secret", "test-secret-test-secret-test-secret",
	})
	cfg.ShutdownTimeout = 5 * time.Second
	a, err := buildApp(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	a.startBackgroundTasks(ctx)
	time.Sleep(500 * time.Millisecond) // let the tailer open the file at EOF

	f, _ := os.OpenFile(logPath, os.O_APPEND|os.O_WRONLY, 0o600)
	for i := 0; i < 15; i++ {
		fmt.Fprintf(f, "Oct 10 12:00:%02d host sshd[1]: Failed password for root from 203.0.113.99 port 22 ssh2\n", i)
	}
	f.Close()

	deadline := time.Now().Add(10 * time.Second)
	for {
		var n int64
		a.db.Model(&database.Incident{}).Count(&n)
		if n >= 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("no incident created through the pipeline; queue=%+v", a.queues[0].Stats())
		}
		time.Sleep(50 * time.Millisecond)
	}
	cancel()
	a.shutdown()
	st := a.queues[0].Stats()
	if st.Lost() != 0 || st.Running || st.Depth != 0 || st.Processed == 0 {
		t.Fatalf("clean shutdown must account for every line: %+v", st)
	}
}

// Same path as above minus the file tailer (which cannot be exercised on every
// platform): queue -> engine -> database, ordered, with a clean drain.
func TestQueueToEngineToDatabase(t *testing.T) {
	dir := t.TempDir()
	cfg := parseServeFlags([]string{
		"-db", filepath.Join(dir, "q.db"), "-auth-log", filepath.Join(dir, "auth.log"),
		"-honeypot=false", "-hostsec=false", "-intel=false", "-jwt-secret", "test-secret-test-secret-test-secret",
	})
	a, err := buildApp(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	q := a.queues[0]
	done := make(chan struct{})
	go func() { q.Run(ctx); close(done) }()
	for i := 0; i < 15; i++ {
		q.Submit(fmt.Sprintf("Oct 10 12:00:%02d host sshd[1]: Failed password for root from 203.0.113.99 port 22 ssh2", i))
	}
	q.Submit("garbage that no parser understands")
	deadline := time.Now().Add(10 * time.Second)
	for q.Stats().Processed < 16 {
		if time.Now().After(deadline) {
			t.Fatalf("lines not processed: %+v", q.Stats())
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	<-done
	a.shutdown()
	var n int64
	// the database is closed by shutdown; reopen read-only via a fresh handle
	db2, err := database.Open(database.Config{Path: cfg.DBPath})
	if err != nil {
		t.Fatal(err)
	}
	defer db2.Close()
	db2.Model(&database.Incident{}).Where("type = ?", database.IncidentSSHBruteForce).Count(&n)
	if n != 1 {
		t.Fatalf("want exactly one SSH brute-force incident, got %d", n)
	}
	if st := q.Stats(); st.Lost() != 0 || st.Failed != 0 {
		t.Fatalf("unexpected loss: %+v", st)
	}
	if st := a.engine.Stats(); st.Created != 1 || st.Failed != 0 {
		t.Fatalf("engine stats: %+v", st)
	}
}
