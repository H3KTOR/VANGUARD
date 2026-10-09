package hostsec

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"

	"vanguard/core/internal/database"
)

func skipIfNoUnixPerms(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("unix permission/ownership semantics required")
	}
}

func driftFixture(t *testing.T, content string) (*database.DB, *fakeReporter, string, *ConfigDriftDetector) {
	t.Helper()
	db := testDB(t)
	rep := &fakeReporter{}
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "etc"), 0o755); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(root, "etc", "app.conf")
	if content != "" {
		if err := os.WriteFile(target, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	cfg := DefaultConfigDriftConfig()
	cfg.Paths = []string{"/etc/app.conf"}
	cfg.CriticalPaths = map[string]bool{}
	return db, rep, target, NewConfigDriftDetector(db, rep, cfg).WithRoot(root)
}

func TestConfigDrift_FirstObservationIsBaselineOnly(t *testing.T) {
	_, rep, _, d := driftFixture(t, "a=1\n")
	d.Scan(bg())
	if len(rep.findings) != 0 {
		t.Fatalf("first observation must not be drift, got %+v", rep.findings)
	}
}

func TestConfigDrift_FirstObservationReportedWhenConfigured(t *testing.T) {
	db, rep, _, _ := driftFixture(t, "a=1\n")
	cfg := DefaultConfigDriftConfig()
	cfg.Paths = []string{"/etc/app.conf"}
	cfg.ReportFirstObservation = true
	root := t.TempDir()
	_ = os.MkdirAll(filepath.Join(root, "etc"), 0o755)
	_ = os.WriteFile(filepath.Join(root, "etc", "app.conf"), []byte("x"), 0o644)
	NewConfigDriftDetector(db, rep, cfg).WithRoot(root).Scan(bg())
	if len(rep.byChange("first_observed")) != 1 {
		t.Fatalf("expected first_observed finding, got %+v", rep.findings)
	}
}

func TestConfigDrift_UnchangedNoFinding(t *testing.T) {
	_, rep, _, d := driftFixture(t, "a=1\n")
	d.Scan(bg())
	d.Scan(bg())
	if len(rep.findings) != 0 {
		t.Fatalf("unchanged must not report, got %+v", rep.findings)
	}
}

func TestConfigDrift_ContentChangeReportedOnceThenDeduped(t *testing.T) {
	_, rep, target, d := driftFixture(t, "a=1\n")
	d.Scan(bg())
	if err := os.WriteFile(target, []byte("a=2\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	d.Scan(bg())
	got := rep.byChange("modified")
	if len(got) != 1 {
		t.Fatalf("expected 1 modified finding, got %+v", rep.findings)
	}
	if got[0].Type != database.IncidentConfigurationDrift {
		t.Errorf("wrong type %s", got[0].Type)
	}
	fields, _ := got[0].Details["changed_fields"].([]string)
	if len(fields) != 1 || fields[0] != "content" {
		t.Errorf("changed_fields = %v", got[0].Details["changed_fields"])
	}
	if got[0].Details["content_hashed"] != true {
		t.Errorf("expected content_hashed=true")
	}
	rep.reset()
	for i := 0; i < 5; i++ {
		d.Scan(bg())
	}
	if len(rep.findings) != 0 {
		t.Fatalf("same drift re-reported: %+v", rep.findings)
	}
}

func TestConfigDrift_MtimeOnlyIsNotDrift(t *testing.T) {
	_, rep, target, d := driftFixture(t, "a=1\n")
	d.Scan(bg())
	future := mustFuture()
	if err := os.Chtimes(target, future, future); err != nil {
		t.Fatal(err)
	}
	d.Scan(bg())
	if len(rep.findings) != 0 {
		t.Fatalf("mtime-only change must not be drift: %+v", rep.findings)
	}
}

func TestConfigDrift_CreatedAndDeleted(t *testing.T) {
	_, rep, target, d := driftFixture(t, "") // absent at baseline
	d.Scan(bg())
	if err := os.WriteFile(target, []byte("new"), 0o644); err != nil {
		t.Fatal(err)
	}
	d.Scan(bg())
	if len(rep.byChange("created")) != 1 {
		t.Fatalf("expected created, got %+v", rep.findings)
	}
	if c := rep.byChange("created")[0]; c.Details["created"] != true {
		t.Errorf("created flag missing")
	}
	rep.reset()
	if err := os.Remove(target); err != nil {
		t.Fatal(err)
	}
	d.Scan(bg())
	if len(rep.byChange("deleted")) != 1 {
		t.Fatalf("expected deleted, got %+v", rep.findings)
	}
}

func TestConfigDrift_ModeChange(t *testing.T) {
	skipIfNoUnixPerms(t)
	_, rep, target, d := driftFixture(t, "a=1\n")
	d.Scan(bg())
	if err := os.Chmod(target, 0o600); err != nil {
		t.Fatal(err)
	}
	d.Scan(bg())
	if len(rep.byChange("perm_changed")) != 1 {
		t.Fatalf("expected perm_changed, got %+v", rep.findings)
	}
}

func TestConfigDrift_HashLimitExceededFallsBackToSize(t *testing.T) {
	db, rep, target, _ := driftFixture(t, "0123456789")
	cfg := DefaultConfigDriftConfig()
	cfg.Paths = []string{"/etc/app.conf"}
	cfg.MaxHashBytes = 4
	cfg.CriticalPaths = map[string]bool{}
	root := filepath.Dir(filepath.Dir(target))
	d := NewConfigDriftDetector(db, rep, cfg).WithRoot(root)
	d.Scan(bg())
	// same size, different content: undetectable by metadata, must NOT fire
	_ = os.WriteFile(target, []byte("9876543210"), 0o644)
	d.Scan(bg())
	if len(rep.findings) != 0 {
		t.Fatalf("same-size change without hashing cannot be detected: %+v", rep.findings)
	}
	// size change is detected and flagged hash_skipped
	_ = os.WriteFile(target, []byte("0123456789ABC"), 0o644)
	d.Scan(bg())
	got := rep.byChange("modified")
	if len(got) != 1 || got[0].Details["hash_skipped"] != true || got[0].Details["content_hashed"] != false {
		t.Fatalf("expected metadata-only modified with hash_skipped, got %+v", rep.findings)
	}
}

func TestConfigDrift_CriticalPathEscalates(t *testing.T) {
	db, rep, target, _ := driftFixture(t, "a")
	cfg := DefaultConfigDriftConfig()
	cfg.Paths = []string{"/etc/app.conf"}
	cfg.CriticalPaths = map[string]bool{"/etc/app.conf": true}
	d := NewConfigDriftDetector(db, rep, cfg).WithRoot(filepath.Dir(filepath.Dir(target)))
	d.Scan(bg())
	_ = os.WriteFile(target, []byte("b"), 0o644)
	d.Scan(bg())
	if len(rep.findings) != 1 || !rep.findings[0].Critical {
		t.Fatalf("expected critical finding, got %+v", rep.findings)
	}
}

func TestConfigDrift_BaselinePersistsAcrossRestart(t *testing.T) {
	db, rep, target, d := driftFixture(t, "a=1\n")
	d.Scan(bg())
	// "restart": brand-new detector over the same DB
	cfg := DefaultConfigDriftConfig()
	cfg.Paths = []string{"/etc/app.conf"}
	cfg.CriticalPaths = map[string]bool{}
	root := filepath.Dir(filepath.Dir(target))
	d2 := NewConfigDriftDetector(db, rep, cfg).WithRoot(root)
	d2.Scan(bg())
	if len(rep.findings) != 0 {
		t.Fatalf("restart with unchanged state must be silent: %+v", rep.findings)
	}
	_ = os.WriteFile(target, []byte("a=2\n"), 0o644)
	d2.Scan(bg())
	if len(rep.byChange("modified")) != 1 {
		t.Fatalf("drift after restart not detected: %+v", rep.findings)
	}
}

func TestConfigDrift_InvalidPathsRejected(t *testing.T) {
	got := sanitizeMonitoredPaths("t", []string{"relative/x", "", "/etc//a/../b", "/etc/b", "/ok\x00bad"}, 10)
	if len(got) != 1 || got[0] != "/etc/b" {
		t.Fatalf("sanitize = %v", got)
	}
	got = sanitizeMonitoredPaths("t", []string{"/a", "/b", "/c"}, 2)
	if len(got) != 2 {
		t.Fatalf("limit not enforced: %v", got)
	}
}

func TestDiffDrift_Table(t *testing.T) {
	base := driftState{Exists: true, IsRegular: true, Mode: "-rw-r--r--", UID: 0, GID: 0, Size: 5, Hash: "aa"}
	cases := []struct {
		name string
		mut  func(*driftState)
		want string
	}{
		{"none", func(s *driftState) {}, ""},
		{"mode", func(s *driftState) { s.Mode = "-rw-------" }, "mode"},
		{"uid", func(s *driftState) { s.UID = 1000 }, "uid"},
		{"gid", func(s *driftState) { s.GID = 1000 }, "gid"},
		{"content", func(s *driftState) { s.Hash = "bb" }, "content"},
	}
	for _, c := range cases {
		curr := base
		c.mut(&curr)
		got := diffDrift(base, curr)
		if c.want == "" && len(got) != 0 || c.want != "" && (len(got) != 1 || got[0] != c.want) {
			t.Errorf("%s: got %v want %q", c.name, got, c.want)
		}
	}
}

func TestConfigDrift_ConcurrentScansRaceFree(t *testing.T) {
	_, _, target, d := driftFixture(t, "a=1\n")
	d.reporter = &lockedReporter{}
	d.Scan(bg())
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if i%2 == 0 {
				_ = os.WriteFile(target, []byte{byte('a' + i)}, 0o644)
			}
			d.Scan(bg())
		}(i)
	}
	wg.Wait()
}

func TestConfigDrift_CancelledContextStopsEarly(t *testing.T) {
	_, rep, _, d := driftFixture(t, "a")
	ctx, cancel := context.WithCancel(bg())
	cancel()
	d.Scan(ctx)
	if len(rep.findings) != 0 {
		t.Fatal("cancelled scan reported findings")
	}
}
