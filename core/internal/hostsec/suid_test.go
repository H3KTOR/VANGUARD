package hostsec

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"vanguard/core/internal/database"
)

// mkScratchDir returns a fresh empty directory that is guaranteed NOT to
// fall under any of thresholds.WritableScanRoots (/tmp, /var/tmp,
// /dev/shm), unlike t.TempDir() whose OS default is /tmp on Linux. It is
// created under the current package's working directory (the sandbox's
// project tree, never one of the writable-escalation roots) and removed
// via t.Cleanup.
func mkScratchDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp(".", "hostsec-scratch-")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		t.Fatalf("Abs: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return abs
}

func writeSetuidFile(t *testing.T, path string) {
	t.Helper()
	if err := os.WriteFile(path, []byte("#!/bin/sh\necho hi\n"), 0755); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := os.Chmod(path, 0755|os.ModeSetuid); err != nil {
		t.Fatalf("chmod setuid: %v", err)
	}
}

func TestSUIDMonitor_FirstScanIsSilent(t *testing.T) {
	db := testDB(t)
	rep := &fakeReporter{}
	dir := t.TempDir()
	writeSetuidFile(t, filepath.Join(dir, "suidbin"))

	m := NewSUIDMonitor(db, rep, []string{dir})
	m.Scan(bg())

	if len(rep.findings) != 0 {
		t.Fatalf("expected 0 findings on cold-start seeding scan, got %d: %+v", len(rep.findings), rep.findings)
	}
}

func TestSUIDMonitor_DetectsNewSetuidBinary(t *testing.T) {
	skipIfNoUnixPerms(t) // needs Unix mode bits / ownership; run on Linux
	db := testDB(t)
	rep := &fakeReporter{}
	// Deliberately NOT t.TempDir(): on Linux, os.TempDir() defaults to
	// /tmp, which is itself one of thresholds.WritableScanRoots, so a
	// SUID binary there would always be Critical-escalated regardless of
	// this test's intent. Use a scratch dir under the package's own
	// source tree instead, to simulate a "normal" (non-writable-root)
	// binary directory like /usr/local/bin.
	dir := mkScratchDir(t)

	m := NewSUIDMonitor(db, rep, []string{dir})
	m.Scan(bg()) // seed (empty dir)

	target := filepath.Join(dir, "newsuid")
	writeSetuidFile(t, target)
	rep.reset()
	m.Scan(bg())

	got := rep.byChange("created")
	if len(got) != 1 {
		t.Fatalf("expected exactly 1 'created' finding, got %d: %+v", len(got), rep.findings)
	}
	if got[0].Type != database.IncidentSUIDSGIDAnomaly {
		t.Errorf("expected type %s, got %s", database.IncidentSUIDSGIDAnomaly, got[0].Type)
	}
	if got[0].Critical {
		t.Errorf("expected Critical=false for a SUID binary in a normal (non-writable) directory")
	}
}

func TestSUIDMonitor_CriticalEscalationInWritableDir(t *testing.T) {
	// t.TempDir() returns a path under the OS temp dir, which on Linux is
	// /tmp -- one of thresholds.WritableScanRoots -- so a SUID binary
	// planted there must be escalated to Critical.
	db := testDB(t)
	rep := &fakeReporter{}
	dir := t.TempDir()
	if !strings.HasPrefix(dir, "/tmp") && !strings.HasPrefix(dir, "/var/tmp") {
		t.Skipf("sandbox TMPDIR (%s) is not under a configured writable scan root; skipping", dir)
	}

	m := NewSUIDMonitor(db, rep, []string{dir})
	m.Scan(bg()) // seed (empty dir)

	target := filepath.Join(dir, "backdoor-suid")
	writeSetuidFile(t, target)
	rep.reset()
	m.Scan(bg())

	got := rep.byChange("created")
	if len(got) != 1 {
		t.Fatalf("expected exactly 1 'created' finding, got %d: %+v", len(got), rep.findings)
	}
	if !got[0].Critical {
		t.Errorf("expected Critical=true for a SUID binary planted under a writable/temp root, got false (path=%s)", target)
	}
}

func TestSUIDMonitor_DetectsDeletedSetuidBinary(t *testing.T) {
	skipIfNoUnixPerms(t) // needs Unix mode bits / ownership; run on Linux
	db := testDB(t)
	rep := &fakeReporter{}
	dir := t.TempDir()
	target := filepath.Join(dir, "suidbin")
	writeSetuidFile(t, target)

	m := NewSUIDMonitor(db, rep, []string{dir})
	m.Scan(bg()) // seed

	if err := os.Remove(target); err != nil {
		t.Fatalf("remove: %v", err)
	}
	rep.reset()
	m.Scan(bg())

	got := rep.byChange("deleted")
	if len(got) != 1 {
		t.Fatalf("expected exactly 1 'deleted' finding, got %d: %+v", len(got), rep.findings)
	}
}
