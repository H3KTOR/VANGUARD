package hostsec

import (
	"os"
	"path/filepath"
	"testing"

	"vanguard/core/internal/database"
)

func TestFIMWatcher_FirstScanIsSilent(t *testing.T) {
	db := testDB(t)
	rep := &fakeReporter{}
	dir := t.TempDir()
	target := filepath.Join(dir, "watched.conf")
	if err := os.WriteFile(target, []byte("original content\n"), 0644); err != nil {
		t.Fatalf("write: %v", err)
	}

	w := NewFIMWatcher(db, rep, []string{target})
	w.Scan(bg())

	if len(rep.findings) != 0 {
		t.Fatalf("expected 0 findings on cold-start seeding scan, got %d: %+v", len(rep.findings), rep.findings)
	}
}

func TestFIMWatcher_DetectsModification(t *testing.T) {
	db := testDB(t)
	rep := &fakeReporter{}
	dir := t.TempDir()
	target := filepath.Join(dir, "watched.conf")
	if err := os.WriteFile(target, []byte("original content\n"), 0644); err != nil {
		t.Fatalf("write: %v", err)
	}

	w := NewFIMWatcher(db, rep, []string{target})
	w.Scan(bg()) // seed baseline silently

	if err := os.WriteFile(target, []byte("tampered content\n"), 0644); err != nil {
		t.Fatalf("rewrite: %v", err)
	}
	rep.reset()
	w.Scan(bg())

	got := rep.byChange("modified")
	if len(got) != 1 {
		t.Fatalf("expected exactly 1 'modified' finding, got %d: %+v", len(got), rep.findings)
	}
	if got[0].Type != database.IncidentFIMChange {
		t.Errorf("expected type %s, got %s", database.IncidentFIMChange, got[0].Type)
	}
	if got[0].Subject != target {
		t.Errorf("expected subject %s, got %s", target, got[0].Subject)
	}

	// Re-scanning with no further change must not re-fire.
	rep.reset()
	w.Scan(bg())
	if len(rep.findings) != 0 {
		t.Fatalf("expected 0 findings on stable re-scan, got %d: %+v", len(rep.findings), rep.findings)
	}
}

func TestFIMWatcher_DetectsCreationAfterFirstScan(t *testing.T) {
	db := testDB(t)
	rep := &fakeReporter{}
	dir := t.TempDir()
	target := filepath.Join(dir, "new-file.conf")
	// Target does not exist yet at the time of the first (seeding) scan.

	w := NewFIMWatcher(db, rep, []string{target})
	w.Scan(bg()) // first scan: tracks the non-existent path silently
	if len(rep.findings) != 0 {
		t.Fatalf("expected 0 findings on cold-start seeding scan, got %d", len(rep.findings))
	}

	if err := os.WriteFile(target, []byte("i am new\n"), 0644); err != nil {
		t.Fatalf("write: %v", err)
	}
	rep.reset()
	w.Scan(bg())

	got := rep.byChange("created")
	if len(got) != 1 {
		t.Fatalf("expected exactly 1 'created' finding, got %d: %+v", len(got), rep.findings)
	}
}

func TestFIMWatcher_DetectsDeletion(t *testing.T) {
	db := testDB(t)
	rep := &fakeReporter{}
	dir := t.TempDir()
	target := filepath.Join(dir, "will-be-deleted.conf")
	if err := os.WriteFile(target, []byte("temporary\n"), 0644); err != nil {
		t.Fatalf("write: %v", err)
	}

	w := NewFIMWatcher(db, rep, []string{target})
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

func TestFIMWatcher_CriticalEscalationForShadow(t *testing.T) {
	db := testDB(t)
	rep := &fakeReporter{}
	dir := t.TempDir()
	// Simulate /etc/shadow at a synthetic path but exercise the escalation
	// logic directly via report(), since criticalFIMPaths is keyed by the
	// real absolute path "/etc/shadow" -- this test asserts the mapping
	// itself is wired correctly without touching the real filesystem.
	target := filepath.Join(dir, "shadow-lookalike")
	if err := os.WriteFile(target, []byte("x\n"), 0600); err != nil {
		t.Fatalf("write: %v", err)
	}

	w := NewFIMWatcher(db, rep, []string{"/etc/shadow"})
	// Can't actually write to /etc/shadow in a test; instead verify the
	// criticalFIMPaths table itself flags it, and that scanning a
	// non-existent /etc/shadow-like path with that exact key would report
	// Critical=true when a change fires. We simulate by calling report
	// directly, which is what scanOne delegates to.
	w.report("/etc/shadow", "modified", fileMeta{Exists: true, Hash: "a"}, fileMeta{Exists: true, Hash: "b"})
	if len(rep.findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(rep.findings))
	}
	if !rep.findings[0].Critical {
		t.Errorf("expected Critical=true for /etc/shadow change, got false")
	}
}
