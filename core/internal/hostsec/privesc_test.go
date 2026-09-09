package hostsec

import (
	"os"
	"path/filepath"
	"testing"

	"vanguard/core/internal/database"
)

func newPrivEscRoot(t *testing.T, passwd, group, sudoers string) string {
	t.Helper()
	root := t.TempDir()
	mustMkdirAll(t, filepath.Join(root, "etc", "sudoers.d"))
	mustWriteFile(t, filepath.Join(root, "etc", "passwd"), passwd)
	mustWriteFile(t, filepath.Join(root, "etc", "group"), group)
	mustWriteFile(t, filepath.Join(root, "etc", "sudoers"), sudoers)
	return root
}

func TestPrivEscDetector_FirstScanIsSilent(t *testing.T) {
	db := testDB(t)
	rep := &fakeReporter{}
	root := newPrivEscRoot(t, basePasswd, baseGroup, "root ALL=(ALL:ALL) ALL\n%sudo ALL=(ALL:ALL) ALL\n")

	p := NewPrivEscDetector(db, rep).WithRoot(root)
	p.Scan(bg())

	if len(rep.findings) != 0 {
		t.Fatalf("expected 0 findings on cold-start seeding scan, got %d: %+v", len(rep.findings), rep.findings)
	}
}

func TestPrivEscDetector_DetectsUID0Account(t *testing.T) {
	db := testDB(t)
	rep := &fakeReporter{}
	root := newPrivEscRoot(t, basePasswd, baseGroup, "root ALL=(ALL:ALL) ALL\n")

	p := NewPrivEscDetector(db, rep).WithRoot(root)
	p.Scan(bg()) // seed

	mustWriteFile(t, filepath.Join(root, "etc", "passwd"), basePasswd+"backdoor:x:0:0:added by attacker:/root:/bin/bash\n")
	rep.reset()
	p.Scan(bg())

	got := rep.byChange("uid0_account")
	if len(got) != 1 {
		t.Fatalf("expected exactly 1 'uid0_account' finding, got %d: %+v", len(got), rep.findings)
	}
	if !got[0].Critical {
		t.Errorf("expected Critical=true for a rogue UID-0 account")
	}
	if got[0].Type != database.IncidentPrivilegeEscalation {
		t.Errorf("expected type %s, got %s", database.IncidentPrivilegeEscalation, got[0].Type)
	}
}

func TestPrivEscDetector_DetectsPrivilegedGroupJoin(t *testing.T) {
	db := testDB(t)
	rep := &fakeReporter{}
	root := newPrivEscRoot(t, basePasswd, baseGroup, "root ALL=(ALL:ALL) ALL\n")

	p := NewPrivEscDetector(db, rep).WithRoot(root)
	p.Scan(bg()) // seed (sudo group already has alice)

	mustWriteFile(t, filepath.Join(root, "etc", "group"), "root:x:0:\nsudo:x:27:alice,mallory\n")
	rep.reset()
	p.Scan(bg())

	got := rep.byChange("privileged_group_join")
	if len(got) != 1 {
		t.Fatalf("expected exactly 1 'privileged_group_join' finding, got %d: %+v", len(got), rep.findings)
	}
	if got[0].Subject != "mallory" {
		t.Errorf("expected subject 'mallory', got %q", got[0].Subject)
	}
}

func TestPrivEscDetector_DetectsDangerousSudoRule(t *testing.T) {
	db := testDB(t)
	rep := &fakeReporter{}
	root := newPrivEscRoot(t, basePasswd, baseGroup, "root ALL=(ALL:ALL) ALL\n%sudo ALL=(ALL:ALL) ALL\n")

	p := NewPrivEscDetector(db, rep).WithRoot(root)
	p.Scan(bg()) // seed

	f, err := os.OpenFile(filepath.Join(root, "etc", "sudoers"), os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		t.Fatalf("open for append: %v", err)
	}
	if _, err := f.WriteString("alice ALL=(ALL) NOPASSWD: ALL\n"); err != nil {
		t.Fatalf("append: %v", err)
	}
	f.Close()

	rep.reset()
	p.Scan(bg())

	got := rep.byChange("dangerous_sudo_rule")
	if len(got) != 1 {
		t.Fatalf("expected exactly 1 'dangerous_sudo_rule' finding, got %d: %+v", len(got), rep.findings)
	}
}

func TestPrivEscDetector_SudoGroupRuleIsNotFlaggedAsDangerous(t *testing.T) {
	// A standard "%sudo ALL=(ALL:ALL) ALL" rule is expected/normal and
	// must never be flagged, even though it matches "ALL=(ALL".
	db := testDB(t)
	rep := &fakeReporter{}
	root := newPrivEscRoot(t, basePasswd, baseGroup, "root ALL=(ALL:ALL) ALL\n%sudo ALL=(ALL:ALL) ALL\n%wheel ALL=(ALL:ALL) ALL\n")

	p := NewPrivEscDetector(db, rep).WithRoot(root)
	p.Scan(bg()) // seed
	rep.reset()
	p.Scan(bg()) // stable re-scan, nothing should have changed

	if got := rep.byChange("dangerous_sudo_rule"); len(got) != 0 {
		t.Fatalf("expected 0 'dangerous_sudo_rule' findings for standard %%sudo/%%wheel/root rules, got %d: %+v", len(got), got)
	}
}
