package hostsec

import (
	"os"
	"path/filepath"
	"testing"

	"vanguard/core/internal/database"
)

func newAccountRoot(t *testing.T, passwd, group string) string {
	t.Helper()
	root := t.TempDir()
	mustMkdirAll(t, filepath.Join(root, "etc"))
	mustWriteFile(t, filepath.Join(root, "etc", "passwd"), passwd)
	mustWriteFile(t, filepath.Join(root, "etc", "group"), group)
	return root
}

const basePasswd = "root:x:0:0:root:/root:/bin/bash\n" +
	"alice:x:1000:1000:Alice:/home/alice:/bin/bash\n"
const baseGroup = "root:x:0:\n" +
	"sudo:x:27:alice\n"

func TestAccountDetector_FirstScanIsSilent(t *testing.T) {
	db := testDB(t)
	rep := &fakeReporter{}
	root := newAccountRoot(t, basePasswd, baseGroup)

	a := NewAccountDetector(db, rep).WithRoot(root)
	a.Scan(bg())

	if len(rep.findings) != 0 {
		t.Fatalf("expected 0 findings on cold-start seeding scan, got %d: %+v", len(rep.findings), rep.findings)
	}
}

func TestAccountDetector_DetectsNewUser(t *testing.T) {
	db := testDB(t)
	rep := &fakeReporter{}
	root := newAccountRoot(t, basePasswd, baseGroup)

	a := NewAccountDetector(db, rep).WithRoot(root)
	a.Scan(bg()) // seed

	mustWriteFile(t, filepath.Join(root, "etc", "passwd"), basePasswd+"backdoor:x:1001:1001:added by attacker:/home/backdoor:/bin/bash\n")
	rep.reset()
	a.Scan(bg())

	got := rep.byChange("user_created")
	if len(got) != 1 {
		t.Fatalf("expected exactly 1 'user_created' finding, got %d: %+v", len(got), rep.findings)
	}
	if got[0].Subject != "backdoor" {
		t.Errorf("expected subject 'backdoor', got %q", got[0].Subject)
	}
	if got[0].Type != database.IncidentAccountChange {
		t.Errorf("expected type %s, got %s", database.IncidentAccountChange, got[0].Type)
	}
}

func TestAccountDetector_DetectsDeletedUser(t *testing.T) {
	db := testDB(t)
	rep := &fakeReporter{}
	root := newAccountRoot(t, basePasswd, baseGroup)

	a := NewAccountDetector(db, rep).WithRoot(root)
	a.Scan(bg()) // seed

	mustWriteFile(t, filepath.Join(root, "etc", "passwd"), "root:x:0:0:root:/root:/bin/bash\n")
	rep.reset()
	a.Scan(bg())

	got := rep.byChange("user_deleted")
	if len(got) != 1 {
		t.Fatalf("expected exactly 1 'user_deleted' finding, got %d: %+v", len(got), rep.findings)
	}
	if got[0].Subject != "alice" {
		t.Errorf("expected subject 'alice', got %q", got[0].Subject)
	}
}

func TestAccountDetector_DetectsUIDChange(t *testing.T) {
	db := testDB(t)
	rep := &fakeReporter{}
	root := newAccountRoot(t, basePasswd, baseGroup)

	a := NewAccountDetector(db, rep).WithRoot(root)
	a.Scan(bg()) // seed

	mustWriteFile(t, filepath.Join(root, "etc", "passwd"),
		"root:x:0:0:root:/root:/bin/bash\n"+
			"alice:x:0:1000:Alice:/home/alice:/bin/bash\n") // alice UID changed to 0!
	rep.reset()
	a.Scan(bg())

	got := rep.byChange("uid_changed")
	if len(got) != 1 {
		t.Fatalf("expected exactly 1 'uid_changed' finding, got %d: %+v", len(got), rep.findings)
	}
}

func TestAccountDetector_DetectsGroupMemberAdded(t *testing.T) {
	db := testDB(t)
	rep := &fakeReporter{}
	root := newAccountRoot(t, basePasswd, baseGroup)

	a := NewAccountDetector(db, rep).WithRoot(root)
	a.Scan(bg()) // seed

	mustWriteFile(t, filepath.Join(root, "etc", "group"), "root:x:0:\nsudo:x:27:alice,backdoor\n")
	rep.reset()
	a.Scan(bg())

	got := rep.byChange("group_member_added")
	if len(got) != 1 {
		t.Fatalf("expected exactly 1 'group_member_added' finding, got %d: %+v", len(got), rep.findings)
	}
	added, _ := got[0].Details["added_members"].([]string)
	if len(added) != 1 || added[0] != "backdoor" {
		t.Errorf("expected added_members=[backdoor], got %+v", got[0].Details["added_members"])
	}
}

func TestAccountDetector_EmptyPasswdGuardSkipsDeletionDiff(t *testing.T) {
	// Regression test for the empty-map-guard bugfix: if /etc/passwd is
	// unreadable/empty on a later scan, the detector must NOT report every
	// previously-known user as deleted.
	db := testDB(t)
	rep := &fakeReporter{}
	root := newAccountRoot(t, basePasswd, baseGroup)

	a := NewAccountDetector(db, rep).WithRoot(root)
	a.Scan(bg()) // seed with root+alice known

	// Simulate an unreadable passwd file by removing it entirely.
	if err := os.Remove(filepath.Join(root, "etc", "passwd")); err != nil {
		t.Fatalf("remove passwd: %v", err)
	}
	rep.reset()
	a.Scan(bg())

	if got := rep.byChange("user_deleted"); len(got) != 0 {
		t.Fatalf("expected 0 'user_deleted' findings when /etc/passwd is unreadable, got %d: %+v", len(got), got)
	}
}
