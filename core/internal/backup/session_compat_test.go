package backup

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"vanguard/core/internal/database"
)

// A backup never contains sessions, so restoring cannot resurrect a token that
// was revoked (or issued) after the backup was taken; everyone signs in again.
func TestBackupExcludesSessions_RestoreInvalidatesAllTokens(t *testing.T) {
	dir := t.TempDir()
	db := openDB(t, filepath.Join(dir, "live.db"))
	seed(t, db)
	var u database.User
	db.First(&u)
	sid, _ := database.NewSessionID()
	if err := db.CreateSession(&database.Session{ID: sid, UserID: u.ID, ExpiresAt: time.Now().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(dir, "backups")
	name, m := mustCreate(t, db, root, CreateOptions{Actor: "admin"})
	if m.Tables["sessions"] != 0 {
		t.Fatalf("the backup must carry no sessions, manifest says %d", m.Tables["sessions"])
	}
	if rep, err := Verify(root, name); err != nil || !rep.Valid {
		t.Fatalf("%v %+v", err, rep)
	}
	if n := tableCount(t, db, "sessions"); n != 1 {
		t.Fatalf("creating a backup must not touch the live sessions, got %d", n)
	}
	target := filepath.Join(dir, "restored", "vanguard.db")
	_ = os.MkdirAll(filepath.Dir(target), 0o700)
	if _, err := Restore(RestoreOptions{Root: root, Name: name, LivePath: target, Confirm: true, Actor: "cli:root", Now: tNow}); err != nil {
		t.Fatal(err)
	}
	r := openDB(t, target)
	if n := tableCount(t, r, "sessions"); n != 0 {
		t.Fatalf("restored database has %d sessions", n)
	}
	if _, err := r.ActiveSession(sid, u.ID, time.Now()); err == nil {
		t.Fatal("a session from before the restore must not be valid after it")
	}
}
