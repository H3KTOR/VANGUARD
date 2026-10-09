package database

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestNewDatabaseFileIsPrivate_ExistingIsNotModified(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permission bits are not meaningful on Windows; run on Linux")
	}
	dir := t.TempDir()
	p := filepath.Join(dir, "new.db")
	old := setUmask(0o022) // a permissive umask must not leak into the database
	defer setUmask(old)
	db, err := Open(Config{Path: p})
	if err != nil {
		t.Fatal(err)
	}
	if m := mustMode(t, p); m != 0o600 {
		t.Fatalf("a new database must be 0600, got %04o", m)
	}
	// SQLite derives the sidecar mode from the main file
	for _, side := range []string{p + "-wal", p + "-shm"} {
		if st, err := os.Stat(side); err == nil && st.Mode().Perm()&0o077 != 0 {
			t.Fatalf("%s is readable by others: %04o", side, st.Mode().Perm())
		}
	}
	db.Close()

	// an existing, deliberately group-readable database is left exactly as it was
	q := filepath.Join(dir, "existing.db")
	if err := os.WriteFile(q, nil, 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(q, 0o640); err != nil {
		t.Fatal(err)
	}
	db2, err := Open(Config{Path: q})
	if err != nil {
		t.Fatal(err)
	}
	db2.Close()
	if m := mustMode(t, q); m != 0o640 {
		t.Fatalf("an existing database's mode must not be changed, got %04o", m)
	}
}

func mustMode(t *testing.T, p string) os.FileMode {
	t.Helper()
	st, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	return st.Mode().Perm()
}

func TestPrepareFile_IgnoresMemoryAndMissingDirectory(t *testing.T) {
	prepareFile(":memory:")
	prepareFile("")
	prepareFile(filepath.Join(t.TempDir(), "no", "such", "dir", "x.db")) // must not panic or create directories
}
