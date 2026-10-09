package backup

import (
	"database/sql"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"vanguard/core/internal/database"
)

// RestoreOptions configures Restore.
type RestoreOptions struct {
	Root     string // backups root
	Name     string // backup directory name
	LivePath string // the live database file to replace
	// Confirm must be true for any change. Without it Restore only validates
	// and returns a plan (a preview), and never touches the live database.
	Confirm bool
	Actor   string
	Now     time.Time

	// beforeActivate is a test hook run after the live database has been
	// set aside and before the candidate is moved into place.
	beforeActivate func() error
	// afterCopy is a test hook run on the candidate copy before validation.
	afterCopy func(candidate string) error
}

// Plan describes what a restore would do / did.
type Plan struct {
	Report         *Report          `json:"report"`
	LiveExists     bool             `json:"live_exists"`
	LiveTables     map[string]int64 `json:"live_tables,omitempty"`
	BackupTables   map[string]int64 `json:"backup_tables"`
	Applied        bool             `json:"applied"`
	PreRestoreName string           `json:"pre_restore_name,omitempty"` // base name of the preserved previous database
	Warnings       []string         `json:"warnings,omitempty"`
}

// Restore validates a backup and, only with Confirm, replaces the live
// database with it. Safety properties:
//   - the backup must pass Verify (checksum, integrity, row counts,
//     schema compatibility) before anything else happens;
//   - the live database must not be in use (exclusive lock probe);
//   - the candidate is a COPY, validated and migrated on its own before
//     activation, so an unusable backup cannot replace a working database;
//   - the previous database is preserved (renamed, never deleted) and put
//     back if activation fails;
//   - the restore is recorded in the restored database's audit table.
func Restore(o RestoreOptions) (*Plan, error) {
	now := o.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}
	rep, err := Verify(o.Root, o.Name)
	if err != nil {
		return nil, err
	}
	plan := &Plan{Report: rep, BackupTables: map[string]int64{}}
	if rep.Manifest != nil {
		plan.BackupTables = rep.Manifest.Tables
	}
	if !rep.Valid {
		return plan, fmt.Errorf("%w: %s", ErrInvalidBackup, strings.Join(rep.Problems, "; "))
	}
	if st, err := os.Stat(o.LivePath); err == nil && !st.IsDir() {
		plan.LiveExists = true
		if tabs, ierr := liveCounts(o.LivePath); ierr == nil {
			plan.LiveTables = tabs
		} else {
			plan.Warnings = append(plan.Warnings, "could not read the live database for comparison")
		}
		if !rep.Manifest.UsersIncluded {
			plan.Warnings = append(plan.Warnings, "this backup has no user accounts: after the restore nobody can log in until a new admin is created")
		}
	}
	if !o.Confirm {
		return plan, nil // preview: nothing was touched
	}

	if plan.LiveExists {
		if err := ensureNotInUse(o.LivePath); err != nil {
			return plan, err
		}
	}

	stamp := now.UTC().Format("20060102T150405.000000000Z")
	src := filepath.Join(o.Root, o.Name, DBFile)
	candidate := o.LivePath + ".restore-" + stamp + ".partial"
	activated := false
	defer func() {
		if !activated {
			_ = os.Remove(candidate)
			_ = os.Remove(candidate + "-wal")
			_ = os.Remove(candidate + "-shm")
		}
	}()

	if err := copyFile(src, candidate); err != nil {
		return plan, fmt.Errorf("could not stage the backup: %w", err)
	}
	if o.afterCopy != nil {
		if err := o.afterCopy(candidate); err != nil {
			return plan, err
		}
	}
	// The staged copy must still be exactly the verified backup.
	sum, _, err := fileSHA256(candidate)
	if err != nil || sum != rep.Manifest.DBSHA256 {
		return plan, fmt.Errorf("%w: staged copy does not match the backup checksum", ErrInvalidBackup)
	}
	info, err := Inspect(candidate)
	if err != nil || info.Integrity != "ok" {
		return plan, fmt.Errorf("%w: staged copy failed its integrity check", ErrInvalidBackup)
	}
	// Prove the upgrade works on the candidate BEFORE touching the live file.
	cdb, err := database.Open(database.Config{Path: candidate})
	if err != nil {
		return plan, fmt.Errorf("%w: schema migration of the backup failed: %v", ErrInvalidBackup, err)
	}
	if sqlDB, e := cdb.DB.DB(); e == nil {
		_, _ = sqlDB.Exec("PRAGMA wal_checkpoint(TRUNCATE)")
		_ = sqlDB.Close()
	}
	_ = os.Remove(candidate + "-wal")
	_ = os.Remove(candidate + "-shm")

	// Set the live database aside (never delete it).
	pre := ""
	if plan.LiveExists {
		pre = o.LivePath + ".pre-restore-" + stamp
		if err := moveWithSidecars(o.LivePath, pre); err != nil {
			return plan, fmt.Errorf("could not preserve the current database; nothing was changed: %w", err)
		}
	}
	rollback := func(cause error) error {
		if pre != "" {
			_ = os.Remove(o.LivePath)
			if rerr := moveWithSidecars(pre, o.LivePath); rerr != nil {
				return fmt.Errorf("%v; ALSO failed to put the previous database back (%v): it is at %s", cause, rerr, filepath.Base(pre))
			}
		}
		return cause
	}
	if o.beforeActivate != nil {
		if err := o.beforeActivate(); err != nil {
			return plan, rollback(err)
		}
	}
	if err := os.Rename(candidate, o.LivePath); err != nil {
		return plan, rollback(fmt.Errorf("could not activate the restored database: %w", err))
	}
	activated = true
	plan.Applied = true
	if pre != "" {
		plan.PreRestoreName = filepath.Base(pre)
	}

	// Record the restore in the database that is now live.
	if ldb, err := database.Open(database.Config{Path: o.LivePath}); err == nil {
		_ = ldb.RecordBackupAudit(&database.BackupAudit{
			At: now, Kind: "restore", Actor: o.Actor, BackupName: o.Name, DBSHA256: rep.Manifest.DBSHA256, Result: "ok",
			Detail: "previous database preserved as " + plan.PreRestoreName,
		})
		if sqlDB, e := ldb.DB.DB(); e == nil {
			_, _ = sqlDB.Exec("PRAGMA wal_checkpoint(TRUNCATE)")
			_ = sqlDB.Close()
		}
	} else {
		plan.Warnings = append(plan.Warnings, "restore completed but the audit entry could not be written")
	}
	return plan, nil
}

func liveCounts(path string) (map[string]int64, error) {
	info, err := Inspect(path) // immutable read; never creates sidecar files
	if err != nil {
		return nil, err
	}
	return info.Tables, nil
}

// ensureNotInUse proves that no other connection has the live database
// open. A plain write lock is NOT enough: in WAL mode an idle daemon holds
// no lock at all. Opening with locking_mode=EXCLUSIVE needs exclusive
// access to the WAL index, which fails while any other process (or
// connection) has the database open, idle or not.
func ensureNotInUse(path string) error {
	d, err := sql.Open("sqlite", path+"?_pragma=busy_timeout(0)&_pragma=locking_mode(EXCLUSIVE)")
	if err != nil {
		return err
	}
	defer closeQuiet(d)
	d.SetMaxOpenConns(1)
	var n int
	if err := d.QueryRow("SELECT COUNT(*) FROM sqlite_master").Scan(&n); err != nil {
		return fmt.Errorf("%w (%v)", ErrInUse, err)
	}
	if _, err := d.Exec("BEGIN IMMEDIATE"); err != nil {
		return fmt.Errorf("%w (%v)", ErrInUse, err)
	}
	_, _ = d.Exec("COMMIT")
	// Fold the write-ahead log into the main file so the file we move is
	// complete on its own.
	_, _ = d.Exec("PRAGMA wal_checkpoint(TRUNCATE)")
	return nil
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer closeQuiet(in)
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, io.LimitReader(in, MaxBackupBytes+1)); err != nil {
		closeQuiet(out)
		return err
	}
	if err := out.Sync(); err != nil {
		closeQuiet(out)
		return err
	}
	return out.Close()
}

// moveWithSidecars renames a SQLite file together with its -wal/-shm so a
// half-checkpointed database is never split from its log.
func moveWithSidecars(from, to string) error {
	if err := os.Rename(from, to); err != nil {
		return err
	}
	for _, suf := range []string{"-wal", "-shm"} {
		if _, err := os.Stat(from + suf); err == nil {
			if err := os.Rename(from+suf, to+suf); err != nil && !errors.Is(err, os.ErrNotExist) {
				return err
			}
		}
	}
	return nil
}
