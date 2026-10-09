// Package backup implements VANGUARD's local backup, verification and
// offline restore of its SQLite state (Phase 11).
//
// What a backup is: a directory
//
//	vanguard-backup-<UTC>[-label]/
//	    vanguard.db      a consistent snapshot (SQLite VACUUM INTO)
//	    manifest.json    format/version, creation time, size, SHA-256,
//	                     integrity result, per-table row counts, schema
//	                     fingerprint, whether user accounts are included
//
// What it guarantees: the snapshot is transactionally consistent even
// while the daemon writes; an interrupted backup never appears as a valid
// one (it is built in a *.partial directory and renamed atomically); an
// existing backup is never overwritten.
//
// What it does NOT guarantee: authenticity. The SHA-256 detects accidental
// corruption/truncation, but anyone who can modify the backup can also
// recompute it. The files are not encrypted or signed. Configuration files
// and .env secrets (JWT secret, Telegram token) are never included.
package backup

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	_ "github.com/glebarez/sqlite" // registers the pure-Go "sqlite" driver

	"vanguard/core/internal/database"
)

// Format constants and bounds.
const (
	FormatName     = "vanguard-backup"
	FormatVersion  = 1
	DBFile         = "vanguard.db"
	ManifestFile   = "manifest.json"
	MaxBackupBytes = int64(2) << 30 // 2 GiB per snapshot
	MaxBackups     = 50             // retained backups per directory
	maxManifest    = 1 << 20
)

// Errors.
var (
	ErrExists          = errors.New("a backup with this name already exists (backups are never overwritten)")
	ErrTooLarge        = errors.New("database exceeds the backup size limit")
	ErrTooManyBackups  = errors.New("backup directory already holds the maximum number of backups; remove old ones first")
	ErrInvalidBackup   = errors.New("backup failed validation")
	ErrInvalidName     = errors.New("invalid backup name")
	ErrInUse           = errors.New("the live database is in use; stop VANGUARD before restoring")
	ErrConfirmRequired = errors.New("restore requires explicit confirmation")
)

var nameRE = regexp.MustCompile(`^vanguard-backup-[0-9]{8}T[0-9]{6}Z(-[a-z0-9]{1,16})?$`)
var labelRE = regexp.MustCompile(`^[a-z0-9]{1,16}$`)

// ValidName reports whether s is a well-formed backup directory name. It
// is the only thing allowed to reach the filesystem from an API/CLI name,
// so path separators and ".." can never appear.
func ValidName(s string) bool { return nameRE.MatchString(s) }

// Manifest describes a backup.
type Manifest struct {
	Format            string           `json:"format"`
	Version           int              `json:"version"`
	CreatedAt         string           `json:"created_at"` // UTC, RFC 3339
	DBFile            string           `json:"db_file"`
	DBSizeBytes       int64            `json:"db_size_bytes"`
	DBSHA256          string           `json:"db_sha256"`
	IntegrityCheck    string           `json:"integrity_check"` // result of PRAGMA integrity_check at creation
	Tables            map[string]int64 `json:"tables"`          // row counts
	SchemaFingerprint string           `json:"schema_fingerprint"`
	UsersIncluded     bool             `json:"users_included"`
	Notes             []string         `json:"notes"`
}

// CreateOptions configures Create.
type CreateOptions struct {
	Dir          string // backups root (created 0700 if missing)
	Label        string // optional [a-z0-9]{1,16}
	ExcludeUsers bool   // drop the users table (credential hashes) from the copy
	MaxBytes     int64  // 0 = MaxBackupBytes
	Now          time.Time
	Actor        string // recorded in the audit table
}

func closeQuiet(c io.Closer) { _ = c.Close() }

func dbSize(db *database.DB) (int64, error) {
	sqlDB, err := db.DB.DB()
	if err != nil {
		return 0, err
	}
	var pages, size int64
	if err := sqlDB.QueryRow("PRAGMA page_count").Scan(&pages); err != nil {
		return 0, err
	}
	if err := sqlDB.QueryRow("PRAGMA page_size").Scan(&size); err != nil {
		return 0, err
	}
	return pages * size, nil
}

func countBackups(dir string) int {
	es, _ := os.ReadDir(dir)
	n := 0
	for _, e := range es {
		if e.IsDir() && nameRE.MatchString(e.Name()) {
			n++
		}
	}
	return n
}

// Create writes a consistent snapshot of db into a new backup directory
// and returns its name and manifest. Nothing is overwritten; on any error
// no partial output remains.
func Create(db *database.DB, o CreateOptions) (name string, m *Manifest, err error) {
	now := o.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}
	max := o.MaxBytes
	if max <= 0 {
		max = MaxBackupBytes
	}
	if o.Label != "" && !labelRE.MatchString(o.Label) {
		return "", nil, fmt.Errorf("%w: label must match [a-z0-9]{1,16}", ErrInvalidName)
	}
	if err := os.MkdirAll(o.Dir, 0o700); err != nil {
		return "", nil, fmt.Errorf("cannot prepare backup directory: %w", err)
	}
	if countBackups(o.Dir) >= MaxBackups {
		return "", nil, ErrTooManyBackups
	}
	sz, err := dbSize(db)
	if err != nil {
		return "", nil, fmt.Errorf("cannot size database: %w", err)
	}
	if sz > max {
		return "", nil, fmt.Errorf("%w (%d > %d bytes)", ErrTooLarge, sz, max)
	}

	name = "vanguard-backup-" + now.UTC().Format("20060102T150405Z")
	if o.Label != "" {
		name += "-" + o.Label
	}
	final := filepath.Join(o.Dir, name)
	if _, statErr := os.Stat(final); statErr == nil {
		return "", nil, ErrExists
	}
	tmp := final + ".partial"
	_ = os.RemoveAll(tmp) // stale leftover of OUR OWN interrupted attempt with this exact name
	if err := os.Mkdir(tmp, 0o700); err != nil {
		return "", nil, err
	}
	ok := false
	defer func() {
		if !ok {
			_ = os.RemoveAll(tmp)
		}
	}()

	dbPath := filepath.Join(tmp, DBFile)
	// VACUUM INTO runs in a single read transaction: a consistent snapshot
	// even while other connections write.
	sqlDB, err := db.DB.DB()
	if err != nil {
		return "", nil, err
	}
	if _, err := sqlDB.Exec("VACUUM INTO ?", dbPath); err != nil {
		return "", nil, fmt.Errorf("snapshot failed: %w", err)
	}
	_ = os.Chmod(dbPath, 0o600)

	if o.ExcludeUsers {
		if err := dropUsers(dbPath); err != nil {
			return "", nil, fmt.Errorf("could not exclude user accounts: %w", err)
		}
	}

	info, err := Inspect(dbPath)
	if err != nil {
		return "", nil, fmt.Errorf("snapshot did not validate: %w", err)
	}
	if info.Integrity != "ok" {
		return "", nil, fmt.Errorf("snapshot failed its integrity check: %s", info.Integrity)
	}
	sum, size, err := fileSHA256(dbPath)
	if err != nil {
		return "", nil, err
	}
	m = &Manifest{
		Format: FormatName, Version: FormatVersion, CreatedAt: now.UTC().Format(time.RFC3339), DBFile: DBFile,
		DBSizeBytes: size, DBSHA256: sum, IntegrityCheck: info.Integrity, Tables: info.Tables,
		SchemaFingerprint: info.Fingerprint, UsersIncluded: !o.ExcludeUsers,
		Notes: []string{
			"SHA-256 detects corruption, not authenticity: the backup is neither signed nor encrypted.",
			"Configuration files and .env secrets are not included.",
			"Firewall rules are restored as data; OS-level firewall state is re-applied by VANGUARD at startup.",
		},
	}
	if o.ExcludeUsers {
		m.Notes = append(m.Notes, "User accounts were excluded: after a restore you must create a new admin account.")
	} else {
		m.Notes = append(m.Notes, "Contains user accounts including password hashes: protect this backup like a credential store.")
	}
	mb, _ := json.MarshalIndent(m, "", "  ")
	if err := os.WriteFile(filepath.Join(tmp, ManifestFile), mb, 0o600); err != nil {
		return "", nil, err
	}
	if err := os.Rename(tmp, final); err != nil {
		return "", nil, fmt.Errorf("could not finalize backup: %w", err)
	}
	ok = true
	return name, m, nil
}

func dropUsers(path string) error {
	d, err := sql.Open("sqlite", path)
	if err != nil {
		return err
	}
	defer closeQuiet(d)
	if _, err := d.Exec("DELETE FROM users"); err != nil {
		// A snapshot from before the users table existed has nothing to drop.
		if strings.Contains(err.Error(), "no such table") {
			return nil
		}
		return err
	}
	_, err = d.Exec("VACUUM") // do not leave deleted rows in free pages
	return err
}

func fileSHA256(path string) (string, int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer closeQuiet(f)
	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(h.Sum(nil)), n, nil
}

// DBInfo is what Inspect learns from a database file, read-only.
type DBInfo struct {
	Integrity   string
	Tables      map[string]int64
	Schema      map[string][]string // table -> columns
	Fingerprint string
}

func quoteIdent(s string) string { return `"` + strings.ReplaceAll(s, `"`, `""`) + `"` }

// Inspect opens path strictly read-only and immutable (no WAL/SHM files
// are created, nothing is modified) and reports integrity, row counts and
// schema.
func Inspect(path string) (*DBInfo, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	uri := "file:" + filepath.ToSlash(abs) + "?mode=ro&immutable=1"
	if len(abs) > 1 && abs[1] == ':' { // Windows drive letter => file:/C:/...
		uri = "file:/" + filepath.ToSlash(abs) + "?mode=ro&immutable=1"
	}
	d, err := sql.Open("sqlite", uri)
	if err != nil {
		return nil, err
	}
	defer closeQuiet(d)
	d.SetMaxOpenConns(1)
	return inspectOpen(d)
}

func inspectOpen(d *sql.DB) (*DBInfo, error) {
	info := &DBInfo{Tables: map[string]int64{}, Schema: map[string][]string{}}
	rows, err := d.Query("PRAGMA integrity_check")
	if err != nil {
		return nil, fmt.Errorf("not a readable SQLite database: %w", err)
	}
	var msgs []string
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			closeQuiet(rows)
			return nil, err
		}
		msgs = append(msgs, s)
		if len(msgs) >= 5 {
			break
		}
	}
	closeQuiet(rows)
	info.Integrity = strings.Join(msgs, "; ")

	trs, err := d.Query("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name")
	if err != nil {
		return nil, err
	}
	var tables []string
	for trs.Next() {
		var n string
		if err := trs.Scan(&n); err != nil {
			closeQuiet(trs)
			return nil, err
		}
		tables = append(tables, n)
	}
	closeQuiet(trs)
	var fp strings.Builder
	for _, t := range tables {
		var cnt int64
		if err := d.QueryRow("SELECT COUNT(*) FROM " + quoteIdent(t)).Scan(&cnt); err != nil {
			return nil, fmt.Errorf("cannot read table %s: %w", t, err)
		}
		info.Tables[t] = cnt
		crs, err := d.Query("SELECT name, type FROM pragma_table_info(?)", t)
		if err != nil {
			return nil, err
		}
		var cols []string
		for crs.Next() {
			var cn, ct string
			if err := crs.Scan(&cn, &ct); err != nil {
				closeQuiet(crs)
				return nil, err
			}
			cols = append(cols, cn)
			fmt.Fprintf(&fp, "%s.%s:%s;", t, cn, strings.ToLower(ct))
		}
		closeQuiet(crs)
		sort.Strings(cols)
		info.Schema[t] = cols
	}
	sum := sha256.Sum256([]byte(fp.String()))
	info.Fingerprint = hex.EncodeToString(sum[:])
	return info, nil
}

// ---------------------------------------------------------------------------
// Compatibility with the running application's schema
// ---------------------------------------------------------------------------

var (
	curOnce   sync.Once
	curSchema map[string][]string
	curErr    error
)

// CurrentSchema returns the table/column set the running application
// creates, obtained by migrating a throw-away database.
func CurrentSchema() (map[string][]string, error) {
	curOnce.Do(func() {
		dir, err := os.MkdirTemp("", "vanguard-schema-")
		if err != nil {
			curErr = err
			return
		}
		defer os.RemoveAll(dir)
		p := filepath.Join(dir, "s.db")
		db, err := database.Open(database.Config{Path: p})
		if err != nil {
			curErr = err
			return
		}
		sqlDB, _ := db.DB.DB()
		info, ierr := inspectOpen(sqlDB)
		_ = sqlDB.Close()
		if ierr != nil {
			curErr = ierr
			return
		}
		curSchema = info.Schema
	})
	return curSchema, curErr
}

// Compat compares a database's schema with the running application's.
// Missing tables/columns are fine (the additive migration creates them);
// tables or columns this version does not know mean the file was produced
// by a NEWER VANGUARD, and restoring/using it here is unsupported.
type Compat struct {
	Compatible bool     `json:"compatible"`
	Unknown    []string `json:"unknown_to_this_version,omitempty"`
	WillAdd    []string `json:"will_be_added_by_migration,omitempty"`
}

// CheckCompat evaluates info against the current schema.
func CheckCompat(info *DBInfo) (Compat, error) {
	cur, err := CurrentSchema()
	if err != nil {
		return Compat{}, err
	}
	c := Compat{Compatible: true}
	for t, cols := range info.Schema {
		curCols, ok := cur[t]
		if !ok {
			c.Unknown = append(c.Unknown, "table "+t)
			continue
		}
		have := map[string]bool{}
		for _, x := range curCols {
			have[x] = true
		}
		for _, x := range cols {
			if !have[x] {
				c.Unknown = append(c.Unknown, "column "+t+"."+x)
			}
		}
	}
	for t, curCols := range cur {
		cols, ok := info.Schema[t]
		if !ok {
			c.WillAdd = append(c.WillAdd, "table "+t)
			continue
		}
		have := map[string]bool{}
		for _, x := range cols {
			have[x] = true
		}
		for _, x := range curCols {
			if !have[x] {
				c.WillAdd = append(c.WillAdd, "column "+t+"."+x)
			}
		}
	}
	sort.Strings(c.Unknown)
	sort.Strings(c.WillAdd)
	c.Compatible = len(c.Unknown) == 0
	return c, nil
}

// SchemaWarnings reports whether the live database contains tables or
// columns this version does not know (it was probably written by a newer
// VANGUARD). Used for a startup warning; it never blocks startup.
func SchemaWarnings(db *database.DB) []string {
	sqlDB, err := db.DB.DB()
	if err != nil {
		return nil
	}
	info, err := inspectOpen(sqlDB)
	if err != nil {
		return nil
	}
	c, err := CheckCompat(info)
	if err != nil || c.Compatible {
		return nil
	}
	return c.Unknown
}

// ---------------------------------------------------------------------------
// Verify / List
// ---------------------------------------------------------------------------

// Report is the result of validating a backup. Verify never modifies
// anything.
type Report struct {
	Name     string    `json:"name"`
	Manifest *Manifest `json:"manifest,omitempty"`
	Valid    bool      `json:"valid"`
	Problems []string  `json:"problems"`
	Compat   *Compat   `json:"compat,omitempty"`
}

// Verify validates the named backup under root: manifest, size, SHA-256,
// integrity_check, row counts and schema compatibility.
func Verify(root, name string) (*Report, error) {
	if !ValidName(name) {
		return nil, ErrInvalidName
	}
	r := &Report{Name: name, Problems: []string{}}
	dir := filepath.Join(root, name)
	st, err := os.Stat(dir)
	if err != nil || !st.IsDir() {
		r.Problems = append(r.Problems, "backup not found")
		return r, nil
	}
	mf, err := os.Open(filepath.Join(dir, ManifestFile))
	if err != nil {
		r.Problems = append(r.Problems, "manifest missing")
		return r, nil
	}
	mb, err := io.ReadAll(io.LimitReader(mf, maxManifest+1))
	closeQuiet(mf)
	if err != nil || len(mb) > maxManifest {
		r.Problems = append(r.Problems, "manifest unreadable or too large")
		return r, nil
	}
	var m Manifest
	if err := json.Unmarshal(mb, &m); err != nil {
		r.Problems = append(r.Problems, "manifest is not valid JSON")
		return r, nil
	}
	r.Manifest = &m
	if m.Format != FormatName {
		r.Problems = append(r.Problems, "not a vanguard-backup manifest")
	}
	if m.Version != FormatVersion {
		r.Problems = append(r.Problems, fmt.Sprintf("unsupported backup format version %d (this build supports %d)", m.Version, FormatVersion))
	}
	if m.DBFile != DBFile {
		r.Problems = append(r.Problems, "manifest names an unexpected database file")
	}
	if len(r.Problems) > 0 {
		return r, nil
	}
	dbPath := filepath.Join(dir, DBFile)
	fst, err := os.Stat(dbPath)
	if err != nil || fst.IsDir() {
		r.Problems = append(r.Problems, "database file missing")
		return r, nil
	}
	if fst.Size() > MaxBackupBytes {
		r.Problems = append(r.Problems, "database file exceeds the size limit")
		return r, nil
	}
	if fst.Size() != m.DBSizeBytes {
		r.Problems = append(r.Problems, fmt.Sprintf("size mismatch: file has %d bytes, manifest says %d (truncated or modified)", fst.Size(), m.DBSizeBytes))
		return r, nil
	}
	sum, _, err := fileSHA256(dbPath)
	if err != nil {
		r.Problems = append(r.Problems, "database file unreadable")
		return r, nil
	}
	if sum != m.DBSHA256 {
		r.Problems = append(r.Problems, "SHA-256 mismatch: the database file was modified or corrupted after the backup was made")
		return r, nil
	}
	info, err := Inspect(dbPath)
	if err != nil {
		r.Problems = append(r.Problems, "database is not a readable SQLite file")
		return r, nil
	}
	if info.Integrity != "ok" {
		r.Problems = append(r.Problems, "SQLite integrity check failed: "+truncate(info.Integrity, 120))
	}
	for t, n := range m.Tables {
		if got, ok := info.Tables[t]; !ok || got != n {
			r.Problems = append(r.Problems, fmt.Sprintf("row count for table %s differs from the manifest", t))
		}
	}
	c, err := CheckCompat(info)
	if err != nil {
		r.Problems = append(r.Problems, "could not determine the current schema")
		return r, nil
	}
	r.Compat = &c
	if !c.Compatible {
		r.Problems = append(r.Problems, "incompatible schema: "+strings.Join(c.Unknown, ", ")+" (produced by a newer VANGUARD; downgrade is unsupported)")
	}
	r.Valid = len(r.Problems) == 0
	return r, nil
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// Entry is a lightweight listing row (no deep verification).
type Entry struct {
	Name          string `json:"name"`
	CreatedAt     string `json:"created_at,omitempty"`
	DBSizeBytes   int64  `json:"db_size_bytes,omitempty"`
	DBSHA256      string `json:"db_sha256,omitempty"`
	UsersIncluded bool   `json:"users_included"`
	ManifestOK    bool   `json:"manifest_readable"`
}

// List returns up to 100 backups, newest first. Leftover *.partial
// directories are not backups and are never listed.
func List(root string) ([]Entry, error) {
	es, err := os.ReadDir(root)
	if err != nil {
		if os.IsNotExist(err) {
			return []Entry{}, nil
		}
		return nil, err
	}
	var out []Entry
	for _, e := range es {
		if !e.IsDir() || !nameRE.MatchString(e.Name()) {
			continue
		}
		en := Entry{Name: e.Name()}
		if b, err := os.ReadFile(filepath.Join(root, e.Name(), ManifestFile)); err == nil && len(b) <= maxManifest {
			var m Manifest
			if json.Unmarshal(b, &m) == nil && m.Format == FormatName {
				en.CreatedAt, en.DBSizeBytes, en.DBSHA256, en.UsersIncluded, en.ManifestOK = m.CreatedAt, m.DBSizeBytes, m.DBSHA256, m.UsersIncluded, true
			}
		}
		out = append(out, en)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name > out[j].Name })
	if len(out) > 100 {
		out = out[:100]
	}
	if out == nil {
		out = []Entry{}
	}
	return out, nil
}

// InspectLive is Inspect for a database that another process (the running
// daemon) may be using: it opens read-only WITHOUT the immutable flag, so the
// write-ahead log is honoured and the numbers describe the current state. It
// never writes to the database or its schema. If the file's directory is not
// writable the sidecar index may be unavailable and the call can fail; callers
// report that as "could not inspect", not as a problem with the database.
func InspectLive(path string) (*DBInfo, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	uri := "file:" + filepath.ToSlash(abs) + "?mode=ro"
	if len(abs) > 1 && abs[1] == ':' {
		uri = "file:/" + filepath.ToSlash(abs) + "?mode=ro"
	}
	d, err := sql.Open("sqlite", uri)
	if err != nil {
		return nil, err
	}
	defer closeQuiet(d)
	d.SetMaxOpenConns(1)
	return inspectOpen(d)
}
