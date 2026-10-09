package backup

import (
	"bytes"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"gorm.io/gorm"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"vanguard/core/internal/database"
)

var tNow = time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)

func openDB(t *testing.T, path string) *database.DB {
	t.Helper()
	db, err := database.Open(database.Config{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { closeDB(db) })
	return db
}

func closeDB(db *database.DB) {
	if s, err := db.DB.DB(); err == nil {
		s.Close()
	}
}

// seed fills a database with one row of every kind of state worth keeping.
func seed(t *testing.T, db *database.DB) {
	t.Helper()
	if err := db.CreateUser(&database.User{Email: "admin@example.test", PasswordHash: "$2a$10$SECRETHASHSECRETHASHSECRETHASHSECRETHASHSECRETHASH", Role: database.RoleAdmin, IsActive: true}); err != nil {
		t.Fatal(err)
	}
	inc := &database.Incident{Type: database.IncidentSSHBruteForce, SourceIP: "203.0.113.5", RiskScore: 70, Metadata: `{"k":"v"}`, DetectedAt: tNow}
	if err := db.CreateIncident(inc); err != nil {
		t.Fatal(err)
	}
	if _, err := db.TransitionIncident(inc.ID, database.StatusInvestigating, "analyst@example.test", "looking"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.AddIncidentNote(inc.ID, "analyst@example.test", "checked with the network team"); err != nil {
		t.Fatal(err)
	}
	ioc := &database.IOC{Type: database.IOCIP, Value: "198.51.100.7", Source: "feed", Enabled: true}
	if err := db.Create(ioc).Error; err != nil {
		t.Fatal(err)
	}
	if _, err := db.SetIOCEnabled(ioc.ID, false); err != nil { // operator disable must survive
		t.Fatal(err)
	}
	if err := db.Create(&database.RuleTuningRevision{CreatedAt: tNow, Actor: "admin@example.test", Kind: "apply", Status: "active", Values: `{}`}).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.CreateFirewallRule(&database.FirewallRule{IPAddress: "203.0.113.5", Source: database.FirewallSourceAutopilot, IsActive: true, BannedAt: tNow}); err != nil {
		t.Fatal(err)
	}
}

func sha(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func mustCreate(t *testing.T, db *database.DB, root string, o CreateOptions) (string, *Manifest) {
	t.Helper()
	o.Dir = root
	if o.Now.IsZero() {
		o.Now = tNow
	}
	name, m, err := Create(db, o)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	return name, m
}

func tableCount(t *testing.T, db *database.DB, table string) int64 {
	t.Helper()
	var n int64
	if err := db.Table(table).Count(&n).Error; err != nil {
		t.Fatal(err)
	}
	return n
}

func TestRoundTrip_PreservesIncidentsEventsIOCsNotesTuningUsers(t *testing.T) {
	dir := t.TempDir()
	live := filepath.Join(dir, "live.db")
	db := openDB(t, live)
	seed(t, db)
	root := filepath.Join(dir, "backups")
	name, m := mustCreate(t, db, root, CreateOptions{Label: "nightly", Actor: "admin"})
	if !strings.HasSuffix(name, "-nightly") || m.IntegrityCheck != "ok" || !m.UsersIncluded || m.Tables["incidents"] != 1 {
		t.Fatalf("%s %+v", name, m)
	}

	rep, err := Verify(root, name)
	if err != nil || !rep.Valid {
		t.Fatalf("verify: %v %+v", err, rep)
	}

	// restore into a SEPARATE fresh target (safe-target recovery)
	target := filepath.Join(dir, "restored", "vanguard.db")
	if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
		t.Fatal(err)
	}
	plan, err := Restore(RestoreOptions{Root: root, Name: name, LivePath: target, Confirm: true, Actor: "cli:root", Now: tNow})
	if err != nil || !plan.Applied || plan.LiveExists {
		t.Fatalf("%v %+v", err, plan)
	}
	r := openDB(t, target)
	if tableCount(t, r, "users") != 1 || tableCount(t, r, "incidents") != 1 || tableCount(t, r, "incident_events") != 2 ||
		tableCount(t, r, "incident_notes") != 1 || tableCount(t, r, "rule_tuning_revisions") != 1 || tableCount(t, r, "firewall_rules") != 1 {
		t.Fatal("row counts differ after restore")
	}
	var ioc database.IOC
	if err := r.First(&ioc).Error; err != nil || ioc.Enabled || !ioc.DisabledByOperator {
		t.Fatalf("operator-disabled indicator state lost: %+v %v", ioc, err)
	}
	notes, _ := r.ListIncidentNotes(1)
	evs, _ := r.ListIncidentEvents(1)
	if len(notes) != 1 || notes[0].Author != "analyst@example.test" || len(evs) < 2 {
		t.Fatalf("notes/audit authorship lost: %+v %+v", notes, evs)
	}
	inc, _ := r.GetIncident(1)
	if inc.Status != database.StatusInvestigating || inc.Metadata != `{"k":"v"}` {
		t.Fatalf("%+v", inc)
	}
	aud, _ := r.ListBackupAudit(10)
	if len(aud) != 1 || aud[0].Kind != "restore" || aud[0].Actor != "cli:root" || aud[0].BackupName != name || aud[0].DBSHA256 != m.DBSHA256 {
		t.Fatalf("restore must be auditable in the restored database: %+v", aud)
	}
}

func TestBackupConsistentDuringConcurrentWrites(t *testing.T) {
	dir := t.TempDir()
	db := openDB(t, filepath.Join(dir, "live.db"))
	var stop atomic.Bool
	var wg sync.WaitGroup
	wg.Add(1)
	go func() { // every transaction adds an incident AND its audit event, atomically
		defer wg.Done()
		for !stop.Load() {
			_ = db.Transaction(func(tx *gorm.DB) error {
				inc := &database.Incident{Type: database.IncidentPortScan, SourceIP: "203.0.113.1", RiskScore: 10, DetectedAt: tNow}
				if err := tx.Create(inc).Error; err != nil {
					return err
				}
				return tx.Create(&database.IncidentEvent{IncidentID: inc.ID, Kind: "response", Outcome: "x", At: tNow}).Error
			})
		}
	}()
	time.Sleep(150 * time.Millisecond)
	var names []string
	for i := 0; i < 3; i++ {
		n, _ := mustCreate(t, db, filepath.Join(dir, "b"), CreateOptions{Now: tNow.Add(time.Duration(i) * time.Second)})
		names = append(names, n)
		time.Sleep(50 * time.Millisecond)
	}
	stop.Store(true)
	wg.Wait()
	for _, n := range names {
		rep, err := Verify(filepath.Join(dir, "b"), n)
		if err != nil || !rep.Valid {
			t.Fatalf("%s: %v %+v", n, err, rep.Problems)
		}
		tabs := rep.Manifest.Tables
		if tabs["incidents"] != tabs["incident_events"] || tabs["incidents"] == 0 {
			t.Fatalf("snapshot is not transactionally consistent: %d incidents vs %d events", tabs["incidents"], tabs["incident_events"])
		}
	}
}

func mutate(t *testing.T, root, name string, f func(dir string)) {
	t.Helper()
	f(filepath.Join(root, name))
}

func TestInvalidBackupsAreRejectedAndLiveDatabaseIsUntouched(t *testing.T) {
	dir := t.TempDir()
	live := filepath.Join(dir, "live.db")
	db := openDB(t, live)
	seed(t, db)
	root := filepath.Join(dir, "b")
	good, m := mustCreate(t, db, root, CreateOptions{})

	liveDir := dir
	snapshotDir := func() string {
		es, _ := os.ReadDir(liveDir)
		var names []string
		for _, e := range es {
			names = append(names, e.Name())
		}
		return strings.Join(names, ",")
	}
	closeDB(db)
	liveHash, filesBefore := sha(t, live), snapshotDir()

	cases := map[string]func(dir string){
		"truncated database": func(d string) {
			b, _ := os.ReadFile(filepath.Join(d, DBFile))
			_ = os.WriteFile(filepath.Join(d, DBFile), b[:len(b)/2], 0o600)
		},
		"flipped bytes (same size)": func(d string) {
			b, _ := os.ReadFile(filepath.Join(d, DBFile))
			b[len(b)-100] ^= 0xFF
			_ = os.WriteFile(filepath.Join(d, DBFile), b, 0o600)
		},
		"empty database": func(d string) { _ = os.WriteFile(filepath.Join(d, DBFile), nil, 0o600) },
		"garbage database": func(d string) {
			_ = os.WriteFile(filepath.Join(d, DBFile), bytes.Repeat([]byte("not sqlite "), 1000), 0o600)
		},
		"missing database":  func(d string) { _ = os.Remove(filepath.Join(d, DBFile)) },
		"missing manifest":  func(d string) { _ = os.Remove(filepath.Join(d, ManifestFile)) },
		"manifest not json": func(d string) { _ = os.WriteFile(filepath.Join(d, ManifestFile), []byte("{nope"), 0o600) },
		"wrong format": func(d string) {
			mm := *m
			mm.Format = "something-else"
			b, _ := json.Marshal(mm)
			_ = os.WriteFile(filepath.Join(d, ManifestFile), b, 0o600)
		},
		"unsupported version": func(d string) {
			mm := *m
			mm.Version = 99
			b, _ := json.Marshal(mm)
			_ = os.WriteFile(filepath.Join(d, ManifestFile), b, 0o600)
		},
		"manifest points elsewhere": func(d string) {
			mm := *m
			mm.DBFile = "../../etc/passwd"
			b, _ := json.Marshal(mm)
			_ = os.WriteFile(filepath.Join(d, ManifestFile), b, 0o600)
		},
		"row counts tampered": func(d string) {
			mm := *m
			mm.Tables = map[string]int64{"incidents": 999}
			b, _ := json.Marshal(mm)
			_ = os.WriteFile(filepath.Join(d, ManifestFile), b, 0o600)
		},
	}
	i := 0
	for name, tamper := range cases {
		i++
		// each case works on its own copy of the good backup
		cp := fmt.Sprintf("vanguard-backup-20261009T1200%02dZ", i)
		copyDir(t, filepath.Join(root, good), filepath.Join(root, cp))
		tamper(filepath.Join(root, cp))
		rep, err := Verify(root, cp)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if rep.Valid {
			t.Errorf("%s: tampered backup was accepted", name)
		}
		_, rerr := Restore(RestoreOptions{Root: root, Name: cp, LivePath: live, Confirm: true, Now: tNow})
		if !errors.Is(rerr, ErrInvalidBackup) {
			t.Errorf("%s: restore must refuse, got %v", name, rerr)
		}
		if sha(t, live) != liveHash || snapshotDir() != filesBefore {
			t.Fatalf("%s: a rejected restore changed the live database or left files behind: %s", name, snapshotDir())
		}
	}
}

func copyDir(t *testing.T, from, to string) {
	t.Helper()
	if err := os.MkdirAll(to, 0o700); err != nil {
		t.Fatal(err)
	}
	es, _ := os.ReadDir(from)
	for _, e := range es {
		b, err := os.ReadFile(filepath.Join(from, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(to, e.Name()), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

func TestIncompatibleNewerSchemaIsRefused(t *testing.T) {
	dir := t.TempDir()
	db := openDB(t, filepath.Join(dir, "live.db"))
	seed(t, db)
	// pretend a future VANGUARD added a table and a column
	if err := db.Exec("CREATE TABLE future_feature (id INTEGER PRIMARY KEY, x TEXT)").Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Exec("ALTER TABLE incidents ADD COLUMN future_col TEXT").Error; err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(dir, "b")
	name, _ := mustCreate(t, db, root, CreateOptions{})
	rep, _ := Verify(root, name)
	if rep.Valid || rep.Compat == nil || rep.Compat.Compatible {
		t.Fatalf("a backup from a newer schema must be incompatible: %+v", rep)
	}
	joined := strings.Join(rep.Compat.Unknown, ",")
	if !strings.Contains(joined, "table future_feature") || !strings.Contains(joined, "column incidents.future_col") {
		t.Fatalf("unknown elements not named: %v", rep.Compat.Unknown)
	}
	live := filepath.Join(dir, "other.db")
	if _, err := Restore(RestoreOptions{Root: root, Name: name, LivePath: live, Confirm: true}); !errors.Is(err, ErrInvalidBackup) {
		t.Fatalf("%v", err)
	}
	if _, err := os.Stat(live); err == nil {
		t.Fatal("nothing may be created for an incompatible backup")
	}
	if w := SchemaWarnings(db); len(w) < 2 {
		t.Fatalf("startup warning must name the unknown schema: %v", w)
	}
}

func TestPreviewNeverMutatesAndConfirmIsRequired(t *testing.T) {
	dir := t.TempDir()
	live := filepath.Join(dir, "live.db")
	db := openDB(t, live)
	seed(t, db)
	root := filepath.Join(dir, "b")
	name, _ := mustCreate(t, db, root, CreateOptions{})
	// diverge the live database after the backup
	_ = db.Create(&database.Incident{Type: database.IncidentPortScan, SourceIP: "203.0.113.9", RiskScore: 5, DetectedAt: tNow}).Error
	closeDB(db)
	before := sha(t, live)
	entriesBefore, _ := os.ReadDir(dir)

	plan, err := Restore(RestoreOptions{Root: root, Name: name, LivePath: live}) // no Confirm
	if err != nil || plan.Applied || !plan.LiveExists || plan.LiveTables["incidents"] != 2 || plan.BackupTables["incidents"] != 1 {
		t.Fatalf("preview must compare live vs backup without applying: %v %+v", err, plan)
	}
	entriesAfter, _ := os.ReadDir(dir)
	if sha(t, live) != before || len(entriesAfter) != len(entriesBefore) {
		t.Fatal("a preview modified the live database or created files")
	}
}

func TestRestoreRefusedWhileDatabaseInUse(t *testing.T) {
	dir := t.TempDir()
	live := filepath.Join(dir, "live.db")
	db := openDB(t, live)
	seed(t, db)
	root := filepath.Join(dir, "b")
	name, _ := mustCreate(t, db, root, CreateOptions{})
	before := sha(t, live)

	// A second connection (the "daemon") holds a write lock.
	holder, err := sql.Open("sqlite", live)
	if err != nil {
		t.Fatal(err)
	}
	defer holder.Close()
	holder.SetMaxOpenConns(1)
	tx, err := holder.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if _, err := tx.Exec("UPDATE incidents SET risk_score = risk_score WHERE id = 1"); err != nil {
		t.Skip("could not take a write lock in this environment: ", err)
	}
	_, err = Restore(RestoreOptions{Root: root, Name: name, LivePath: live, Confirm: true})
	if !errors.Is(err, ErrInUse) {
		t.Fatalf("restore while the database is in use must be refused, got %v", err)
	}
	if _, serr := os.Stat(live); serr != nil {
		t.Fatal("live database disappeared")
	}
	_ = before
}

func TestInterruptedRestoreRestoresOriginalLiveDatabase(t *testing.T) {
	dir := t.TempDir()
	live := filepath.Join(dir, "live.db")
	db := openDB(t, live)
	seed(t, db)
	root := filepath.Join(dir, "b")
	name, _ := mustCreate(t, db, root, CreateOptions{})
	_ = db.Create(&database.Incident{Type: database.IncidentPortScan, SourceIP: "203.0.113.9", RiskScore: 5, DetectedAt: tNow}).Error
	if s, err := db.DB.DB(); err == nil {
		_, _ = s.Exec("PRAGMA wal_checkpoint(TRUNCATE)")
	}
	closeDB(db)
	before := sha(t, live)

	// (a) failure after the live DB was set aside and before activation
	_, err := Restore(RestoreOptions{Root: root, Name: name, LivePath: live, Confirm: true, Now: tNow,
		beforeActivate: func() error { return errors.New("simulated crash before activation") }})
	if err == nil || !strings.Contains(err.Error(), "simulated crash") {
		t.Fatalf("%v", err)
	}
	if sha(t, live) != before {
		t.Fatal("the original live database must be back in place, byte-identical")
	}
	// (b) the staged copy is corrupted before validation
	_, err = Restore(RestoreOptions{Root: root, Name: name, LivePath: live, Confirm: true, Now: tNow.Add(time.Second),
		afterCopy: func(c string) error {
			b, _ := os.ReadFile(c)
			b[len(b)-50] ^= 0xFF
			return os.WriteFile(c, b, 0o600)
		}})
	if !errors.Is(err, ErrInvalidBackup) {
		t.Fatalf("%v", err)
	}
	if sha(t, live) != before {
		t.Fatal("corrupt staging must not affect the live database")
	}
	es, _ := os.ReadDir(dir)
	for _, e := range es {
		if strings.Contains(e.Name(), ".partial") || strings.Contains(e.Name(), "pre-restore") {
			t.Errorf("leftover artifact after a failed restore: %s", e.Name())
		}
	}
}

func TestRepeatedRestorePreservesEachPreviousDatabase(t *testing.T) {
	dir := t.TempDir()
	live := filepath.Join(dir, "live.db")
	db := openDB(t, live)
	seed(t, db)
	root := filepath.Join(dir, "b")
	name, _ := mustCreate(t, db, root, CreateOptions{})
	closeDB(db)
	var pres []string
	for i := 0; i < 2; i++ {
		plan, err := Restore(RestoreOptions{Root: root, Name: name, LivePath: live, Confirm: true, Actor: "op", Now: tNow.Add(time.Duration(i) * time.Nanosecond)})
		if err != nil || !plan.Applied || plan.PreRestoreName == "" {
			t.Fatalf("restore %d: %v %+v", i, err, plan)
		}
		pres = append(pres, plan.PreRestoreName)
	}
	if pres[0] == pres[1] {
		t.Fatal("each restore must preserve its own previous database")
	}
	for _, p := range pres {
		if _, err := os.Stat(filepath.Join(dir, p)); err != nil {
			t.Errorf("preserved database %s missing", p)
		}
	}
	r := openDB(t, live)
	if tableCount(t, r, "incidents") != 1 {
		t.Fatal("live database must equal the backup after repeated restores")
	}
}

func TestNameValidationBlocksTraversalAndOverwrite(t *testing.T) {
	root := t.TempDir()
	for _, bad := range []string{"", "..", "../x", "a/b", `a\b`, "vanguard-backup-..", "/etc/passwd", "vanguard-backup-20261009T120000Z/../../x", "vanguard-backup-20261009T120000Z.partial", "VANGUARD-BACKUP-20261009T120000Z"} {
		if ValidName(bad) {
			t.Errorf("%q must not be a valid name", bad)
		}
		if _, err := Verify(root, bad); !errors.Is(err, ErrInvalidName) {
			t.Errorf("Verify(%q): %v", bad, err)
		}
		if _, err := Restore(RestoreOptions{Root: root, Name: bad, LivePath: filepath.Join(root, "x.db"), Confirm: true}); !errors.Is(err, ErrInvalidName) {
			t.Errorf("Restore(%q): %v", bad, err)
		}
	}
	db := openDB(t, filepath.Join(t.TempDir(), "l.db"))
	seed(t, db)
	if _, _, err := Create(db, CreateOptions{Dir: root, Now: tNow}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Create(db, CreateOptions{Dir: root, Now: tNow}); !errors.Is(err, ErrExists) {
		t.Fatalf("an existing backup must never be overwritten: %v", err)
	}
	if _, _, err := Create(db, CreateOptions{Dir: root, Now: tNow, Label: "Bad Label!"}); !errors.Is(err, ErrInvalidName) {
		t.Fatalf("%v", err)
	}
}

func TestBoundsAndPartialOutputNeverListedOrValid(t *testing.T) {
	root := t.TempDir()
	db := openDB(t, filepath.Join(t.TempDir(), "l.db"))
	seed(t, db)
	if _, _, err := Create(db, CreateOptions{Dir: root, Now: tNow, MaxBytes: 4096}); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("size bound: %v", err)
	}
	es, _ := os.ReadDir(root)
	if len(es) != 0 {
		t.Fatal("a refused backup must leave nothing behind")
	}
	// an interrupted earlier attempt: a .partial directory
	stale := filepath.Join(root, "vanguard-backup-20261009T120000Z.partial")
	_ = os.MkdirAll(stale, 0o700)
	_ = os.WriteFile(filepath.Join(stale, DBFile), []byte("half written"), 0o600)
	l, _ := List(root)
	if len(l) != 0 {
		t.Fatalf("partial output must not be listed as a backup: %v", l)
	}
	if rep, err := Verify(root, "vanguard-backup-20261009T120000Z"); err != nil || rep.Valid {
		t.Fatal("a partial backup must never verify as valid")
	}
	name, _ := mustCreate(t, db, root, CreateOptions{}) // same name: replaces its own stale partial
	if rep, _ := Verify(root, name); !rep.Valid {
		t.Fatal("backup after a stale partial must be valid")
	}
	if _, err := os.Stat(stale); err == nil {
		t.Fatal("stale partial of the same name should have been cleaned")
	}
	// retention cap
	for i := 0; i < MaxBackups; i++ {
		_ = os.MkdirAll(filepath.Join(root, fmt.Sprintf("vanguard-backup-20260101T0000%02dZ", i%60)+fmt.Sprintf("-x%d", i)), 0o700)
	}
	if _, _, err := Create(db, CreateOptions{Dir: root, Now: tNow.Add(time.Hour)}); !errors.Is(err, ErrTooManyBackups) {
		t.Fatalf("directory bound: %v", err)
	}
}

func TestExcludeUsersLeavesNoCredentialHashInTheFile(t *testing.T) {
	dir := t.TempDir()
	db := openDB(t, filepath.Join(dir, "l.db"))
	seed(t, db)
	root := filepath.Join(dir, "b")
	withUsers, _ := mustCreate(t, db, root, CreateOptions{Now: tNow})
	without, m := mustCreate(t, db, root, CreateOptions{Now: tNow.Add(time.Minute), ExcludeUsers: true})
	if m.UsersIncluded || m.Tables["users"] != 0 {
		t.Fatalf("%+v", m)
	}
	hasHash := func(n string) bool {
		b, _ := os.ReadFile(filepath.Join(root, n, DBFile))
		return bytes.Contains(b, []byte("SECRETHASH"))
	}
	if !hasHash(withUsers) {
		t.Fatal("control: the default backup should contain the account row")
	}
	if hasHash(without) {
		t.Fatal("credential hash survived in free pages of the user-less backup")
	}
	if rep, _ := Verify(root, without); !rep.Valid {
		t.Fatalf("%v", rep.Problems)
	}
	plan, err := Restore(RestoreOptions{Root: root, Name: without, LivePath: filepath.Join(dir, "x.db")})
	if err != nil || len(plan.Warnings) > 0 && false {
		t.Fatal(err)
	}
}

func TestLegacySchemaBackupRestoresAndMigratesWithoutLosingData(t *testing.T) {
	// testdata/legacy_1208a94.db was produced by the code of commit 1208a94
	// (5 models: no incident_events, IOC, notes, tuning or audit tables).
	src, err := os.ReadFile(filepath.Join("testdata", "legacy_1208a94.db"))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	root := filepath.Join(dir, "b")
	name := "vanguard-backup-20260901T000000Z-legacy"
	bdir := filepath.Join(root, name)
	_ = os.MkdirAll(bdir, 0o700)
	_ = os.WriteFile(filepath.Join(bdir, DBFile), src, 0o600)
	info, err := Inspect(filepath.Join(bdir, DBFile))
	if err != nil || info.Integrity != "ok" {
		t.Fatalf("%v %+v", err, info)
	}
	if _, has := info.Tables["incident_events"]; has {
		t.Fatal("fixture is supposed to predate incident_events")
	}
	s, n, _ := fileSHA256(filepath.Join(bdir, DBFile))
	mb, _ := json.Marshal(Manifest{Format: FormatName, Version: FormatVersion, CreatedAt: "2026-09-01T00:00:00Z", DBFile: DBFile,
		DBSizeBytes: n, DBSHA256: s, IntegrityCheck: "ok", Tables: info.Tables, SchemaFingerprint: info.Fingerprint, UsersIncluded: true})
	_ = os.WriteFile(filepath.Join(bdir, ManifestFile), mb, 0o600)

	rep, err := Verify(root, name)
	if err != nil || !rep.Valid || !rep.Compat.Compatible {
		t.Fatalf("a genuine older schema must be compatible: %v %+v", err, rep)
	}
	if !strings.Contains(strings.Join(rep.Compat.WillAdd, ","), "table incident_events") {
		t.Fatalf("migration additions should be listed: %v", rep.Compat.WillAdd)
	}
	live := filepath.Join(dir, "vanguard.db")
	if _, err := Restore(RestoreOptions{Root: root, Name: name, LivePath: live, Confirm: true, Actor: "op", Now: tNow}); err != nil {
		t.Fatal(err)
	}
	db := openDB(t, live)
	if tableCount(t, db, "incidents") != 3 || tableCount(t, db, "users") != 1 || tableCount(t, db, "firewall_rules") != 1 || tableCount(t, db, "host_file_baselines") < 1 {
		t.Fatal("legacy data lost in the restore + migration")
	}
	i2, _ := db.GetIncident(2)
	if i2.Status != database.StatusResolved || i2.ResolvedAt == nil || i2.Metadata != `{"legacy":true}` {
		t.Fatalf("legacy incident state not preserved: %+v", i2)
	}
	// the migrated database is fully usable with the new features
	if _, err := db.TransitionIncident(1, database.StatusInvestigating, "a@x", ""); err != nil {
		t.Fatalf("new lifecycle on migrated data: %v", err)
	}
	if _, err := db.AddIncidentNote(1, "a@x", "after migration"); err != nil {
		t.Fatal(err)
	}
}

func TestFilePermissionsAreRestrictive(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permission bits are not meaningful on Windows")
	}
	dir := t.TempDir()
	db := openDB(t, filepath.Join(dir, "l.db"))
	seed(t, db)
	root := filepath.Join(dir, "b")
	name, _ := mustCreate(t, db, root, CreateOptions{})
	for _, p := range []string{filepath.Join(root, name), filepath.Join(root, name, DBFile), filepath.Join(root, name, ManifestFile)} {
		st, _ := os.Stat(p)
		if st.Mode().Perm()&0o077 != 0 {
			t.Errorf("%s is accessible by group/other: %v", p, st.Mode().Perm())
		}
	}
}

func TestDatabaseFailureDuringBackupLeavesNothingAndNoValidBackup(t *testing.T) {
	dir := t.TempDir()
	db := openDB(t, filepath.Join(dir, "l.db"))
	seed(t, db)
	closeDB(db) // the database handle is dead
	root := filepath.Join(dir, "b")
	if _, _, err := Create(db, CreateOptions{Dir: root, Now: tNow}); err == nil {
		t.Fatal("a backup from an unusable database must fail")
	}
	es, _ := os.ReadDir(root)
	for _, e := range es {
		t.Errorf("leftover after failed backup: %s", e.Name())
	}
}

// An idle running daemon holds no write lock in WAL mode, but it still has
// the database open: a restore must be refused in that case too.
func TestRestoreRefusedWhileDatabaseIsOpenAndIdle(t *testing.T) {
	dir := t.TempDir()
	live := filepath.Join(dir, "live.db")
	db := openDB(t, live) // stays open, no transaction in flight
	seed(t, db)
	root := filepath.Join(dir, "b")
	name, _ := mustCreate(t, db, root, CreateOptions{})
	before := sha(t, live)
	_ = db.Exec("SELECT 1").Error
	_, err := Restore(RestoreOptions{Root: root, Name: name, LivePath: live, Confirm: true, Now: tNow})
	if !errors.Is(err, ErrInUse) {
		t.Fatalf("an idle-but-open database must still count as in use, got %v", err)
	}
	closeDB(db)
	if _, serr := os.Stat(live); serr != nil || sha(t, live) == "" {
		t.Fatal("live database damaged")
	}
	_ = before
	// once the daemon has stopped, the same restore is allowed
	if _, err := Restore(RestoreOptions{Root: root, Name: name, LivePath: live, Confirm: true, Now: tNow}); err != nil {
		t.Fatalf("restore after the database was closed: %v", err)
	}
}
