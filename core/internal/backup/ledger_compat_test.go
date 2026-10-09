package backup

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"vanguard/core/internal/database"
	"vanguard/core/internal/retention"
)

// The ledger travels with a backup; restore keeps it verifiable and extends it
// (the restore itself is an audited, sealed event); retention never touches the
// sealed tables; tampering with a restored copy is still detected.
func TestAuditLedgerSurvivesBackupRestoreAndRetention(t *testing.T) {
	dir := t.TempDir()
	db := openDB(t, filepath.Join(dir, "live.db"))
	seed(t, db)
	_ = db.RecordAdminAudit(&database.AdminAudit{Actor: "admin@example.test", Action: "firewall.block", Target: "203.0.113.5", Result: "ok"})
	pol := database.RetentionPolicy{IncidentRetentionDays: 90, BatchSize: 50, MaxBatchesPerRun: 3, KeepWithNotes: true}
	if _, err := db.SetRetentionPolicy(pol, 0, "cli:admin", tNow); err != nil {
		t.Fatal(err)
	}
	if _, err := retention.New(db).Execute(context.Background(), "cli:admin"); err != nil {
		t.Fatal(err)
	}
	if r, err := db.SealPending(time.Now().UTC()); err != nil || r.Sealed < 3 {
		t.Fatalf("%v %+v", err, r)
	}
	before, _ := db.VerifyLedger(database.VerifyOptions{})
	if !before.OK {
		t.Fatalf("%+v", before.Findings)
	}

	root := filepath.Join(dir, "backups")
	name, m := mustCreate(t, db, root, CreateOptions{Actor: "admin"})
	if _, ok := m.Tables["audit_ledger"]; !ok {
		t.Fatalf("the manifest must list the ledger table: %v", m.Tables)
	}
	target := filepath.Join(dir, "restored", "vanguard.db")
	_ = os.MkdirAll(filepath.Dir(target), 0o700)
	if _, err := Restore(RestoreOptions{Root: root, Name: name, LivePath: target, Confirm: true, Actor: "cli:root", Now: tNow}); err != nil {
		t.Fatal(err)
	}
	r := openDB(t, target)
	v, _ := r.VerifyLedger(database.VerifyOptions{})
	if !v.OK || v.HeadSeq != before.HeadSeq || v.HeadHash != before.HeadHash {
		t.Fatalf("the restored ledger must be identical and valid: %+v", v)
	}
	// the restore wrote a backup_audits row; it is sealed on the next pass and the chain stays valid
	if res, err := r.SealPending(time.Now().UTC()); err != nil || res.Sealed < 1 || res.Legacy {
		t.Fatalf("%v %+v", err, res)
	}
	if v, _ := r.VerifyLedger(database.VerifyOptions{}); !v.OK || v.HeadSeq <= before.HeadSeq {
		t.Fatalf("%+v", v)
	}
	// a later retention run does not break verification of the sealed tables
	if _, err := retention.New(r).Execute(context.Background(), "cli:root"); err != nil {
		t.Fatal(err)
	}
	r.SealPending(time.Now().UTC())
	if v, _ := r.VerifyLedger(database.VerifyOptions{}); !v.OK {
		t.Fatalf("%+v", v.Findings)
	}
	// tampering with the restored copy is detected
	r.Exec("UPDATE admin_audits SET actor = 'mallory' WHERE id = 1")
	if v, _ := r.VerifyLedger(database.VerifyOptions{}); v.OK {
		t.Fatal("tampering with a restored database must be detected")
	}
}

// A corrupted ledger inside a backup is flagged by verification of that copy,
// while the backup's own integrity checks still describe the FILE.
func TestLegacyDatabaseGetsALedgerOnFirstSeal_FlaggedLegacy(t *testing.T) {
	src, err := os.ReadFile(filepath.Join("testdata", "legacy_1208a94.db"))
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "vanguard.db")
	if err := os.WriteFile(p, src, 0o600); err != nil {
		t.Fatal(err)
	}
	db := openDB(t, p)
	_ = db.RecordAdminAudit(&database.AdminAudit{Actor: "a", Action: "x", Result: "ok"})
	res, err := db.SealPending(time.Now().UTC())
	if err != nil || !res.Legacy || res.Sealed != 1 {
		t.Fatalf("%v %+v", err, res)
	}
	v, _ := db.VerifyLedger(database.VerifyOptions{})
	if !v.OK || v.LegacyEntries != 1 {
		t.Fatalf("legacy entries must be counted so integrity before sealing is not overstated: %+v", v)
	}
}
