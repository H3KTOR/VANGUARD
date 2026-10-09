package backup

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"vanguard/core/internal/database"
	"vanguard/core/internal/retention"
)

// Phase 12 added the retention_policies and retention_runs tables. A backup
// must carry the operator's policy and the audit trail of what retention did,
// and a restored database must keep honouring them.
func TestRetentionPolicyAndAuditSurviveBackupRestore(t *testing.T) {
	dir := t.TempDir()
	db := openDB(t, filepath.Join(dir, "live.db"))
	seed(t, db)
	// An old resolved incident that retention will remove before the backup.
	old := tNow.AddDate(0, 0, -400)
	oldInc := &database.Incident{Type: database.IncidentPortScan, SourceIP: "203.0.113.50", Status: database.StatusResolved, DetectedAt: old, ResolvedAt: &old}
	if err := db.Create(oldInc).Error; err != nil {
		t.Fatal(err)
	}
	pol := database.RetentionPolicy{IncidentRetentionDays: 90, BatchSize: 50, MaxBatchesPerRun: 3, KeepWithNotes: true}
	if _, err := db.SetRetentionPolicy(pol, 0, "cli:admin", tNow); err != nil {
		t.Fatal(err)
	}
	res, err := retention.New(db).Execute(context.Background(), "cli:admin")
	if err != nil || res.Run.IncidentsDeleted != 1 {
		t.Fatalf("setup: %v %+v", err, res)
	}

	root := filepath.Join(dir, "backups")
	name, m := mustCreate(t, db, root, CreateOptions{Actor: "admin"})
	for _, tbl := range []string{"retention_policies", "retention_runs"} {
		if _, ok := m.Tables[tbl]; !ok {
			t.Fatalf("manifest must list %s: %v", tbl, m.Tables)
		}
	}
	if rep, err := Verify(root, name); err != nil || !rep.Valid {
		t.Fatalf("%v %+v", err, rep)
	}

	target := filepath.Join(dir, "restored", "vanguard.db")
	_ = os.MkdirAll(filepath.Dir(target), 0o700)
	if _, err := Restore(RestoreOptions{Root: root, Name: name, LivePath: target, Confirm: true, Actor: "cli:root", Now: tNow}); err != nil {
		t.Fatal(err)
	}
	r := openDB(t, target)
	got, err := r.GetRetentionPolicy()
	if err != nil || got.IncidentRetentionDays != 90 || got.BatchSize != 50 || got.MaxBatchesPerRun != 3 || !got.KeepWithNotes || got.Revision != 1 || got.UpdatedBy != "cli:admin" {
		t.Fatalf("retention policy not preserved: %+v %v", got, err)
	}
	runs, _ := r.ListRetentionRuns(10)
	if len(runs) != 2 {
		t.Fatalf("retention audit trail not preserved: %+v", runs)
	}
	// Retention keeps working on the restored database and is idempotent there.
	rr := retention.New(r)
	again, err := rr.Execute(context.Background(), "cli:root")
	if err != nil || again.Run.IncidentsDeleted != 0 {
		t.Fatalf("%v %+v", err, again)
	}
	if tableCount(t, r, "incidents") != 1 {
		t.Fatal("the surviving incident must still be there")
	}
}

// A pre-Phase-12 database has no retention tables. After restore+migration the
// policy is the safe default (keep everything) and a dry run works.
func TestLegacyDatabaseGetsSafeRetentionDefaults(t *testing.T) {
	src, err := os.ReadFile(filepath.Join("testdata", "legacy_1208a94.db"))
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "vanguard.db")
	if err := os.WriteFile(p, src, 0o600); err != nil {
		t.Fatal(err)
	}
	db := openDB(t, p) // migrates the legacy file in place
	pol, err := db.GetRetentionPolicy()
	if err != nil || pol.IncidentRetentionDays != 0 || pol.Revision != 0 {
		t.Fatalf("legacy databases must default to keep-everything: %+v %v", pol, err)
	}
	before := tableCount(t, db, "incidents")
	res, err := retention.New(db).Execute(context.Background(), "system:retention")
	if err != nil || res.Run.Status != database.RetentionStatusDisabled {
		t.Fatalf("%v %+v", err, res)
	}
	if tableCount(t, db, "incidents") != before {
		t.Fatal("a disabled retention policy deleted data")
	}
}
