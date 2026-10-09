package retention

import (
	"context"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"vanguard/core/internal/database"
)

var now0 = time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)

func newRunner(t *testing.T, days, batch, maxBatches int, keepNotes bool) (*Runner, *database.DB) {
	t.Helper()
	db, err := database.Open(database.Config{Path: filepath.Join(t.TempDir(), "r.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if s, err := db.DB.DB(); err == nil {
			s.Close()
		}
	})
	if days >= 0 {
		p := database.RetentionPolicy{IncidentRetentionDays: days, BatchSize: batch, MaxBatchesPerRun: maxBatches, KeepWithNotes: keepNotes}
		if _, err := db.SetRetentionPolicy(p, 0, "test-admin", now0); err != nil {
			t.Fatal(err)
		}
	}
	r := New(db)
	r.now = func() time.Time { return now0 }
	return r, db
}

func ago(days int) time.Time { return now0.AddDate(0, 0, -days) }

// mk creates an incident with the given status and age (days since resolution
// or detection).
func mk(t *testing.T, db *database.DB, status database.IncidentStatus, ageDays int) *database.Incident {
	t.Helper()
	inc := &database.Incident{Type: database.IncidentPortScan, SourceIP: "203.0.113.9", Severity: database.SeverityLow, Status: status, DetectedAt: ago(ageDays)}
	if status == database.StatusResolved || status == database.StatusFalsePositive {
		ra := ago(ageDays)
		inc.ResolvedAt = &ra
	}
	if err := db.Create(inc).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Create(&database.IncidentEvent{IncidentID: inc.ID, Kind: "lifecycle", Actor: "system", At: ago(ageDays)}).Error; err != nil {
		t.Fatal(err)
	}
	return inc
}

func count(t *testing.T, db *database.DB, model any, where string, args ...any) int64 {
	t.Helper()
	var n int64
	q := db.Model(model)
	if where != "" {
		q = q.Where(where, args...)
	}
	if err := q.Count(&n).Error; err != nil {
		t.Fatal(err)
	}
	return n
}

func exists(t *testing.T, db *database.DB, id uint) bool {
	return count(t, db, &database.Incident{}, "id = ?", id) == 1
}

func TestDisabledByDefaultDeletesNothingAndWritesNoAuditRow(t *testing.T) {
	r, db := newRunner(t, -1, 0, 0, true) // no policy row stored
	old := mk(t, db, database.StatusResolved, 4000)
	res, err := r.Execute(context.Background(), "system:retention")
	if err != nil {
		t.Fatal(err)
	}
	if res.Run.Status != database.RetentionStatusDisabled || !exists(t, db, old.ID) {
		t.Fatalf("default policy must keep everything: %+v", res.Run)
	}
	if n := count(t, db, &database.RetentionRun{}, ""); n != 0 {
		t.Fatalf("a no-op daemon tick must not append audit rows, got %d", n)
	}
	// an explicit preview is an operator action and is recorded
	if res, _ = r.Preview(context.Background(), "cli:admin"); res.Run.Status != database.RetentionStatusDisabled {
		t.Fatalf("%+v", res.Run)
	}
	if n := count(t, db, &database.RetentionRun{}, "mode = ?", database.RetentionModeDryRun); n != 1 {
		t.Fatalf("dry run must be audited, got %d", n)
	}
}

func TestPreviewModifiesNothingAndReportsWhatExecuteWouldDo(t *testing.T) {
	r, db := newRunner(t, 90, 100, 5, true)
	a := mk(t, db, database.StatusResolved, 200)
	b := mk(t, db, database.StatusFalsePositive, 150)
	_ = mk(t, db, database.StatusResolved, 10) // too recent
	_ = db.Create(&database.IncidentNote{IncidentID: a.ID, Author: "x", Text: "soft", CreatedAt: ago(200), Deleted: true}).Error
	_ = db.Create(&database.IOCMatch{IOCID: 1, IncidentID: b.ID, MatchedAt: ago(1), IOCType: database.IOCIP, Kind: "direct"}).Error

	before := snapshot(t, db)
	res, err := r.Preview(context.Background(), "cli:admin")
	if err != nil {
		t.Fatal(err)
	}
	after := snapshot(t, db)
	for k, v := range before {
		if after[k] != v {
			t.Fatalf("preview changed %s: %d -> %d", k, v, after[k])
		}
	}
	run := res.Run
	if run.Status != database.RetentionStatusPreview || run.Mode != database.RetentionModeDryRun || run.EligibleTotal != 2 ||
		run.EventsDeleted != 2 || run.NotesDeleted != 1 || run.MatchesUnlinked != 1 || run.IncidentsDeleted != 0 {
		t.Fatalf("preview numbers: %+v", run)
	}
	if !strings.Contains(run.Detail, "nothing was modified") {
		t.Fatalf("detail: %q", run.Detail)
	}
}

func snapshot(t *testing.T, db *database.DB) map[string]int64 {
	t.Helper()
	m := map[string]int64{}
	for name, model := range map[string]any{
		"incidents": &database.Incident{}, "events": &database.IncidentEvent{}, "notes": &database.IncidentNote{},
		"matches": &database.IOCMatch{}, "rules": &database.FirewallRule{}, "tuning": &database.RuleTuningRevision{},
		"backup_audits": &database.BackupAudit{}, "users": &database.User{},
	} {
		m[name] = count(t, db, model, "")
	}
	return m
}

func TestExecuteDeletesOnlyEligibleAndKeepsProtectedRecords(t *testing.T) {
	r, db := newRunner(t, 90, 100, 5, true)
	_ = db.Create(&database.RuleTuningRevision{CreatedAt: ago(500), Actor: "admin", Kind: "apply", Status: "active", Values: `{}`}).Error
	_ = db.RecordBackupAudit(&database.BackupAudit{Kind: "create", Actor: "cli", Result: "ok"})
	_ = db.CreateUser(&database.User{Email: "a@example.test", PasswordHash: "x", Role: database.RoleAdmin, IsActive: true})

	del1 := mk(t, db, database.StatusResolved, 365)
	del2 := mk(t, db, database.StatusFalsePositive, 365)
	del3 := mk(t, db, database.StatusAutoBlocked, 365)
	keepOpen := mk(t, db, database.StatusOpen, 4000)
	keepInv := mk(t, db, database.StatusInvestigating, 4000)
	keepNew := mk(t, db, database.StatusResolved, 5)
	keepBan := mk(t, db, database.StatusResolved, 365)
	keepNote := mk(t, db, database.StatusResolved, 365)

	banned := keepBan.ID
	_ = db.Create(&database.FirewallRule{IPAddress: "203.0.113.9", IsActive: true, BannedAt: ago(1), IncidentID: &banned, Source: database.FirewallSourceManual}).Error
	_ = db.Create(&database.IncidentNote{IncidentID: keepNote.ID, Author: "analyst", Text: "important", CreatedAt: ago(300)}).Error
	// deleted incidents' dependents
	_ = db.Create(&database.IncidentNote{IncidentID: del1.ID, Author: "analyst", Text: "gone", CreatedAt: ago(300), Deleted: true}).Error
	d1 := del1.ID
	_ = db.Create(&database.FirewallRule{IPAddress: "203.0.113.10", BannedAt: ago(300), IncidentID: &d1, Source: database.FirewallSourceAutopilot}).Error
	// (the column has default:true, so a false zero value must be set by UPDATE)
	if err := db.Model(&database.FirewallRule{}).Where("ip_address = ?", "203.0.113.10").Update("is_active", false).Error; err != nil {
		t.Fatal(err)
	}
	_ = db.Create(&database.IOCMatch{IOCID: 7, IncidentID: del2.ID, MatchedAt: ago(2), IOCType: database.IOCIP, Kind: "direct", Context: "198.51.100.1"}).Error

	before := snapshot(t, db)
	res, err := r.Execute(context.Background(), "system:retention")
	if err != nil {
		t.Fatal(err)
	}
	run := res.Run
	if run.Status != database.RetentionStatusCompleted || run.IncidentsDeleted != 3 || run.EventsDeleted != 3 || run.NotesDeleted != 1 ||
		run.MatchesUnlinked != 1 || run.RulesUnlinked != 1 || run.SkippedActive != 1 || run.SkippedNotes != 1 {
		t.Fatalf("run: %+v", run)
	}
	for _, g := range []*database.Incident{del1, del2, del3} {
		if exists(t, db, g.ID) || count(t, db, &database.IncidentEvent{}, "incident_id = ?", g.ID) != 0 {
			t.Fatalf("incident %d (or its events) survived", g.ID)
		}
	}
	for name, k := range map[string]*database.Incident{"open": keepOpen, "investigating": keepInv, "recent": keepNew, "active ban": keepBan, "live note": keepNote} {
		if !exists(t, db, k.ID) || count(t, db, &database.IncidentEvent{}, "incident_id = ?", k.ID) != 1 {
			t.Fatalf("protected incident (%s) was damaged", name)
		}
	}
	after := snapshot(t, db)
	// never touched
	for _, k := range []string{"tuning", "backup_audits", "users", "matches", "rules"} {
		if after[k] != before[k] {
			t.Fatalf("%s must not be deleted: %d -> %d", k, before[k], after[k])
		}
	}
	// the match history survives with its link cleared; the inactive rule keeps its history
	var m database.IOCMatch
	if err := db.Where("ioc_id = ?", 7).First(&m).Error; err != nil || m.IncidentID != 0 || m.Context != "198.51.100.1" {
		t.Fatalf("match must survive unlinked: %+v %v", m, err)
	}
	var fr database.FirewallRule
	if err := db.Where("ip_address = ?", "203.0.113.10").First(&fr).Error; err != nil || fr.IncidentID != nil {
		t.Fatalf("inactive ban must survive unlinked: %+v %v", fr, err)
	}
	var act database.FirewallRule
	if err := db.Where("ip_address = ? AND is_active = 1", "203.0.113.9").First(&act).Error; err != nil || act.IncidentID == nil || *act.IncidentID != keepBan.ID {
		t.Fatalf("active ban link must be intact: %+v %v", act, err)
	}
	// audit row exists and describes the ID range, not the content
	var row database.RetentionRun
	if err := db.Where("mode = ?", database.RetentionModeExecute).First(&row).Error; err != nil || row.Actor != "system:retention" || row.IncidentsDeleted != 3 || row.MinID == 0 || row.MaxID < row.MinID {
		t.Fatalf("audit row: %+v %v", row, err)
	}
}

func TestKeepWithNotesOffDeletesNotes(t *testing.T) {
	r, db := newRunner(t, 90, 100, 5, false)
	inc := mk(t, db, database.StatusResolved, 365)
	_ = db.Create(&database.IncidentNote{IncidentID: inc.ID, Author: "analyst", Text: "live", CreatedAt: ago(300)}).Error
	res, err := r.Execute(context.Background(), "cli:admin")
	if err != nil || res.Run.IncidentsDeleted != 1 || res.Run.NotesDeleted != 1 {
		t.Fatalf("%v %+v", err, res.Run)
	}
}

func TestIdempotent(t *testing.T) {
	r, db := newRunner(t, 90, 100, 5, true)
	for i := 0; i < 5; i++ {
		mk(t, db, database.StatusResolved, 365)
	}
	r1, _ := r.Execute(context.Background(), "cli:admin")
	r2, err := r.Execute(context.Background(), "cli:admin")
	if err != nil || r1.Run.IncidentsDeleted != 5 || r2.Run.IncidentsDeleted != 0 || r2.Run.Status != database.RetentionStatusCompleted || r2.More {
		t.Fatalf("not idempotent: %+v / %+v", r1.Run, r2.Run)
	}
}

func TestBatchAndRunBoundsAreRespected(t *testing.T) {
	r, db := newRunner(t, 90, 10, 2, true) // 10 per batch, 2 batches per run
	for i := 0; i < 25; i++ {
		mk(t, db, database.StatusResolved, 365)
	}
	var sizes []int64
	var prev int64 = 25
	r.afterBatch = func(int) {
		cur := count(t, db, &database.Incident{}, "")
		sizes = append(sizes, prev-cur)
		prev = cur
	}
	res, _ := r.Execute(context.Background(), "cli:admin")
	if res.Run.Status != database.RetentionStatusPartial || !res.More || res.Run.IncidentsDeleted != 20 || res.Run.Batches != 2 {
		t.Fatalf("first run: %+v more=%v", res.Run, res.More)
	}
	for _, s := range sizes {
		if s > 10 {
			t.Fatalf("a transaction deleted %d incidents, more than the batch size", s)
		}
	}
	res, _ = r.Execute(context.Background(), "cli:admin")
	if res.Run.IncidentsDeleted != 5 || res.Run.Status != database.RetentionStatusCompleted {
		t.Fatalf("second run: %+v", res.Run)
	}
}

func TestCancellationStopsBetweenBatchesAndKeepsCommittedWork(t *testing.T) {
	r, db := newRunner(t, 90, 10, 10, true)
	for i := 0; i < 40; i++ {
		mk(t, db, database.StatusResolved, 365)
	}
	ctx, cancel := context.WithCancel(context.Background())
	r.afterBatch = func(n int) {
		if n == 2 {
			cancel()
		}
	}
	res, _ := r.Execute(ctx, "cli:admin")
	if res.Run.Status != database.RetentionStatusPartial || !res.More || res.Run.IncidentsDeleted != 20 {
		t.Fatalf("%+v", res.Run)
	}
	if left := count(t, db, &database.Incident{}, ""); left != 20 {
		t.Fatalf("expected 20 incidents left, got %d", left)
	}
	if n := count(t, db, &database.IncidentEvent{}, ""); n != 20 {
		t.Fatalf("events of surviving incidents must remain, got %d", n)
	}
}

func TestBatchIsAtomic_FailureLeavesNoPartialDeletion(t *testing.T) {
	r, db := newRunner(t, 90, 10, 5, true)
	inc := mk(t, db, database.StatusResolved, 365)
	_ = db.Create(&database.IncidentNote{IncidentID: inc.ID, Author: "a", Text: "x", CreatedAt: ago(300), Deleted: true}).Error
	// A trigger makes the final incident delete fail AFTER events/notes were deleted in the same transaction.
	if err := db.Exec(`CREATE TRIGGER block_incident_delete BEFORE DELETE ON incidents BEGIN SELECT RAISE(ABORT, 'blocked'); END`).Error; err != nil {
		t.Fatal(err)
	}
	before := snapshot(t, db)
	res, err := r.Execute(context.Background(), "cli:admin")
	if err != nil {
		t.Fatal(err)
	}
	if res.Run.Status != database.RetentionStatusFailed || !res.More || res.Run.IncidentsDeleted != 0 {
		t.Fatalf("%+v", res.Run)
	}
	after := snapshot(t, db)
	for k, v := range before {
		if after[k] != v {
			t.Fatalf("partial deletion leaked: %s %d -> %d", k, v, after[k])
		}
	}
	if n := count(t, db, &database.RetentionRun{}, "status = ?", database.RetentionStatusFailed); n != 1 {
		t.Fatalf("failure must be audited, got %d", n)
	}
}

func TestSkipHookPreventsExecuteButNotPreview(t *testing.T) {
	r, db := newRunner(t, 90, 100, 5, true)
	inc := mk(t, db, database.StatusResolved, 365)
	r.Skip = func() string { return "Panic Mode is active" }
	res, _ := r.Execute(context.Background(), "system:retention")
	if res.Run.Status != database.RetentionStatusSkipped || !exists(t, db, inc.ID) || !strings.Contains(res.Run.Detail, "Panic Mode") {
		t.Fatalf("%+v", res.Run)
	}
	if res, _ = r.Preview(context.Background(), "cli:admin"); res.Run.Status != database.RetentionStatusPreview || res.Run.EligibleTotal != 1 {
		t.Fatalf("%+v", res.Run)
	}
}

// A ban created after the preview must protect the incident from the real run.
func TestExecuteRechecksEligibility(t *testing.T) {
	r, db := newRunner(t, 90, 100, 5, true)
	inc := mk(t, db, database.StatusResolved, 365)
	if res, _ := r.Preview(context.Background(), "cli:admin"); res.Run.EligibleTotal != 1 {
		t.Fatalf("%+v", res.Run)
	}
	id := inc.ID
	_ = db.Create(&database.FirewallRule{IPAddress: "203.0.113.9", IsActive: true, BannedAt: ago(0), IncidentID: &id, Source: database.FirewallSourceManual}).Error
	res, _ := r.Execute(context.Background(), "cli:admin")
	if res.Run.IncidentsDeleted != 0 || !exists(t, db, inc.ID) {
		t.Fatalf("an incident gained an active ban after the preview and must now be protected: %+v", res.Run)
	}
}

func TestOverlappingRunsAreRefused(t *testing.T) {
	r, db := newRunner(t, 90, 10, 5, true)
	for i := 0; i < 30; i++ {
		mk(t, db, database.StatusResolved, 365)
	}
	inBatch := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	r.afterBatch = func(int) {
		once.Do(func() { close(inBatch) })
		<-release
	}
	done := make(chan struct{})
	go func() { _, _ = r.Execute(context.Background(), "cli:a"); close(done) }()
	<-inBatch
	if _, err := r.Execute(context.Background(), "cli:b"); err != ErrAlreadyRunning {
		t.Fatalf("want ErrAlreadyRunning, got %v", err)
	}
	if _, err := r.Preview(context.Background(), "cli:b"); err != ErrAlreadyRunning {
		t.Fatalf("a preview must not overlap a run either, got %v", err)
	}
	close(release)
	<-done
}

func TestPolicyValidationBounds(t *testing.T) {
	ok := database.RetentionPolicy{IncidentRetentionDays: 90, BatchSize: 200, MaxBatchesPerRun: 20}
	if err := Validate(ok); err != nil {
		t.Fatal(err)
	}
	for name, mut := range map[string]func(*database.RetentionPolicy){
		"days too small": func(p *database.RetentionPolicy) { p.IncidentRetentionDays = 7 },
		"negative days":  func(p *database.RetentionPolicy) { p.IncidentRetentionDays = -1 },
		"days too large": func(p *database.RetentionPolicy) { p.IncidentRetentionDays = 100000 },
		"batch small":    func(p *database.RetentionPolicy) { p.BatchSize = 1 },
		"batch large":    func(p *database.RetentionPolicy) { p.BatchSize = 100000 },
		"batches zero":   func(p *database.RetentionPolicy) { p.MaxBatchesPerRun = 0 },
		"batches large":  func(p *database.RetentionPolicy) { p.MaxBatchesPerRun = 1000 },
	} {
		p := ok
		mut(&p)
		if Validate(p) == nil {
			t.Errorf("%s must be rejected", name)
		}
	}
	zero := ok
	zero.IncidentRetentionDays = 0
	if Validate(zero) != nil {
		t.Fatal("0 days (keep forever) is valid")
	}
}

func TestPolicyRevisionConflictAndAudit(t *testing.T) {
	_, db := newRunner(t, -1, 0, 0, true)
	p := database.RetentionPolicy{IncidentRetentionDays: 90, BatchSize: 200, MaxBatchesPerRun: 20, KeepWithNotes: true}
	saved, err := db.SetRetentionPolicy(p, 0, "cli:admin", now0)
	if err != nil || saved.Revision != 1 {
		t.Fatalf("%v %+v", err, saved)
	}
	if _, err := db.SetRetentionPolicy(p, 0, "cli:other", now0); err != database.ErrRetentionPolicyConflict {
		t.Fatalf("stale revision must be refused, got %v", err)
	}
	if _, err := db.SetRetentionPolicy(p, 1, "cli:admin", now0); err != nil {
		t.Fatal(err)
	}
	rows, _ := db.ListRetentionRuns(10)
	if len(rows) != 2 || rows[0].Mode != database.RetentionModePolicyChange || rows[0].PolicyRevision != 2 {
		t.Fatalf("policy changes must be audited: %+v", rows)
	}
	cur, _ := db.GetRetentionPolicy()
	if cur.Revision != 2 || cur.UpdatedBy != "cli:admin" {
		t.Fatalf("%+v", cur)
	}
}

func TestCorruptStoredPolicyFailsClosed(t *testing.T) {
	r, db := newRunner(t, 90, 100, 5, true)
	inc := mk(t, db, database.StatusResolved, 365)
	if err := db.Exec("UPDATE retention_policies SET batch_size = 999999").Error; err != nil {
		t.Fatal(err)
	}
	res, _ := r.Execute(context.Background(), "system:retention")
	if res.Run.Status != database.RetentionStatusFailed || !exists(t, db, inc.ID) {
		t.Fatalf("an invalid stored policy must delete nothing: %+v", res.Run)
	}
}
