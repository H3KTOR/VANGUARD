package database

import (
	"errors"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func fileDB(t *testing.T) *DB {
	t.Helper()
	db, err := Open(Config{Path: filepath.Join(t.TempDir(), "t.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { sqlClose(db) })
	return db
}

func sqlClose(db *DB) {
	if s, err := db.DB.DB(); err == nil {
		s.Close()
	}
}

func newInc(t *testing.T, db *DB) *Incident {
	t.Helper()
	inc := &Incident{Type: IncidentPortScan, SourceIP: "203.0.113.5", RiskScore: 50}
	if err := db.CreateIncident(inc); err != nil {
		t.Fatal(err)
	}
	return inc
}

var allStatuses = []IncidentStatus{StatusOpen, StatusAutoBlocked, StatusInvestigating, StatusResolved, StatusFalsePositive}

func forceStatus(t *testing.T, db *DB, id uint, s IncidentStatus) {
	t.Helper()
	if err := db.Model(&Incident{}).Where("id = ?", id).Update("status", s).Error; err != nil {
		t.Fatal(err)
	}
}

func TestLifecycle_FullTransitionMatrix(t *testing.T) {
	db := fileDB(t)
	for _, from := range allStatuses {
		for _, to := range allStatuses {
			inc := newInc(t, db)
			forceStatus(t, db, inc.ID, from)
			got, err := db.TransitionIncident(inc.ID, to, "tester", "matrix")
			switch {
			case from == to:
				if err != nil || got.Status != to {
					t.Errorf("%s->%s must be an idempotent no-op, err=%v", from, to, err)
				}
				if evs, _ := db.ListIncidentEvents(inc.ID); len(evs) != 0 {
					t.Errorf("%s->%s no-op must not write an event", from, to)
				}
			case ValidTransition(from, to):
				if err != nil || got.Status != to {
					t.Errorf("%s->%s should be allowed: %v", from, to, err)
				}
			default:
				if !errors.Is(err, ErrInvalidTransition) {
					t.Errorf("%s->%s should be rejected, got err=%v", from, to, err)
				}
				cur, _ := db.GetIncident(inc.ID)
				if cur.Status != from {
					t.Errorf("%s->%s rejected transition modified the row: now %s", from, to, cur.Status)
				}
				if evs, _ := db.ListIncidentEvents(inc.ID); len(evs) != 0 {
					t.Errorf("%s->%s rejected transition wrote an event", from, to)
				}
			}
		}
	}
}

func TestLifecycle_AutoBlockedNeverOverwritesAnalystDecision(t *testing.T) {
	db := fileDB(t)
	for _, s := range []IncidentStatus{StatusInvestigating, StatusResolved, StatusFalsePositive} {
		inc := newInc(t, db)
		forceStatus(t, db, inc.ID, s)
		applied, err := db.MarkAutoBlocked(inc.ID, "autopilot", "ban")
		cur, _ := db.GetIncident(inc.ID)
		if err != nil || applied || cur.Status != s {
			t.Errorf("status %s: applied=%v err=%v now=%s", s, applied, err, cur.Status)
		}
	}
	inc := newInc(t, db)
	if applied, err := db.MarkAutoBlocked(inc.ID, "autopilot", "ban"); err != nil || !applied {
		t.Fatalf("open incident must be markable: applied=%v err=%v", applied, err)
	}
}

func TestLifecycle_ResolveReopenTimestamps(t *testing.T) {
	db := fileDB(t)
	inc := newInc(t, db)
	r, _ := db.TransitionIncident(inc.ID, StatusResolved, "a@x", "fixed")
	if r.ResolvedAt == nil {
		t.Fatal("resolved must stamp resolved_at")
	}
	r, err := db.TransitionIncident(inc.ID, StatusOpen, "a@x", "recurred")
	if err != nil || r.ResolvedAt != nil {
		t.Fatalf("reopen must clear resolved_at: %v %v", err, r.ResolvedAt)
	}
	evs, _ := db.ListIncidentEvents(inc.ID)
	if len(evs) != 2 || evs[0].ToStatus != "resolved" || evs[1].ToStatus != "open" || evs[1].FromStatus != "resolved" {
		t.Fatalf("audit trail wrong: %+v", evs)
	}
}

func TestLifecycle_UnknownTargetAndMissingIncident(t *testing.T) {
	db := fileDB(t)
	inc := newInc(t, db)
	if _, err := db.TransitionIncident(inc.ID, "bogus", "a", ""); !errors.Is(err, ErrInvalidTransition) {
		t.Errorf("bogus status: %v", err)
	}
	if _, err := db.TransitionIncident(99999, StatusResolved, "a", ""); !errors.Is(err, ErrNotFound) {
		t.Errorf("missing incident: %v", err)
	}
}

func TestLifecycle_AuditTextSanitizedAndBounded(t *testing.T) {
	db := fileDB(t)
	inc := newInc(t, db)
	reason := "line1\nline2\x00\x1b[31m" + strings.Repeat("Z", 5000)
	if _, err := db.TransitionIncident(inc.ID, StatusInvestigating, "evil\nactor", reason); err != nil {
		t.Fatal(err)
	}
	evs, _ := db.ListIncidentEvents(inc.ID)
	if len(evs) != 1 {
		t.Fatal("expected one event")
	}
	if strings.ContainsAny(evs[0].Detail+evs[0].Actor, "\n\x00\x1b") {
		t.Errorf("control characters survived: %q %q", evs[0].Detail, evs[0].Actor)
	}
	if len(evs[0].Detail) > maxEventDetailLen {
		t.Errorf("detail not bounded: %d", len(evs[0].Detail))
	}
}

func TestLifecycle_EventHistoryBounded(t *testing.T) {
	db := fileDB(t)
	inc := newInc(t, db)
	for i := 0; i < maxEventsPerIncident+50; i++ {
		if err := db.AddIncidentEvent(IncidentEvent{IncidentID: inc.ID, Kind: EventResponse, Outcome: "attempted"}); err != nil {
			t.Fatal(err)
		}
	}
	evs, _ := db.ListIncidentEvents(inc.ID)
	if len(evs) != maxEventsPerIncident {
		t.Fatalf("history not bounded: %d", len(evs))
	}
}

func TestLifecycle_ConcurrentTransitionsExactlyOneWins(t *testing.T) {
	db := fileDB(t)
	inc := newInc(t, db)
	targets := []IncidentStatus{StatusResolved, StatusFalsePositive, StatusInvestigating, StatusAutoBlocked}
	var wg sync.WaitGroup
	results := make([]error, 16)
	for i := range results {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, results[i] = db.TransitionIncident(inc.ID, targets[i%len(targets)], "worker", "race")
		}(i)
	}
	wg.Wait()
	for _, err := range results {
		if err != nil && !errors.Is(err, ErrConflict) && !errors.Is(err, ErrInvalidTransition) && !isBusy(err) {
			t.Errorf("unexpected error: %v", err)
		}
	}
	// The audit trail must be a consistent chain: each event's from-status
	// equals the previous event's to-status, starting from open.
	evs, _ := db.ListIncidentEvents(inc.ID)
	prev := string(StatusOpen)
	for _, ev := range evs {
		if ev.FromStatus != prev {
			t.Fatalf("broken audit chain: %+v", evs)
		}
		prev = ev.ToStatus
	}
	cur, _ := db.GetIncident(inc.ID)
	if string(cur.Status) != prev {
		t.Fatalf("final status %s does not match audit chain end %s", cur.Status, prev)
	}
}

func isBusy(err error) bool {
	return err != nil && strings.Contains(strings.ToLower(err.Error()), "locked")
}

func TestLifecycle_ExistingDatabaseMigratesAdditively(t *testing.T) {
	path := filepath.Join(t.TempDir(), "old.db")
	db, err := Open(Config{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	inc := newInc(t, db)
	// Simulate a pre-Phase-5 database: drop the new table.
	if err := db.Migrator().DropTable(&IncidentEvent{}); err != nil {
		t.Fatal(err)
	}
	sqlClose(db)

	db2, err := Open(Config{Path: path})
	if err != nil {
		t.Fatalf("reopen/migrate old DB: %v", err)
	}
	defer sqlClose(db2)
	got, err := db2.GetIncident(inc.ID)
	if err != nil || got.SourceIP != "203.0.113.5" {
		t.Fatalf("existing incidents must survive migration: %v", err)
	}
	if _, err := db2.TransitionIncident(inc.ID, StatusResolved, "a", ""); err != nil {
		t.Fatalf("lifecycle on migrated DB: %v", err)
	}
}
