package firewall

import (
	"context"
	"path/filepath"
	"sync"
	"testing"

	"vanguard/core/internal/database"
)

func fileAutopilot(t *testing.T, path string) (*Autopilot, *database.DB, *MockExecutor) {
	t.Helper()
	db, err := database.Open(database.Config{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if s, err := db.DB.DB(); err == nil {
			s.Close()
		}
	})
	exec := NewMockExecutor()
	return NewAutopilot(db, exec, DefaultConfig()), db, exec
}

// Many detectors/analysts can react to the same actor at once. The ban for
// one address must be applied exactly once.
func TestSafety_ConcurrentResponsesToOneActorCreateOneBan(t *testing.T) {
	a, db, exec := fileAutopilot(t, filepath.Join(t.TempDir(), "c.db"))
	var incs []*database.Incident
	for i := 0; i < 12; i++ {
		inc := &database.Incident{Type: database.IncidentSSHBruteForce, SourceIP: "203.0.113.90", RiskScore: 80}
		if err := db.CreateIncident(inc); err != nil {
			t.Fatal(err)
		}
		incs = append(incs, inc)
	}
	var wg sync.WaitGroup
	for _, inc := range incs {
		wg.Add(1)
		go func(inc *database.Incident) {
			defer wg.Done()
			_ = a.HandleIncident(context.Background(), inc)
		}(inc)
	}
	wg.Wait()

	rules, _ := db.ListFirewallRules(true)
	active := 0
	for _, r := range rules {
		if r.IPAddress == "203.0.113.90" && r.IsActive && !r.IsWhitelisted {
			active++
		}
	}
	if active != 1 {
		t.Fatalf("expected exactly 1 active ban rule for the actor, got %d", active)
	}
	blocks := 0
	exec.mu.Lock()
	for _, c := range exec.Calls {
		if c == "block 203.0.113.90" {
			blocks++
		}
	}
	exec.mu.Unlock()
	if blocks != 1 {
		t.Fatalf("expected exactly 1 firewall block command, got %d", blocks)
	}
}

// A restart must not lose the outcome of a response nor re-run it.
func TestSafety_RestartPreservesResponseOutcome(t *testing.T) {
	path := filepath.Join(t.TempDir(), "r.db")
	a, db, _ := fileAutopilot(t, path)
	inc := &database.Incident{Type: database.IncidentSSHBruteForce, SourceIP: "203.0.113.91", RiskScore: 80}
	_ = db.CreateIncident(inc)
	_ = a.HandleIncident(context.Background(), inc)
	if s, err := db.DB.DB(); err == nil {
		s.Close()
	}

	a2, db2, exec2 := fileAutopilot(t, path) // "restart": fresh process, fresh (empty) executor
	cur, _ := db2.GetIncident(inc.ID)
	if cur.Status != database.StatusAutoBlocked {
		t.Fatalf("incident status lost: %s", cur.Status)
	}
	evs, _ := db2.ListIncidentEvents(inc.ID)
	if !hasEvent(evs, database.EventResponse, "succeeded") || !hasEvent(evs, database.EventVerification, "verified") {
		t.Fatalf("outcome events lost: %+v", evs)
	}
	if err := a2.ReconcileOnStartup(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !exec2.Blocked["203.0.113.91"] {
		t.Fatal("active ban must be re-applied to the fresh firewall on startup")
	}
	// Re-evaluating the same incident must not create a second ban.
	_ = a2.HandleIncident(context.Background(), inc)
	rules, _ := db2.ListFirewallRules(true)
	n := 0
	for _, r := range rules {
		if r.IPAddress == "203.0.113.91" && !r.IsWhitelisted {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("restart re-evaluation duplicated the ban: %d rules", n)
	}
}
