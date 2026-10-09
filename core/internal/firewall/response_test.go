package firewall

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"gorm.io/gorm"

	"vanguard/core/internal/database"
)

func hiRisk(t *testing.T, db *database.DB, ip string) *database.Incident {
	t.Helper()
	inc := &database.Incident{Type: database.IncidentSSHBruteForce, SourceIP: ip, RiskScore: 75}
	if err := db.CreateIncident(inc); err != nil {
		t.Fatal(err)
	}
	return inc
}

func eventsOf(t *testing.T, db *database.DB, id uint) []database.IncidentEvent {
	t.Helper()
	evs, err := db.ListIncidentEvents(id)
	if err != nil {
		t.Fatal(err)
	}
	return evs
}

func hasEvent(evs []database.IncidentEvent, kind, outcome string) bool {
	for _, e := range evs {
		if e.Kind == kind && e.Outcome == outcome {
			return true
		}
	}
	return false
}

func TestPlan_IsNonMutatingAndMatchesExecution(t *testing.T) {
	a, db, exec := testAutopilot(t, DefaultConfig())
	inc := hiRisk(t, db, "203.0.113.50")

	d, err := a.Plan(inc)
	if err != nil || !d.WouldBan || d.Executed || d.Outcome != "would_ban" || d.DurationSeconds <= 0 {
		t.Fatalf("plan = %+v err=%v", d, err)
	}
	if len(exec.Calls) != 0 {
		t.Fatalf("Plan must not touch the firewall: %v", exec.Calls)
	}
	if n := len(eventsOf(t, db, inc.ID)); n != 0 {
		t.Fatalf("Plan must not write audit events, got %d", n)
	}
	if banned, _ := db.IsBanned(inc.SourceIP); banned {
		t.Fatal("Plan must not persist a ban")
	}
	if cur, _ := db.GetIncident(inc.ID); cur.Status != database.StatusOpen {
		t.Fatalf("Plan changed incident status to %s", cur.Status)
	}

	// The preview must agree with real execution.
	_ = a.HandleIncident(context.Background(), inc)
	if !exec.Blocked[inc.SourceIP] {
		t.Fatal("plan said would_ban but execution did not ban")
	}
	// ...and now report already_banned.
	if d2, _ := a.Plan(inc); d2.WouldBan || d2.Outcome != "already_banned" {
		t.Fatalf("post-ban plan = %+v", d2)
	}
}

func TestPlan_Outcomes(t *testing.T) {
	cfg := DefaultConfig()
	a, db, _ := testAutopilot(t, cfg)
	low := &database.Incident{Type: database.IncidentPortScan, SourceIP: "203.0.113.51", RiskScore: 10}
	_ = db.CreateIncident(low)
	if d, _ := a.Plan(low); d.WouldBan || d.Outcome != "below_threshold" {
		t.Errorf("low risk: %+v", d)
	}
	_ = db.CreateFirewallRule(&database.FirewallRule{IPAddress: "203.0.113.52", IsWhitelisted: true, IsActive: true})
	wl := hiRisk(t, db, "203.0.113.52")
	if d, _ := a.Plan(wl); d.WouldBan || d.Outcome != "whitelisted" {
		t.Errorf("whitelisted: %+v", d)
	}
	cfg.Enabled = false
	a2, db2, _ := testAutopilot(t, cfg)
	if d, _ := a2.Plan(hiRisk(t, db2, "203.0.113.53")); d.WouldBan || d.Outcome != "disabled" {
		t.Errorf("disabled: %+v", d)
	}
}

func TestResponse_SuccessIsVerifiedAndRecorded(t *testing.T) {
	a, db, _ := testAutopilot(t, DefaultConfig())
	inc := hiRisk(t, db, "203.0.113.60")
	a.OnIncident(inc)
	evs := eventsOf(t, db, inc.ID)
	if !hasEvent(evs, database.EventResponse, "succeeded") || !hasEvent(evs, database.EventVerification, "verified") {
		t.Fatalf("expected succeeded + verified, got %+v", evs)
	}
	if cur, _ := db.GetIncident(inc.ID); cur.Status != database.StatusAutoBlocked {
		t.Errorf("status = %s", cur.Status)
	}
}

func TestResponse_SucceededIsNotVerified_WhenCommandHadNoEffect(t *testing.T) {
	a, db, exec := testAutopilot(t, DefaultConfig())
	exec.NoEffect = true // command "succeeds" but the firewall does not block
	inc := hiRisk(t, db, "203.0.113.61")
	err := a.HandleIncident(context.Background(), inc)
	if err == nil {
		t.Fatal("unverifiable ban must surface an error")
	}
	evs := eventsOf(t, db, inc.ID)
	if !hasEvent(evs, database.EventResponse, "succeeded") || !hasEvent(evs, database.EventVerification, "failed") || hasEvent(evs, database.EventVerification, "verified") {
		t.Fatalf("events = %+v", evs)
	}
	cur, _ := db.GetIncident(inc.ID)
	if cur.Status == database.StatusAutoBlocked {
		t.Fatal("incident must not claim auto_blocked when verification failed")
	}
	if banned, _ := db.IsBanned(inc.SourceIP); banned {
		t.Fatal("non-enforcing rule must be deactivated so a later incident can retry")
	}
}

func TestResponse_VerificationErrorIsInconclusiveNotVerified(t *testing.T) {
	a, db, exec := testAutopilot(t, DefaultConfig())
	exec.VerifyErr = errors.New("ufw status exploded")
	inc := hiRisk(t, db, "203.0.113.62")
	if err := a.HandleIncident(context.Background(), inc); err != nil {
		t.Fatalf("inconclusive verification must not fail the ban: %v", err)
	}
	evs := eventsOf(t, db, inc.ID)
	if !hasEvent(evs, database.EventVerification, "inconclusive") || hasEvent(evs, database.EventVerification, "verified") {
		t.Fatalf("events = %+v", evs)
	}
	if banned, _ := db.IsBanned(inc.SourceIP); !banned {
		t.Fatal("block must be kept when verification is merely inconclusive")
	}
}

func TestResponse_VerificationTimeoutIsInconclusive(t *testing.T) {
	old := verifyTimeout
	verifyTimeout = 40 * time.Millisecond
	defer func() { verifyTimeout = old }()
	a, db, exec := testAutopilot(t, DefaultConfig())
	exec.VerifyDelay = 2 * time.Second
	inc := hiRisk(t, db, "203.0.113.63")
	start := time.Now()
	_ = a.HandleIncident(context.Background(), inc)
	if time.Since(start) > time.Second {
		t.Fatal("verification must be bounded by its timeout")
	}
	evs := eventsOf(t, db, inc.ID)
	var detail string
	for _, e := range evs {
		if e.Kind == database.EventVerification {
			detail = e.Outcome + ":" + e.Detail
		}
	}
	if !strings.HasPrefix(detail, "inconclusive:") || !strings.Contains(detail, "timed out") {
		t.Fatalf("timeout must be inconclusive, got %q", detail)
	}
}

func TestResponse_BlockFailureRecordedAndIncidentKept(t *testing.T) {
	a, db, exec := testAutopilot(t, DefaultConfig())
	exec.BlockErr = errors.New("ufw: permission denied")
	inc := hiRisk(t, db, "203.0.113.64")
	if err := a.HandleIncident(context.Background(), inc); err == nil {
		t.Fatal("expected error")
	}
	evs := eventsOf(t, db, inc.ID)
	if !hasEvent(evs, database.EventResponse, "failed") {
		t.Fatalf("failure must be visible: %+v", evs)
	}
	cur, err := db.GetIncident(inc.ID)
	if err != nil || cur.Status != database.StatusOpen {
		t.Fatalf("original incident must survive a response failure untouched: %v %v", err, cur)
	}
	if banned, _ := db.IsBanned(inc.SourceIP); banned {
		t.Fatal("no rule may be persisted for a failed block")
	}
}

func TestResponse_PersistFailureRollsBackBlock(t *testing.T) {
	a, db, exec := testAutopilot(t, DefaultConfig())
	inc := hiRisk(t, db, "203.0.113.65")
	_ = db.Callback().Create().Before("gorm:create").Register("test:fail_fw", func(tx *gorm.DB) {
		if tx.Statement.Table == "firewall_rules" {
			_ = tx.AddError(errors.New("disk full"))
		}
	})
	if err := a.HandleIncident(context.Background(), inc); err == nil {
		t.Fatal("expected persist failure error")
	}
	if exec.Blocked[inc.SourceIP] {
		t.Fatal("orphaned block must be rolled back when the rule cannot be persisted")
	}
	evs := eventsOf(t, db, inc.ID)
	found := false
	for _, e := range evs {
		if e.Outcome == "failed" && strings.Contains(e.Detail, "rollback of block: ok") {
			found = true
		}
	}
	if !found {
		t.Fatalf("rollback must be recorded: %+v", evs)
	}
}

func TestResponse_WhitelistSuppressedAndNeverBlocked(t *testing.T) {
	a, db, exec := testAutopilot(t, DefaultConfig())
	_ = db.CreateFirewallRule(&database.FirewallRule{IPAddress: "203.0.113.66", IsWhitelisted: true, IsActive: true})
	inc := hiRisk(t, db, "203.0.113.66")
	_ = a.HandleIncident(context.Background(), inc)
	if len(exec.Calls) != 0 {
		t.Fatalf("whitelisted IP must never reach the executor: %v", exec.Calls)
	}
	if !hasEvent(eventsOf(t, db, inc.ID), database.EventResponse, "suppressed") {
		t.Fatal("suppression must be recorded")
	}
	// Direct Ban() (manual path) is also refused and recorded.
	id := inc.ID
	if err := a.Ban(context.Background(), "203.0.113.66", "manual", time.Hour, &id, database.FirewallSourceManual); err == nil {
		t.Fatal("manual ban of a whitelisted IP must be refused")
	}
	if len(exec.Calls) != 0 {
		t.Fatalf("executor touched: %v", exec.Calls)
	}
}

func TestResponse_DoesNotOverwriteAnalystDecision(t *testing.T) {
	a, db, _ := testAutopilot(t, DefaultConfig())
	inc := hiRisk(t, db, "203.0.113.67")
	if _, err := db.TransitionIncident(inc.ID, database.StatusFalsePositive, "analyst", "benign scanner"); err != nil {
		t.Fatal(err)
	}
	_ = a.HandleIncident(context.Background(), inc)
	if cur, _ := db.GetIncident(inc.ID); cur.Status != database.StatusFalsePositive {
		t.Fatalf("response overwrote analyst decision: %s", cur.Status)
	}
}

func TestResponse_NotEligibleRecorded(t *testing.T) {
	a, db, exec := testAutopilot(t, DefaultConfig())
	low := &database.Incident{Type: database.IncidentPortScan, SourceIP: "203.0.113.68", RiskScore: 5}
	_ = db.CreateIncident(low)
	a.OnIncident(low)
	if len(exec.Calls) != 0 || !hasEvent(eventsOf(t, db, low.ID), database.EventResponse, "not_eligible") {
		t.Fatalf("calls=%v events=%+v", exec.Calls, eventsOf(t, db, low.ID))
	}
}

func TestUFWStatusParsing(t *testing.T) {
	active := "Status: active\n\nTo                         Action      From\n--                         ------      ----\nAnywhere                   DENY        203.0.113.9\n22/tcp                     ALLOW       Anywhere\n"
	if d, a := ufwStatusDenies(active, "203.0.113.9"); !d || !a {
		t.Errorf("active deny: %v %v", d, a)
	}
	if d, _ := ufwStatusDenies(active, "203.0.113.90"); d {
		t.Error("substring IP must not match")
	}
	if d, _ := ufwStatusDenies(active, "198.51.100.1"); d {
		t.Error("absent IP")
	}
	if d, a := ufwStatusDenies("Status: inactive\n", "203.0.113.9"); d || a {
		t.Errorf("inactive: %v %v", d, a)
	}
	inactiveWithRule := "Status: inactive\nAnywhere DENY 203.0.113.9\n"
	if d, a := ufwStatusDenies(inactiveWithRule, "203.0.113.9"); !d || a {
		t.Errorf("rule present but firewall inactive must report active=false: %v %v", d, a)
	}
}

func TestMockExecutorConcurrentUse(t *testing.T) {
	m := NewMockExecutor()
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			ip := "10.0.0." + string(rune('a'+i%5))
			_ = m.Block(context.Background(), ip)
			_, _ = m.IsBlocked(context.Background(), ip)
			_ = m.Unblock(context.Background(), ip)
			_, _ = m.Status(context.Background())
		}(i)
	}
	wg.Wait()
}
