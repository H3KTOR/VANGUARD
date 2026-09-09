package firewall

import (
	"context"
	"testing"
	"time"

	"vanguard/core/internal/database"
)

func testAutopilot(t *testing.T, cfg Config) (*Autopilot, *database.DB, *MockExecutor) {
	t.Helper()
	db, err := database.Open(database.Config{Path: ":memory:"})
	if err != nil {
		t.Fatalf("failed to open db: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	exec := NewMockExecutor()
	return NewAutopilot(db, exec, cfg), db, exec
}

func TestAutopilotAutoBansHighRiskIncident(t *testing.T) {
	cfg := DefaultConfig()
	a, db, exec := testAutopilot(t, cfg)

	inc := &database.Incident{
		Type: database.IncidentSSHBruteForce, SourceIP: "203.0.113.10",
		RiskScore: 75, Severity: database.SeverityHigh, Status: database.StatusOpen,
	}
	if err := db.CreateIncident(inc); err != nil {
		t.Fatalf("failed to create incident: %v", err)
	}

	a.OnIncident(inc)

	if !exec.Blocked["203.0.113.10"] {
		t.Fatalf("expected IP to be blocked at the OS level")
	}
	banned, err := db.IsBanned("203.0.113.10")
	if err != nil || !banned {
		t.Fatalf("expected IsBanned=true, got %v err=%v", banned, err)
	}
	got, err := db.GetIncident(inc.ID)
	if err != nil {
		t.Fatalf("GetIncident failed: %v", err)
	}
	if got.Status != database.StatusAutoBlocked {
		t.Errorf("expected status auto_blocked, got %s", got.Status)
	}
}

func TestAutopilotNeverBansWhitelistedIP(t *testing.T) {
	cfg := DefaultConfig()
	a, db, exec := testAutopilot(t, cfg)

	ip := "203.0.113.99"
	if err := db.CreateFirewallRule(&database.FirewallRule{
		IPAddress: ip, IsWhitelisted: true, IsActive: true, Reason: "admin office",
	}); err != nil {
		t.Fatalf("failed to seed whitelist: %v", err)
	}

	inc := &database.Incident{
		Type: database.IncidentHoneypotTrigger, SourceIP: ip,
		RiskScore: 95, Severity: database.SeverityCritical, Status: database.StatusOpen,
	}
	if err := db.CreateIncident(inc); err != nil {
		t.Fatalf("failed to create incident: %v", err)
	}

	a.OnIncident(inc)

	if exec.Blocked[ip] {
		t.Fatalf("fail-safe violated: whitelisted IP %s was blocked despite CRITICAL risk score", ip)
	}
	banned, _ := db.IsBanned(ip)
	if banned {
		t.Fatalf("fail-safe violated: whitelisted IP has an active ban record")
	}
}

func TestAutopilotSkipsBelowThreshold(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MinRiskScoreToBan = 60
	a, db, exec := testAutopilot(t, cfg)

	inc := &database.Incident{
		Type: database.IncidentWebDirScan, SourceIP: "203.0.113.20",
		RiskScore: 25, Severity: database.SeverityLow, Status: database.StatusOpen,
	}
	if err := db.CreateIncident(inc); err != nil {
		t.Fatalf("failed to create incident: %v", err)
	}

	a.OnIncident(inc)

	if exec.Blocked["203.0.113.20"] {
		t.Fatalf("expected low-risk incident to NOT trigger an auto-ban")
	}
}

func TestAutopilotDisabledSkipsAllBans(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = false
	a, db, exec := testAutopilot(t, cfg)

	inc := &database.Incident{
		Type: database.IncidentHoneypotTrigger, SourceIP: "203.0.113.30",
		RiskScore: 100, Severity: database.SeverityCritical, Status: database.StatusOpen,
	}
	if err := db.CreateIncident(inc); err != nil {
		t.Fatalf("failed to create incident: %v", err)
	}
	a.OnIncident(inc)

	if exec.Blocked["203.0.113.30"] {
		t.Fatalf("expected Autopilot.Enabled=false to prevent all auto-bans")
	}
}

func TestAdminWhitelistSeededOnStartup(t *testing.T) {
	cfg := DefaultConfig()
	cfg.AdminWhitelistIPs = []string{"198.51.100.1"}
	a, db, _ := testAutopilot(t, cfg)
	_ = a

	whitelisted, err := db.IsWhitelisted("198.51.100.1")
	if err != nil {
		t.Fatalf("IsWhitelisted failed: %v", err)
	}
	if !whitelisted {
		t.Fatalf("expected admin IP to be whitelisted immediately on Autopilot construction")
	}
}

func TestHostLocalIPAlwaysWhitelisted(t *testing.T) {
	// database.HostLocalIP (and ::1) must be whitelisted unconditionally,
	// even with zero operator-configured AdminWhitelistIPs, so host-
	// security findings (Mega Expansion Phase 1) can never trigger a
	// self-ban -- see alwaysWhitelistedIPs' doc comment in autopilot.go.
	cfg := DefaultConfig()
	cfg.AdminWhitelistIPs = nil
	a, db, _ := testAutopilot(t, cfg)
	_ = a

	for _, ip := range []string{database.HostLocalIP, "::1"} {
		whitelisted, err := db.IsWhitelisted(ip)
		if err != nil {
			t.Fatalf("IsWhitelisted(%s) failed: %v", ip, err)
		}
		if !whitelisted {
			t.Fatalf("expected %s to be unconditionally whitelisted on Autopilot construction", ip)
		}
	}
}

func TestHostLocalFindingNeverAutoBanned(t *testing.T) {
	// End-to-end fail-safe check: an incident sourced at HostLocalIP with
	// a CRITICAL risk score must never result in an actual ban, mirroring
	// TestAutopilotNeverBansWhitelistedIP but for the host-security path.
	cfg := DefaultConfig()
	a, db, exec := testAutopilot(t, cfg)

	inc := &database.Incident{
		Type: database.IncidentPrivilegeEscalation, SourceIP: database.HostLocalIP,
		RiskScore: 95, Severity: database.SeverityCritical, Status: database.StatusOpen,
	}
	if err := db.CreateIncident(inc); err != nil {
		t.Fatalf("failed to create incident: %v", err)
	}

	a.OnIncident(inc)

	if exec.Blocked[database.HostLocalIP] {
		t.Fatalf("fail-safe violated: HostLocalIP was blocked despite CRITICAL risk score")
	}
	banned, _ := db.IsBanned(database.HostLocalIP)
	if banned {
		t.Fatalf("fail-safe violated: HostLocalIP has an active ban record")
	}
}

func TestTTLBanExpiresAndIsReaped(t *testing.T) {
	cfg := DefaultConfig()
	a, db, exec := testAutopilot(t, cfg)
	ctx := context.Background()

	ip := "203.0.113.40"
	if err := a.Ban(ctx, ip, "test ban", 1*time.Millisecond, nil, database.FirewallSourceManual); err != nil {
		t.Fatalf("Ban failed: %v", err)
	}
	time.Sleep(5 * time.Millisecond)

	n, err := a.ReapExpiredBans(ctx)
	if err != nil {
		t.Fatalf("ReapExpiredBans failed: %v", err)
	}
	if n != 1 {
		t.Fatalf("expected 1 rule reaped, got %d", n)
	}
	if exec.Blocked[ip] {
		t.Fatalf("expected IP to be unblocked at OS level after TTL reap")
	}
	banned, _ := db.IsBanned(ip)
	if banned {
		t.Fatalf("expected IsBanned=false after TTL reap")
	}
}

func TestBanRefusesWhitelistedIPEvenWhenCalledDirectly(t *testing.T) {
	cfg := DefaultConfig()
	a, db, exec := testAutopilot(t, cfg)
	ctx := context.Background()
	ip := "203.0.113.50"

	if err := db.CreateFirewallRule(&database.FirewallRule{
		IPAddress: ip, IsWhitelisted: true, IsActive: true,
	}); err != nil {
		t.Fatalf("seed failed: %v", err)
	}

	err := a.Ban(ctx, ip, "manual attempt", time.Hour, nil, database.FirewallSourceManual)
	if err == nil {
		t.Fatalf("expected Ban() to refuse a whitelisted IP, got nil error")
	}
	if exec.Blocked[ip] {
		t.Fatalf("fail-safe violated: whitelisted IP was blocked via direct Ban() call")
	}
}

func TestWhitelistLiftsExistingBan(t *testing.T) {
	cfg := DefaultConfig()
	a, db, exec := testAutopilot(t, cfg)
	ctx := context.Background()
	ip := "203.0.113.60"

	if err := a.Ban(ctx, ip, "initial ban", time.Hour, nil, database.FirewallSourceManual); err != nil {
		t.Fatalf("Ban failed: %v", err)
	}
	banned, _ := db.IsBanned(ip)
	if !banned {
		t.Fatalf("expected IP to be banned before whitelisting")
	}

	if err := a.Whitelist(ctx, ip, "false positive, trusted partner"); err != nil {
		t.Fatalf("Whitelist failed: %v", err)
	}

	banned, _ = db.IsBanned(ip)
	if banned {
		t.Fatalf("expected ban to be lifted after whitelisting")
	}
	if exec.Blocked[ip] {
		t.Fatalf("expected OS-level block to be removed after whitelisting")
	}
	if !exec.Allowed[ip] {
		t.Fatalf("expected OS-level allow rule after whitelisting")
	}
}

func TestPanicModeDryRunPreviewDoesNotExecute(t *testing.T) {
	cfg := DefaultConfig()
	cfg.AdminWhitelistIPs = []string{"198.51.100.5"}
	a, _, exec := testAutopilot(t, cfg)

	preview := a.PreviewPanicMode("203.0.113.1")
	if !preview.WillBlockAllOthers {
		t.Errorf("expected preview to indicate all other traffic would be blocked")
	}
	if len(preview.WillAllowIPs) != 2 {
		t.Errorf("expected 2 allowed IPs in preview (admin whitelist + caller), got %v", preview.WillAllowIPs)
	}
	if exec.Lockdown {
		t.Fatalf("dry-run preview must NEVER call the executor")
	}
}

func TestPanicModeRequiresExplicitConfirmation(t *testing.T) {
	cfg := DefaultConfig()
	a, _, exec := testAutopilot(t, cfg)
	ctx := context.Background()

	err := a.EnterPanicMode(ctx, "203.0.113.1", "testing", false)
	if err == nil {
		t.Fatalf("expected EnterPanicMode to reject confirmed=false")
	}
	if exec.Lockdown {
		t.Fatalf("lockdown must not be enabled without explicit confirmation")
	}
}

func TestPanicModeEnableAndManualExit(t *testing.T) {
	cfg := DefaultConfig()
	cfg.PanicModeAutoRollback = time.Hour // long enough not to fire during the test
	a, _, exec := testAutopilot(t, cfg)
	ctx := context.Background()

	if err := a.EnterPanicMode(ctx, "203.0.113.1", "drill", true); err != nil {
		t.Fatalf("EnterPanicMode failed: %v", err)
	}
	if !exec.Lockdown {
		t.Fatalf("expected lockdown to be active at OS level")
	}
	status := a.PanicModeStatus()
	if !status.Active {
		t.Fatalf("expected PanicModeStatus().Active == true")
	}

	if err := a.ExitPanicMode(ctx, "manual exit"); err != nil {
		t.Fatalf("ExitPanicMode failed: %v", err)
	}
	if exec.Lockdown {
		t.Fatalf("expected lockdown to be disabled at OS level")
	}
	status = a.PanicModeStatus()
	if status.Active {
		t.Fatalf("expected PanicModeStatus().Active == false after exit")
	}
}

func TestPanicModeAutoRollbackFiresAfterTimeout(t *testing.T) {
	cfg := DefaultConfig()
	cfg.PanicModeAutoRollback = 20 * time.Millisecond
	a, _, exec := testAutopilot(t, cfg)
	ctx := context.Background()

	if err := a.EnterPanicMode(ctx, "203.0.113.1", "drill", true); err != nil {
		t.Fatalf("EnterPanicMode failed: %v", err)
	}
	if !exec.Lockdown {
		t.Fatalf("expected lockdown active immediately after enable")
	}

	time.Sleep(100 * time.Millisecond)

	if exec.Lockdown {
		t.Fatalf("expected emergency auto-rollback to have disabled lockdown by now")
	}
	if a.PanicModeStatus().Active {
		t.Fatalf("expected PanicModeStatus().Active == false after auto-rollback")
	}
}

// ---------------------------------------------------------------------------
// AlertNotifier wiring (Telegram alerts)
// ---------------------------------------------------------------------------

// fakeAlertNotifier records every call it receives instead of making a
// real network call, letting us assert Autopilot's alert-on-ban wiring
// without depending on the notify package or the real Telegram API.
type fakeAlertNotifier struct {
	bans        int
	lastIP      string
	lastType    string
	lastSev     string
	lastRisk    int
	panicCalls  int
	lastActive  bool
	lastPReason string
}

func (f *fakeAlertNotifier) NotifyBan(ctx context.Context, ip, incidentType, severity string, riskScore int, duration time.Duration, reason string) {
	f.bans++
	f.lastIP = ip
	f.lastType = incidentType
	f.lastSev = severity
	f.lastRisk = riskScore
}

func (f *fakeAlertNotifier) NotifyPanicMode(ctx context.Context, active bool, reason string) {
	f.panicCalls++
	f.lastActive = active
	f.lastPReason = reason
}

func TestAutopilotNotifiesOnBan(t *testing.T) {
	cfg := DefaultConfig()
	a, db, _ := testAutopilot(t, cfg)
	notifier := &fakeAlertNotifier{}
	a.SetAlertNotifier(notifier)

	inc := &database.Incident{
		Type: database.IncidentSSHBruteForce, SourceIP: "203.0.113.80",
		RiskScore: 80, Severity: database.SeverityHigh, Status: database.StatusOpen,
	}
	if err := db.CreateIncident(inc); err != nil {
		t.Fatalf("failed to create incident: %v", err)
	}

	a.OnIncident(inc)

	if notifier.bans != 1 {
		t.Fatalf("expected exactly 1 NotifyBan call, got %d", notifier.bans)
	}
	if notifier.lastIP != "203.0.113.80" {
		t.Errorf("expected notified IP 203.0.113.80, got %s", notifier.lastIP)
	}
	if notifier.lastType != string(database.IncidentSSHBruteForce) {
		t.Errorf("expected notified type %s, got %s", database.IncidentSSHBruteForce, notifier.lastType)
	}
	if notifier.lastRisk != 80 {
		t.Errorf("expected notified risk score 80, got %d", notifier.lastRisk)
	}
}

func TestAutopilotDoesNotNotifyWithoutAttachedNotifier(t *testing.T) {
	cfg := DefaultConfig()
	a, db, _ := testAutopilot(t, cfg) // no SetAlertNotifier call

	inc := &database.Incident{
		Type: database.IncidentSSHBruteForce, SourceIP: "203.0.113.81",
		RiskScore: 80, Severity: database.SeverityHigh, Status: database.StatusOpen,
	}
	if err := db.CreateIncident(inc); err != nil {
		t.Fatalf("failed to create incident: %v", err)
	}

	// Must not panic when a.alert is nil.
	a.OnIncident(inc)
}

func TestAutopilotDoesNotNotifyWhitelistedOrBelowThreshold(t *testing.T) {
	cfg := DefaultConfig()
	a, db, _ := testAutopilot(t, cfg)
	notifier := &fakeAlertNotifier{}
	a.SetAlertNotifier(notifier)

	inc := &database.Incident{
		Type: database.IncidentWebDirScan, SourceIP: "203.0.113.82",
		RiskScore: 10, Severity: database.SeverityLow, Status: database.StatusOpen,
	}
	if err := db.CreateIncident(inc); err != nil {
		t.Fatalf("failed to create incident: %v", err)
	}

	a.OnIncident(inc)

	if notifier.bans != 0 {
		t.Fatalf("expected no NotifyBan call for a below-threshold incident, got %d", notifier.bans)
	}
}

func TestPanicModeNotifiesOnEnterAndExit(t *testing.T) {
	cfg := DefaultConfig()
	cfg.PanicModeAutoRollback = time.Hour
	a, _, _ := testAutopilot(t, cfg)
	notifier := &fakeAlertNotifier{}
	a.SetAlertNotifier(notifier)
	ctx := context.Background()

	if err := a.EnterPanicMode(ctx, "203.0.113.1", "drill", true); err != nil {
		t.Fatalf("EnterPanicMode failed: %v", err)
	}
	if notifier.panicCalls != 1 || !notifier.lastActive {
		t.Fatalf("expected 1 NotifyPanicMode(active=true) call, got calls=%d active=%v", notifier.panicCalls, notifier.lastActive)
	}

	if err := a.ExitPanicMode(ctx, "manual exit"); err != nil {
		t.Fatalf("ExitPanicMode failed: %v", err)
	}
	if notifier.panicCalls != 2 || notifier.lastActive {
		t.Fatalf("expected a second NotifyPanicMode(active=false) call, got calls=%d active=%v", notifier.panicCalls, notifier.lastActive)
	}
}

func TestReconcileOnStartupReappliesActiveBans(t *testing.T) {
	cfg := DefaultConfig()
	db, err := database.Open(database.Config{Path: ":memory:"})
	if err != nil {
		t.Fatalf("failed to open db: %v", err)
	}
	defer db.Close()

	unbanAt := time.Now().UTC().Add(time.Hour)
	if err := db.CreateFirewallRule(&database.FirewallRule{
		IPAddress: "203.0.113.70", IsActive: true, UnbanAt: &unbanAt, Reason: "pre-existing ban",
	}); err != nil {
		t.Fatalf("seed failed: %v", err)
	}

	exec := NewMockExecutor()
	a := NewAutopilot(db, exec, cfg)

	if err := a.ReconcileOnStartup(context.Background()); err != nil {
		t.Fatalf("ReconcileOnStartup failed: %v", err)
	}
	if !exec.Blocked["203.0.113.70"] {
		t.Fatalf("expected startup reconciliation to re-apply the pre-existing DB ban at the OS level")
	}
}
