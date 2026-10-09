package firewall

import (
	"context"
	"fmt"
	"log"
	"time"

	"vanguard/core/internal/database"
)

// DefaultTTL is the ban duration applied when a caller doesn't specify one.
const DefaultTTL = 1 * time.Hour

// AlertNotifier is the minimal surface Autopilot needs to push a real-time
// alert (e.g. Telegram) when it bans an IP or toggles Panic Mode. Defined
// here -- rather than importing internal/notify directly -- so the
// firewall package stays decoupled from any specific alert channel; the
// concrete *notify.TelegramNotifier satisfies this interface structurally.
// A nil AlertNotifier (the zero value) is always safe: every call site
// nil-checks before calling, exactly like the *notify.TelegramNotifier
// receiver itself does.
type AlertNotifier interface {
	NotifyBan(ctx context.Context, ip, incidentType, severity string, riskScore int, duration time.Duration, reason string)
	NotifyPanicMode(ctx context.Context, active bool, reason string)
}

// Autopilot is VANGUARD's automated mitigation layer. It subscribes to the
// detection Engine (via its Notifier interface) and, for qualifying
// incidents, issues a TTL ban -- unless the source IP is protected by the
// fail-safe whitelist, in which case the ban is always skipped no matter
// what the risk score is.
//
// Autopilot also owns Panic Mode (site-wide lockdown) and the TTL reaper
// that expires bans on schedule.
type Autopilot struct {
	db       *database.DB
	exec     Executor
	cfg      Config
	panicCtl panicController // Panic Mode / lockdown state, see panic_mode.go
	alert    AlertNotifier   // optional; nil disables push alerts entirely
}

// Config controls Autopilot behavior.
type Config struct {
	// Enabled turns automatic banning on/off. When false, Autopilot still
	// records what it *would* do (useful for a supervised rollout) but
	// never calls Executor.
	Enabled bool
	// MinRiskScoreToBan: incidents below this score are logged but not
	// auto-banned (left for manual review). Per spec, HIGH (60+) and
	// CRITICAL (80+) are the natural auto-response tier; MEDIUM is
	// borderline and configurable.
	MinRiskScoreToBan int
	// DefaultBanDuration is used when a specific incident type doesn't
	// define its own TTL below.
	DefaultBanDuration time.Duration
	// BanDurationByType lets operators tune TTLs per signature (e.g.
	// honeypot hits get a much longer ban than a borderline port scan).
	BanDurationByType map[database.IncidentType]time.Duration
	// AdminWhitelistIPs are hardcoded/config-supplied IPs that must NEVER
	// be blocked, seeded into the DB whitelist on startup (belt-and-
	// suspenders alongside the DB-driven whitelist so a fresh install is
	// safe even before an operator adds entries via the dashboard).
	AdminWhitelistIPs []string
	// EssentialPorts are kept open during Panic Mode lockdown (e.g. 22 for
	// SSH admin access, 80/443 for the web app itself).
	EssentialPorts []int
	// PanicModeAutoRollback is how long Panic Mode stays active before
	// automatically disabling itself, guarding against an admin locking
	// themselves out. Per spec: 30 minutes.
	PanicModeAutoRollback time.Duration
}

// DefaultConfig returns sane defaults matching the spec's HIGH/CRITICAL
// auto-response tier and 30-minute Panic Mode rollback.
func DefaultConfig() Config {
	return Config{
		Enabled:            true,
		MinRiskScoreToBan:  60, // HIGH and above
		DefaultBanDuration: DefaultTTL,
		BanDurationByType: map[database.IncidentType]time.Duration{
			database.IncidentHoneypotTrigger:   24 * time.Hour,
			database.IncidentFailedThenSuccess: 24 * time.Hour,
			database.IncidentSSHBruteForce:     1 * time.Hour,
			database.IncidentPortScan:          3 * time.Hour,
			database.IncidentHTTPFlood:         1 * time.Hour,
			// ATTACK_CHAIN is VANGUARD's most severe correlated signature
			// (coordinated recon -> web-probing -> auth-probing from one
			// IP) -- ban for a full week, well beyond any other signature.
			database.IncidentAttackChain: 7 * 24 * time.Hour,
			database.IncidentWebScanner:  6 * time.Hour,
		},
		EssentialPorts:        []int{22, 80, 443},
		PanicModeAutoRollback: 30 * time.Minute,
	}
}

// NewAutopilot constructs an Autopilot bound to db and exec. On
// construction it seeds cfg.AdminWhitelistIPs into the database whitelist
// (idempotently) so the fail-safe is effective immediately, even before
// any incidents have been processed.
func NewAutopilot(db *database.DB, exec Executor, cfg Config) *Autopilot {
	a := &Autopilot{db: db, exec: exec, cfg: cfg}
	a.seedAdminWhitelist()
	return a
}

// SetAlertNotifier attaches (or detaches, if passed nil) a real-time alert
// channel. Kept as a separate setter rather than a NewAutopilot parameter
// so existing call sites (tests, simulator) that construct an Autopilot
// without any alerting need zero changes.
func (a *Autopilot) SetAlertNotifier(n AlertNotifier) {
	a.alert = n
}

// alwaysWhitelistedIPs are seeded into the fail-safe whitelist on every
// startup, unconditionally, regardless of cfg.AdminWhitelistIPs. Loopback
// addresses must never be bannable: VANGUARD's Host Security scanners
// (internal/hostsec, Mega Expansion Phase 1 -- FIM/Persistence/Account/
// PrivEsc/SUID) raise incidents with SourceIP = database.HostLocalIP
// ("127.0.0.1") for host-local findings that have no attacker IP to
// attribute to, and a future misconfiguration (e.g. an operator setting
// MinRiskScoreToBan very low) must never be able to turn "VANGUARD
// detected a local file change" into "VANGUARD firewalls itself off from
// its own loopback interface".
var alwaysWhitelistedIPs = []string{database.HostLocalIP, "::1"}

func (a *Autopilot) seedAdminWhitelist() {
	for _, ip := range append(append([]string{}, alwaysWhitelistedIPs...), a.cfg.AdminWhitelistIPs...) {
		if ip == "" {
			continue
		}
		whitelisted, err := a.db.IsWhitelisted(ip)
		if err != nil {
			log.Printf("[autopilot] failed to check whitelist for admin IP %s: %v", ip, err)
			continue
		}
		if whitelisted {
			continue
		}
		if err := a.db.CreateFirewallRule(&database.FirewallRule{
			IPAddress:     ip,
			Reason:        "Hardcoded admin whitelist (startup config)",
			Source:        database.FirewallSourceManual,
			IsWhitelisted: true,
			IsActive:      true,
			BannedAt:      time.Now().UTC(),
		}); err != nil {
			log.Printf("[autopilot] failed to seed admin whitelist for %s: %v", ip, err)
			continue
		}
		log.Printf("[autopilot] seeded fail-safe whitelist entry for admin IP %s", ip)
	}
}

// OnIncident implements detection.Notifier. It is the automatic entry
// point invoked by the detection Engine for every newly created incident.
func (a *Autopilot) OnIncident(inc *database.Incident) {
	ctx := context.Background()
	if err := a.HandleIncident(ctx, inc); err != nil {
		log.Printf("[autopilot] failed to handle incident #%d: %v", inc.ID, err)
	}
}

// HandleIncident applies Autopilot policy to a single incident: fail-safe
// whitelist check, minimum-score gate, then a TTL ban if warranted. The
// decision itself is made by Plan() -- the same function the read-only
// response-plan API uses -- so a preview can never disagree with what is
// executed. Every outcome (including "not eligible"/"suppressed") is
// recorded in the incident's audit trail.
// Exposed as a public method (not just via OnIncident) so the REST API can
// invoke the same logic on-demand.
func (a *Autopilot) HandleIncident(ctx context.Context, inc *database.Incident) error {
	var idp *uint
	if inc.ID != 0 {
		idp = &inc.ID
	}
	d, err := a.Plan(inc)
	if err != nil {
		a.recordEvent(idp, database.EventResponse, "failed", "policy evaluation failed: "+truncateDetail(err.Error()))
		return err
	}
	if !d.WouldBan {
		switch d.Outcome {
		case "disabled":
			log.Printf("[autopilot] disabled; incident #%d (%s, risk %d) left for manual review", inc.ID, inc.Type, inc.RiskScore)
		case "whitelisted":
			log.Printf("[autopilot] SKIPPED ban for incident #%d: %s is whitelisted (fail-safe)", inc.ID, inc.SourceIP)
		case "below_threshold":
			log.Printf("[autopilot] incident #%d (risk %d) below auto-ban threshold (%d); left open for manual review",
				inc.ID, inc.RiskScore, a.cfg.MinRiskScoreToBan)
		case "already_banned":
			log.Printf("[autopilot] %s already banned; incident #%d recorded but no new rule created", inc.SourceIP, inc.ID)
		}
		outcome := "not_eligible"
		if d.Outcome == "whitelisted" {
			outcome = "suppressed"
		}
		a.recordEvent(idp, database.EventResponse, outcome, d.Outcome+": "+d.Reason)
		return nil
	}

	return a.Ban(ctx, inc.SourceIP, fmt.Sprintf("Autopilot: %s (incident #%d, risk %d)", inc.Type, inc.ID, inc.RiskScore),
		time.Duration(d.DurationSeconds)*time.Second, idp, database.FirewallSourceAutopilot)
}

// Ban issues a TTL firewall block on ip: it re-checks the whitelist
// fail-safe (so this can be called safely from any code path, not just
// HandleIncident), executes the OS-level block, persists a FirewallRule,
// verifies the effect read-only, and records every step as an incident
// audit event when incidentID is non-nil.
//
// Honesty rules: a successful command is recorded as "succeeded", never as
// "verified"; verification that fails keeps the incident open and
// deactivates the (non-enforcing) rule so a later incident can retry;
// inconclusive verification keeps the block (removing protection on
// uncertainty would be worse) but is recorded as inconclusive.
func (a *Autopilot) Ban(ctx context.Context, ip, reason string, duration time.Duration, incidentID *uint, source database.FirewallSource) error {
	whitelisted, err := a.db.IsWhitelisted(ip)
	if err != nil {
		a.recordEvent(incidentID, database.EventResponse, "failed", "whitelist check failed: "+truncateDetail(err.Error()))
		return fmt.Errorf("whitelist check failed: %w", err)
	}
	if whitelisted {
		a.recordEvent(incidentID, database.EventResponse, "suppressed", "refused: "+ip+" is protected by the fail-safe whitelist")
		return fmt.Errorf("refusing to ban %s: protected by fail-safe whitelist", ip)
	}

	if err := a.exec.Block(ctx, ip); err != nil {
		a.recordEvent(incidentID, database.EventResponse, "failed", "firewall block failed: "+truncateDetail(err.Error()))
		return fmt.Errorf("firewall block failed: %w", err)
	}
	a.recordEvent(incidentID, database.EventResponse, "succeeded",
		fmt.Sprintf("block command for %s returned success (ttl %s); effect not yet verified", ip, duration))

	unbanAt := time.Now().UTC().Add(duration)
	rule := &database.FirewallRule{
		IPAddress:  ip,
		Reason:     reason,
		Source:     source,
		IsActive:   true,
		IncidentID: incidentID,
		BannedAt:   time.Now().UTC(),
		UnbanAt:    &unbanAt,
	}
	if err := a.db.CreateFirewallRule(rule); err != nil {
		// The OS-level block exists but we cannot track/expire it: undo it
		// rather than leave an orphan that would never be reaped.
		rb := "ok"
		if uerr := a.exec.Unblock(ctx, ip); uerr != nil {
			rb = "FAILED: " + truncateDetail(uerr.Error())
		}
		a.recordEvent(incidentID, database.EventResponse, "failed",
			"could not persist firewall rule ("+truncateDetail(err.Error())+"); rollback of block: "+rb)
		return fmt.Errorf("failed to persist firewall rule: %w", err)
	}

	vOutcome, vDetail := a.verifyBlock(ctx, ip)
	a.recordEvent(incidentID, database.EventVerification, vOutcome, vDetail)
	if vOutcome == "failed" {
		log.Printf("[autopilot] VERIFICATION FAILED for ban of %s (incident %v): %s", ip, incidentID, vDetail)
		if derr := a.db.DeactivateFirewallRule(rule.ID); derr != nil {
			log.Printf("[autopilot] failed to deactivate non-enforcing rule #%d: %v", rule.ID, derr)
		}
		return fmt.Errorf("ban of %s could not be verified: %s", ip, vDetail)
	}

	if incidentID != nil {
		if _, err := a.db.MarkAutoBlocked(*incidentID, "autopilot", reason); err != nil {
			log.Printf("[autopilot] failed to update incident #%d status: %v", *incidentID, err)
		}
	}
	log.Printf("[autopilot] banned %s for %s (rule #%d, expires %s, verification: %s)", ip, duration, rule.ID, unbanAt.Format(time.RFC3339), vOutcome)

	// Push a real-time alert (e.g. Telegram) on a successful ban. Best-effort
	// and fully decoupled from the ban's own success: alert delivery never
	// runs on the request/detection hot path's error path, and a nil/absent
	// notifier is always a safe no-op (see AlertNotifier doc comment).
	if a.alert != nil {
		incType, severity := "manual_block", "N/A"
		if incidentID != nil {
			if inc, err := a.db.GetIncident(*incidentID); err == nil {
				incType, severity = string(inc.Type), string(inc.Severity)
				a.alert.NotifyBan(ctx, ip, incType, severity, inc.RiskScore, duration, reason)
				return nil
			}
		}
		a.alert.NotifyBan(ctx, ip, incType, severity, 0, duration, reason)
	}
	return nil
}

// ManualUnban lifts an active ban immediately (used by the "Investigate" /
// "Mark False Positive" dashboard actions or an operator's explicit
// override), regardless of remaining TTL.
func (a *Autopilot) ManualUnban(ctx context.Context, ruleID uint) error {
	rules, err := a.db.ListFirewallRules(true)
	if err != nil {
		return err
	}
	for _, r := range rules {
		if r.ID == ruleID {
			if err := a.exec.Unblock(ctx, r.IPAddress); err != nil {
				return fmt.Errorf("firewall unblock failed: %w", err)
			}
			return a.db.DeactivateFirewallRule(ruleID)
		}
	}
	return fmt.Errorf("firewall rule #%d not found or already inactive", ruleID)
}

// Whitelist adds ip to the fail-safe whitelist so it can never be
// auto-banned, and immediately lifts any existing active ban on it.
func (a *Autopilot) Whitelist(ctx context.Context, ip, reason string) error {
	if err := a.exec.Allow(ctx, ip); err != nil {
		return fmt.Errorf("firewall allow failed: %w", err)
	}
	banned, err := a.db.IsBanned(ip)
	if err != nil {
		return err
	}
	if banned {
		rules, err := a.db.ActiveBans()
		if err != nil {
			return err
		}
		for _, r := range rules {
			if r.IPAddress == ip {
				if err := a.db.DeactivateFirewallRule(r.ID); err != nil {
					log.Printf("[autopilot] failed to deactivate ban #%d while whitelisting %s: %v", r.ID, ip, err)
				}
			}
		}
	}
	return a.db.CreateFirewallRule(&database.FirewallRule{
		IPAddress:     ip,
		Reason:        reason,
		Source:        database.FirewallSourceManual,
		IsWhitelisted: true,
		IsActive:      true,
		BannedAt:      time.Now().UTC(),
	})
}

// ReapExpiredBans finds TTL bans whose window has elapsed, lifts them at
// the OS level, and marks them inactive in the database. Intended to be
// polled periodically (e.g. every minute) by cmd/vanguard's background
// loop.
func (a *Autopilot) ReapExpiredBans(ctx context.Context) (int, error) {
	expired, err := a.db.ExpiredBans()
	if err != nil {
		return 0, err
	}
	count := 0
	for _, rule := range expired {
		if err := a.exec.Unblock(ctx, rule.IPAddress); err != nil {
			log.Printf("[autopilot] failed to unblock expired rule #%d (%s): %v", rule.ID, rule.IPAddress, err)
			continue
		}
		if err := a.db.DeactivateFirewallRule(rule.ID); err != nil {
			log.Printf("[autopilot] failed to deactivate expired rule #%d: %v", rule.ID, err)
			continue
		}
		log.Printf("[autopilot] TTL expired: unbanned %s (rule #%d)", rule.IPAddress, rule.ID)
		count++
	}
	return count, nil
}

// ExecutorStatus returns the underlying Executor's raw status dump (e.g.
// `ufw status verbose`, or the MockExecutor's in-memory summary), exposed
// for the REST API's diagnostic "System" view.
func (a *Autopilot) ExecutorStatus(ctx context.Context) (string, error) {
	return a.exec.Status(ctx)
}

// ReconcileOnStartup re-applies every currently-active ban from the
// database to the live OS firewall. This must run once at process start:
// UFW/iptables rules do NOT persist across a fresh `ufw reset`/reboot the
// way the SQLite record of "who should be banned" does, so without this
// step a restart would silently drop all active bans at the OS level while
// the dashboard still shows them as active.
func (a *Autopilot) ReconcileOnStartup(ctx context.Context) error {
	active, err := a.db.ActiveBans()
	if err != nil {
		return err
	}
	for _, rule := range active {
		if err := a.exec.Block(ctx, rule.IPAddress); err != nil {
			log.Printf("[autopilot] reconcile: failed to re-apply ban on %s: %v", rule.IPAddress, err)
		}
	}
	log.Printf("[autopilot] reconciled %d active ban(s) with the OS firewall on startup", len(active))
	return nil
}
