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

func (a *Autopilot) seedAdminWhitelist() {
	for _, ip := range a.cfg.AdminWhitelistIPs {
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
// whitelist check, minimum-score gate, then a TTL ban if warranted.
// Exposed as a public method (not just via OnIncident) so the REST API can
// invoke the same logic on-demand for a manual "block this IP" action.
func (a *Autopilot) HandleIncident(ctx context.Context, inc *database.Incident) error {
	if !a.cfg.Enabled {
		log.Printf("[autopilot] disabled; incident #%d (%s, risk %d) left for manual review", inc.ID, inc.Type, inc.RiskScore)
		return nil
	}

	whitelisted, err := a.db.IsWhitelisted(inc.SourceIP)
	if err != nil {
		return fmt.Errorf("whitelist check failed: %w", err)
	}
	if whitelisted {
		log.Printf("[autopilot] SKIPPED ban for incident #%d: %s is whitelisted (fail-safe)", inc.ID, inc.SourceIP)
		return nil
	}

	if inc.RiskScore < a.cfg.MinRiskScoreToBan {
		log.Printf("[autopilot] incident #%d (risk %d) below auto-ban threshold (%d); left open for manual review",
			inc.ID, inc.RiskScore, a.cfg.MinRiskScoreToBan)
		return nil
	}

	alreadyBanned, err := a.db.IsBanned(inc.SourceIP)
	if err != nil {
		return fmt.Errorf("ban check failed: %w", err)
	}
	if alreadyBanned {
		log.Printf("[autopilot] %s already banned; incident #%d recorded but no new rule created", inc.SourceIP, inc.ID)
		return nil
	}

	duration := a.cfg.DefaultBanDuration
	if d, ok := a.cfg.BanDurationByType[inc.Type]; ok {
		duration = d
	}
	if duration <= 0 {
		duration = DefaultTTL
	}

	return a.Ban(ctx, inc.SourceIP, fmt.Sprintf("Autopilot: %s (incident #%d, risk %d)", inc.Type, inc.ID, inc.RiskScore), duration, &inc.ID, database.FirewallSourceAutopilot)
}

// Ban issues a TTL firewall block on ip: it re-checks the whitelist
// fail-safe (so this can be called safely from any code path, not just
// HandleIncident), executes the OS-level block, persists a FirewallRule,
// and -- if incidentID is non-nil -- flips that incident's status to
// auto_blocked.
func (a *Autopilot) Ban(ctx context.Context, ip, reason string, duration time.Duration, incidentID *uint, source database.FirewallSource) error {
	whitelisted, err := a.db.IsWhitelisted(ip)
	if err != nil {
		return fmt.Errorf("whitelist check failed: %w", err)
	}
	if whitelisted {
		return fmt.Errorf("refusing to ban %s: protected by fail-safe whitelist", ip)
	}

	if err := a.exec.Block(ctx, ip); err != nil {
		return fmt.Errorf("firewall block failed: %w", err)
	}

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
		return fmt.Errorf("failed to persist firewall rule: %w", err)
	}
	if incidentID != nil {
		if err := a.db.UpdateIncidentStatus(*incidentID, database.StatusAutoBlocked); err != nil {
			log.Printf("[autopilot] failed to update incident #%d status: %v", *incidentID, err)
		}
	}
	log.Printf("[autopilot] banned %s for %s (rule #%d, expires %s)", ip, duration, rule.ID, unbanAt.Format(time.RFC3339))
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
