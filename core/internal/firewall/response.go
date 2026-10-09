package firewall

// Phase 5, Milestone 3: explicit response outcomes, read-only verification
// and a non-mutating policy preview.
//
// Outcome vocabulary (recorded as database.IncidentEvent.Outcome):
//
//	kind=response:      suppressed | not_eligible | succeeded | failed
//	kind=verification:  verified | failed | inconclusive
//
// "succeeded" means ONLY that the firewall command returned success. It
// is never reported as an effective block until a verification event says
// "verified". Verification is a single read-only query (no retries, hard
// timeout); a timeout, an error, or an executor that cannot verify is
// "inconclusive" -- never "verified".

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"

	"vanguard/core/internal/database"
)

// verifyTimeout bounds the single read-only verification query.
var verifyTimeout = 5 * time.Second

// BlockVerifier is the optional read-only capability an Executor may offer
// to confirm that traffic from ip is actually denied right now.
type BlockVerifier interface {
	IsBlocked(ctx context.Context, ip string) (bool, error)
}

// Decision is the result of evaluating Autopilot policy for one incident,
// computed without executing anything.
type Decision struct {
	IncidentID uint   `json:"incident_id"`
	SourceIP   string `json:"source_ip"`
	// WouldBan is true only if HandleIncident would issue a ban right now.
	WouldBan bool `json:"would_ban"`
	// Outcome: "would_ban" or the reason no action is taken
	// (disabled, whitelisted, below_threshold, already_banned).
	Outcome         string `json:"outcome"`
	Reason          string `json:"reason"`
	DurationSeconds int64  `json:"duration_seconds,omitempty"`
	MinRiskScore    int    `json:"min_risk_score"`
	RiskScore       int    `json:"risk_score"`
	// Executed is always false for a plan: nothing was changed.
	Executed bool `json:"executed"`
}

// Plan evaluates the same policy HandleIncident applies and returns what
// would happen, performing only database READS. It never calls the
// Executor and never writes.
func (a *Autopilot) Plan(inc *database.Incident) (Decision, error) {
	d := Decision{
		IncidentID: inc.ID, SourceIP: inc.SourceIP,
		MinRiskScore: a.cfg.MinRiskScoreToBan, RiskScore: inc.RiskScore,
	}
	if !a.cfg.Enabled {
		d.Outcome, d.Reason = "disabled", "autopilot is disabled; incident is left for manual review"
		return d, nil
	}
	whitelisted, err := a.db.IsWhitelisted(inc.SourceIP)
	if err != nil {
		return d, fmt.Errorf("whitelist check failed: %w", err)
	}
	if whitelisted {
		d.Outcome, d.Reason = "whitelisted", inc.SourceIP+" is protected by the fail-safe whitelist"
		return d, nil
	}
	if inc.RiskScore < a.cfg.MinRiskScoreToBan {
		d.Outcome = "below_threshold"
		d.Reason = fmt.Sprintf("risk %d is below the auto-ban threshold %d", inc.RiskScore, a.cfg.MinRiskScoreToBan)
		return d, nil
	}
	banned, err := a.db.IsBanned(inc.SourceIP)
	if err != nil {
		return d, fmt.Errorf("ban check failed: %w", err)
	}
	if banned {
		d.Outcome, d.Reason = "already_banned", inc.SourceIP+" already has an active ban"
		return d, nil
	}
	dur := a.cfg.DefaultBanDuration
	if t, ok := a.cfg.BanDurationByType[inc.Type]; ok {
		dur = t
	}
	if dur <= 0 {
		dur = DefaultTTL
	}
	d.WouldBan, d.Outcome = true, "would_ban"
	d.Reason = fmt.Sprintf("risk %d >= threshold %d and %s is not whitelisted or banned", inc.RiskScore, a.cfg.MinRiskScoreToBan, inc.SourceIP)
	d.DurationSeconds = int64(dur.Seconds())
	return d, nil
}

// recordEvent writes an audit entry for an incident (no-op when the ban
// is not tied to an incident). Failure to record is logged, never fatal:
// the audit trail must not break the response path.
func (a *Autopilot) recordEvent(incidentID *uint, kind, outcome, detail string) {
	if incidentID == nil {
		return
	}
	if err := a.db.AddIncidentEvent(database.IncidentEvent{
		IncidentID: *incidentID, Kind: kind, Actor: "autopilot", Outcome: outcome, Detail: detail,
	}); err != nil {
		log.Printf("[autopilot] failed to record %s/%s event for incident #%d: %v", kind, outcome, *incidentID, err)
	}
}

// verifyBlock performs one bounded, read-only check that ip is blocked.
// It returns the verification outcome and a human detail string.
func (a *Autopilot) verifyBlock(ctx context.Context, ip string) (outcome, detail string) {
	v, ok := a.exec.(BlockVerifier)
	if !ok {
		return "inconclusive", "executor cannot verify firewall state"
	}
	vctx, cancel := context.WithTimeout(ctx, verifyTimeout)
	defer cancel()
	blocked, err := v.IsBlocked(vctx, ip)
	switch {
	case vctx.Err() != nil && err != nil:
		return "inconclusive", "verification timed out"
	case err != nil:
		return "inconclusive", "verification query failed: " + truncateDetail(err.Error())
	case blocked:
		return "verified", "firewall state shows traffic from " + ip + " is denied"
	default:
		return "failed", "firewall state does NOT show a deny rule for " + ip
	}
}

func truncateDetail(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > 200 {
		return s[:200]
	}
	return s
}

// ufwStatusDenies reports whether `ufw status` output contains an active
// DENY rule for ip, and whether the firewall is active at all. Pure
// function over the command output (unit-tested).
func ufwStatusDenies(output, ip string) (denied bool, active bool) {
	for _, line := range strings.Split(output, "\n") {
		l := strings.TrimSpace(line)
		if strings.HasPrefix(strings.ToLower(l), "status:") {
			active = strings.Contains(strings.ToLower(l), "active") && !strings.Contains(strings.ToLower(l), "inactive")
			continue
		}
		fields := strings.Fields(l)
		hasIP, hasDeny := false, false
		for _, f := range fields {
			if f == ip {
				hasIP = true
			}
			if strings.HasPrefix(strings.ToUpper(f), "DENY") || strings.EqualFold(f, "REJECT") {
				hasDeny = true
			}
		}
		if hasIP && hasDeny {
			denied = true
		}
	}
	return denied, active
}
