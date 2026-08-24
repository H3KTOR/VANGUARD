package simulator

import (
	"fmt"
	"time"

	"vanguard/core/internal/database"
	"vanguard/core/internal/risk"
)

// persistParams bundles what every simulator needs to turn a computed risk
// score into an Incident (+ optional TTL FirewallRule), so each scenario
// file only has to build its own Metadata payload and call persistIncident.
type persistParams struct {
	IncidentType   database.IncidentType
	SourceIP       string
	AttemptCount   int
	Breakdown      risk.Breakdown
	Metadata       any
	AutoBan        bool
	BanDuration    time.Duration
	NarrativeSoFar []string
}

// persistIncident writes the Incident row (and, unless the IP is
// whitelisted or AutoBan is false, a simulated Autopilot TTL ban) and
// returns the fully populated Result. Shared by every simulator so the
// fail-safe whitelist check and status transitions are implemented exactly
// once.
func persistIncident(db *database.DB, p persistParams) (*Result, error) {
	severity := risk.Severity(p.Breakdown.Total)
	narrative := append([]string{}, p.NarrativeSoFar...)
	narrative = append(narrative, fmt.Sprintf("Risk score calculated: %d/100 (%s) -- %s",
		p.Breakdown.Total, severity, p.Breakdown.Explanation))

	result := &Result{
		SourceIP:     p.SourceIP,
		AttemptCount: p.AttemptCount,
		RiskScore:    p.Breakdown.Total,
		Severity:     severity,
	}

	if db == nil {
		return nil, fmt.Errorf("simulator: persisting requires a database connection")
	}

	inc := &database.Incident{
		Type:         p.IncidentType,
		SourceIP:     p.SourceIP,
		RiskScore:    p.Breakdown.Total,
		Severity:     severity,
		Status:       database.StatusOpen,
		AttemptCount: p.AttemptCount,
		DetectedAt:   time.Now().UTC(),
	}
	if p.Metadata != nil {
		if err := inc.SetMetadata(p.Metadata); err != nil {
			return nil, fmt.Errorf("simulator: failed to encode metadata: %w", err)
		}
	}
	if err := db.CreateIncident(inc); err != nil {
		return nil, fmt.Errorf("simulator: failed to persist incident: %w", err)
	}
	narrative = append(narrative, fmt.Sprintf("Incident #%d created and stored in SQLite", inc.ID))
	result.Incident = inc

	if p.AutoBan {
		whitelisted, err := db.IsWhitelisted(p.SourceIP)
		if err != nil {
			return nil, fmt.Errorf("simulator: whitelist check failed: %w", err)
		}
		if whitelisted {
			narrative = append(narrative, fmt.Sprintf("Autopilot SKIPPED ban: %s is whitelisted (fail-safe honored)", p.SourceIP))
		} else {
			banDuration := p.BanDuration
			if banDuration <= 0 {
				banDuration = time.Hour
			}
			unbanAt := time.Now().UTC().Add(banDuration)
			rule := &database.FirewallRule{
				IPAddress:  p.SourceIP,
				Reason:     fmt.Sprintf("Autopilot: %s (incident #%d, risk %d)", p.IncidentType, inc.ID, p.Breakdown.Total),
				Source:     database.FirewallSourceSimulator,
				IsActive:   true,
				IncidentID: &inc.ID,
				BannedAt:   time.Now().UTC(),
				UnbanAt:    &unbanAt,
			}
			if err := db.CreateFirewallRule(rule); err != nil {
				return nil, fmt.Errorf("simulator: failed to persist firewall rule: %w", err)
			}
			if err := db.UpdateIncidentStatus(inc.ID, database.StatusAutoBlocked); err != nil {
				return nil, fmt.Errorf("simulator: failed to update incident status: %w", err)
			}
			inc.Status = database.StatusAutoBlocked
			narrative = append(narrative, fmt.Sprintf("Autopilot issued TTL ban on %s for %s (expires %s)",
				p.SourceIP, banDuration, unbanAt.Format(time.RFC3339)))
			result.FirewallRule = rule
		}
	} else {
		narrative = append(narrative, "AutoBan disabled for this run; incident left open for manual review")
	}

	result.Narrative = narrative
	return result, nil
}

// reputationFor looks up the recent-incident count used as the Threat
// Reputation input, returning 0 gracefully if db is nil or the query fails
// (e.g. during a dry-run preview with no live database).
func reputationFor(db *database.DB, ip string, window time.Duration) int {
	if db == nil {
		return 0
	}
	count, err := db.CountRecentEventsByIP(ip, time.Now().UTC().Add(-window))
	if err != nil {
		return 0
	}
	return int(count)
}
