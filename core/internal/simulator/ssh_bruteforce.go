package simulator

import (
	"context"
	"fmt"
	"math/rand"
	"time"

	"vanguard/core/internal/database"
)

// sshBruteForceDefaults mirrors the thresholds from the V1 Detection Engine
// spec ("> 10 failed attempts from one IP in a short window") and the
// "Failed -> Successful Login Sequence" CRITICAL escalation rule.
const (
	sshDefaultAttempts       = 25 // safely above the >10 threshold
	sshDefaultWindowSeconds  = 45
	sshDefaultBanDuration    = 1 * time.Hour
	sshSuccessEscalationOdds = 3 // 1-in-N simulated runs also appends a successful login
)

// sshBruteForceSimulator implements the `vanguard simulate ssh-bruteforce`
// scenario: it fabricates N failed SSH auth events (as if parsed from
// /var/log/auth.log) from a single source IP within a short window,
// optionally followed by one successful login to trigger the CRITICAL
// "failed-then-success" escalation, then runs them through the same
// risk-scoring formula the real detection engine uses and persists the
// resulting Incident (and, unless disabled, a simulated Autopilot ban).
type sshBruteForceSimulator struct{}

// NewSSHBruteForceSimulator constructs the ssh-bruteforce scenario.
func NewSSHBruteForceSimulator() Simulator {
	return &sshBruteForceSimulator{}
}

func (s *sshBruteForceSimulator) Name() string { return "ssh-bruteforce" }

func (s *sshBruteForceSimulator) Description() string {
	return "Simulates N failed SSH logins from one IP (optionally followed by a success) to exercise brute-force detection, risk scoring, and auto-ban."
}

// sshAttemptLog is the synthetic equivalent of a single parsed
// /var/log/auth.log line. It is not persisted as its own DB row (V1 has no
// raw-log table) but is included in the Incident's Metadata JSON blob so
// the dashboard/incident detail view has concrete "evidence" to render,
// exactly like a real detection would attach matched log lines.
type sshAttemptLog struct {
	Timestamp time.Time `json:"timestamp"`
	User      string    `json:"user"`
	Result    string    `json:"result"` // "failed" | "accepted"
	Port      int       `json:"port"`
	RawLine   string    `json:"raw_line"`
}

// sshBruteForceMetadata is the structured payload stored in
// Incident.Metadata for this scenario.
type sshBruteForceMetadata struct {
	Simulated        bool            `json:"simulated"`
	TargetPort       int             `json:"target_port"`
	Attempts         []sshAttemptLog `json:"attempts"`
	UsernamesTried   []string        `json:"usernames_tried"`
	SuccessAfterFail bool            `json:"success_after_fail"`
	ScoreBreakdown   ScoreBreakdown  `json:"score_breakdown"`
}

// ScoreBreakdown documents how a RiskScore was derived, per the spec's
// "Risk Score = Base Severity + Frequency + Threat Reputation" formula.
// Every detector (real or simulated) should populate one of these so the
// dashboard and the AI Analyst can explain *why* a score is what it is.
type ScoreBreakdown struct {
	BaseSeverity    int    `json:"base_severity"`
	FrequencyBonus  int    `json:"frequency_bonus"`
	ReputationBonus int    `json:"reputation_bonus"`
	EscalationBonus int    `json:"escalation_bonus"`
	Total           int    `json:"total"` // clamped 0-100
	Explanation     string `json:"explanation"`
}

// commonSSHUsernames is a small pool used to make the synthetic attempts
// look like a realistic dictionary attack.
var commonSSHUsernames = []string{"root", "admin", "ubuntu", "test", "oracle", "postgres", "deploy", "git"}

func (s *sshBruteForceSimulator) Run(ctx context.Context, db *database.DB, opts Options) (*Result, error) {
	opts = opts.withDefaults(sshDefaultAttempts, sshDefaultWindowSeconds, sshDefaultBanDuration)

	sourceIP := opts.SourceIP
	if sourceIP == "" {
		sourceIP = randomPublicIP()
	}

	narrative := []string{
		fmt.Sprintf("[1/5] Generating %d synthetic failed SSH login attempts from %s over a %ds window",
			opts.AttemptCount, sourceIP, opts.WindowSeconds),
	}

	// Decide (once, deterministically per-run) whether this simulation also
	// includes the CRITICAL "failed -> successful login" escalation.
	successAfterFail := rand.Intn(sshSuccessEscalationOdds) == 0

	attempts, usernames := generateSSHAttempts(sourceIP, opts.AttemptCount, opts.WindowSeconds, successAfterFail)

	narrative = append(narrative, "[2/5] Detection engine evaluated events: threshold '>10 failed attempts/IP' EXCEEDED")

	incidentType := database.IncidentSSHBruteForce
	if successAfterFail {
		incidentType = database.IncidentFailedThenSuccess
		narrative = append(narrative, "[2b/5] Successful login observed immediately after failures -> escalation rule triggered (CRITICAL)")
	}

	// --- Dynamic Risk Scoring: Base Severity + Frequency + Threat Reputation ---
	breakdown := ScoreBreakdown{BaseSeverity: 40} // SSH brute force base severity
	if successAfterFail {
		breakdown.BaseSeverity = 55 // a confirmed compromise attempt starts higher
	}

	// Frequency component: scales with volume above the 10-attempt threshold,
	// capped so a single detector can't alone reach CRITICAL without other
	// context (mirrors "not simply additive" framing in the spec).
	over := opts.AttemptCount - 10
	if over < 0 {
		over = 0
	}
	breakdown.FrequencyBonus = clampScore(over) // e.g. 25 attempts -> +15, capped at 100 by final clamp
	if breakdown.FrequencyBonus > 30 {
		breakdown.FrequencyBonus = 30
	}

	// Threat Reputation component: repeat offenders from the same IP in the
	// last 24h score higher. Falls back to 0 gracefully if db is nil (dry
	// preview without a live DB) or the query errors.
	if db != nil {
		if count, err := db.CountRecentEventsByIP(sourceIP, time.Now().UTC().Add(-24*time.Hour)); err == nil {
			rep := int(count) * 5
			if rep > 20 {
				rep = 20
			}
			breakdown.ReputationBonus = rep
		}
	}

	// Escalation bonus: the failed->success sequence is CRITICAL by policy
	// regardless of other factors, so we push it firmly into the 80+ band.
	if successAfterFail {
		breakdown.EscalationBonus = 25
	}

	riskScore := clampScore(breakdown.BaseSeverity + breakdown.FrequencyBonus + breakdown.ReputationBonus + breakdown.EscalationBonus)
	breakdown.Total = riskScore
	breakdown.Explanation = fmt.Sprintf(
		"base=%d (ssh_bruteforce%s) + frequency=%d (%d attempts) + reputation=%d (repeat-offender history) + escalation=%d (failed->success: %v) = %d",
		breakdown.BaseSeverity, map[bool]string{true: "+success", false: ""}[successAfterFail],
		breakdown.FrequencyBonus, opts.AttemptCount, breakdown.ReputationBonus, breakdown.EscalationBonus, successAfterFail, riskScore,
	)
	severity := database.SeverityFromScore(riskScore)

	narrative = append(narrative, fmt.Sprintf("[3/5] Risk score calculated: %d/100 (%s) -- %s", riskScore, severity, breakdown.Explanation))

	result := &Result{
		Scenario:     s.Name(),
		SourceIP:     sourceIP,
		AttemptCount: opts.AttemptCount,
		RiskScore:    riskScore,
		Severity:     severity,
		DryRun:       opts.DryRun,
	}

	meta := sshBruteForceMetadata{
		Simulated:        true,
		TargetPort:       22,
		Attempts:         attempts,
		UsernamesTried:   usernames,
		SuccessAfterFail: successAfterFail,
		ScoreBreakdown:   breakdown,
	}

	if opts.DryRun {
		narrative = append(narrative, "[4/5] DRY RUN: incident would be created (no DB write performed)")
		if opts.AutoBan {
			narrative = append(narrative, fmt.Sprintf("[5/5] DRY RUN: Autopilot would issue a %s ban on %s", opts.BanDuration, sourceIP))
		}
		result.Narrative = narrative
		return result, nil
	}

	if db == nil {
		return nil, fmt.Errorf("simulator: %s requires a database connection unless DryRun is set", s.Name())
	}

	inc := &database.Incident{
		Type:         incidentType,
		SourceIP:     sourceIP,
		RiskScore:    riskScore,
		Severity:     severity,
		Status:       database.StatusOpen,
		AttemptCount: opts.AttemptCount,
		DetectedAt:   time.Now().UTC(),
	}
	if err := inc.SetMetadata(meta); err != nil {
		return nil, fmt.Errorf("simulator: failed to encode metadata: %w", err)
	}

	if err := db.CreateIncident(inc); err != nil {
		return nil, fmt.Errorf("simulator: failed to persist incident: %w", err)
	}
	narrative = append(narrative, fmt.Sprintf("[4/5] Incident #%d created and stored in SQLite", inc.ID))
	result.Incident = inc

	if opts.AutoBan {
		// Fail-safe: never fabricate a ban for a whitelisted IP, even in a
		// simulation -- this exercises the same guard the real Autopilot
		// must always apply.
		whitelisted, err := db.IsWhitelisted(sourceIP)
		if err != nil {
			return nil, fmt.Errorf("simulator: whitelist check failed: %w", err)
		}
		if whitelisted {
			narrative = append(narrative, fmt.Sprintf("[5/5] Autopilot SKIPPED ban: %s is whitelisted (fail-safe honored)", sourceIP))
		} else {
			unbanAt := time.Now().UTC().Add(opts.BanDuration)
			rule := &database.FirewallRule{
				IPAddress:  sourceIP,
				Reason:     fmt.Sprintf("Autopilot: %s (incident #%d, risk %d)", incidentType, inc.ID, riskScore),
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
			narrative = append(narrative, fmt.Sprintf("[5/5] Autopilot issued TTL ban on %s for %s (expires %s)",
				sourceIP, opts.BanDuration, unbanAt.Format(time.RFC3339)))
			result.FirewallRule = rule
		}
	} else {
		narrative = append(narrative, "[5/5] AutoBan disabled for this run; incident left open for manual review")
	}

	result.Narrative = narrative
	return result, nil
}

// generateSSHAttempts fabricates a realistic sequence of failed (and
// optionally one final accepted) SSH login log lines spread evenly across
// windowSeconds, ending at time.Now().
func generateSSHAttempts(sourceIP string, count, windowSeconds int, appendSuccess bool) ([]sshAttemptLog, []string) {
	now := time.Now().UTC()
	attempts := make([]sshAttemptLog, 0, count+1)
	usernamesSeen := make(map[string]bool)

	step := time.Duration(0)
	if count > 1 {
		step = time.Duration(windowSeconds) * time.Second / time.Duration(count)
	}
	start := now.Add(-time.Duration(windowSeconds) * time.Second)

	for i := 0; i < count; i++ {
		user := commonSSHUsernames[rand.Intn(len(commonSSHUsernames))]
		usernamesSeen[user] = true
		ts := start.Add(step * time.Duration(i))
		attempts = append(attempts, sshAttemptLog{
			Timestamp: ts,
			User:      user,
			Result:    "failed",
			Port:      22,
			RawLine: fmt.Sprintf(
				"%s sshd[%d]: Failed password for %s from %s port %d ssh2",
				ts.Format("Jan _2 15:04:05"), 10000+i, user, sourceIP, 40000+rand.Intn(20000)),
		})
	}

	if appendSuccess {
		user := "root"
		usernamesSeen[user] = true
		ts := now
		attempts = append(attempts, sshAttemptLog{
			Timestamp: ts,
			User:      user,
			Result:    "accepted",
			Port:      22,
			RawLine: fmt.Sprintf(
				"%s sshd[%d]: Accepted password for %s from %s port %d ssh2",
				ts.Format("Jan _2 15:04:05"), 10000+count, user, sourceIP, 40000+rand.Intn(20000)),
		})
	}

	usernames := make([]string, 0, len(usernamesSeen))
	for u := range usernamesSeen {
		usernames = append(usernames, u)
	}
	return attempts, usernames
}
