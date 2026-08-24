package simulator

import (
	"context"
	"fmt"
	"math/rand"
	"time"

	"vanguard/core/internal/database"
	"vanguard/core/internal/risk"
	"vanguard/core/internal/thresholds"
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
// risk-scoring formula (internal/risk) the real detection engine uses and
// persists the resulting Incident (and, unless disabled, a simulated
// Autopilot ban).
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
	ScoreBreakdown   risk.Breakdown  `json:"score_breakdown"`
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

	narrative = append(narrative, fmt.Sprintf("[2/5] Detection engine evaluated events: threshold '>%d failed attempts/IP' EXCEEDED", thresholds.SSHBruteForceMinAttempts))

	incidentType := database.IncidentSSHBruteForce
	if successAfterFail {
		incidentType = database.IncidentFailedThenSuccess
		narrative = append(narrative, "[2b/5] Successful login observed immediately after failures -> escalation rule triggered (CRITICAL)")
	}

	breakdown := risk.Score(risk.Input{
		Type:                incidentType,
		EventCount:          opts.AttemptCount,
		Threshold:           thresholds.SSHBruteForceMinAttempts,
		MaxFrequencyBonus:   30,
		RecentIncidentCount: reputationFor(db, sourceIP, 24*time.Hour),
		Escalate:            successAfterFail,
		EscalationNote:      "failed-then-successful login sequence",
	})

	result := &Result{Scenario: s.Name(), DryRun: opts.DryRun}

	meta := sshBruteForceMetadata{
		Simulated:        true,
		TargetPort:       22,
		Attempts:         attempts,
		UsernamesTried:   usernames,
		SuccessAfterFail: successAfterFail,
		ScoreBreakdown:   breakdown,
	}

	if opts.DryRun {
		severity := risk.Severity(breakdown.Total)
		narrative = append(narrative, fmt.Sprintf("[3/5] Risk score calculated: %d/100 (%s) -- %s", breakdown.Total, severity, breakdown.Explanation))
		narrative = append(narrative, "[4/5] DRY RUN: incident would be created (no DB write performed)")
		if opts.AutoBan {
			narrative = append(narrative, fmt.Sprintf("[5/5] DRY RUN: Autopilot would issue a %s ban on %s", opts.BanDuration, sourceIP))
		}
		result.SourceIP = sourceIP
		result.AttemptCount = opts.AttemptCount
		result.RiskScore = breakdown.Total
		result.Severity = severity
		result.Narrative = narrative
		return result, nil
	}

	persisted, err := persistIncident(db, persistParams{
		IncidentType:   incidentType,
		SourceIP:       sourceIP,
		AttemptCount:   opts.AttemptCount,
		Breakdown:      breakdown,
		Metadata:       meta,
		AutoBan:        opts.AutoBan,
		BanDuration:    opts.BanDuration,
		NarrativeSoFar: narrative,
	})
	if err != nil {
		return nil, err
	}
	persisted.Scenario = s.Name()
	return persisted, nil
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
