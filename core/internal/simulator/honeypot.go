package simulator

import (
	"context"
	"fmt"
	"math/rand"
	"time"

	"vanguard/core/internal/database"
	"vanguard/core/internal/risk"
)

// honeypotDefaults: per the spec, ANY connection to a decoy port is
// CRITICAL by definition -- there is no attempt threshold. Bans default to
// a longer TTL than brute-force since honeypot contact proves malicious
// intent beyond reasonable doubt (no legitimate client ever has a reason to
// connect to a fake port).
const (
	honeypotDefaultBanDuration = 24 * time.Hour
)

// decoyPorts mirrors the fake services the real Honeypot Engine listens on
// (internal/honeypot), so simulated triggers look identical to real ones.
var decoyPorts = []struct {
	Port    int
	Service string
}{
	{2222, "fake-ssh"},
	{33060, "fake-mysql"},
	{8081, "fake-admin-panel"},
}

// honeypotSimulator implements `vanguard simulate honeypot`: simulates an
// attacker connecting to a decoy port, which the real engine treats as an
// instant CRITICAL trigger regardless of frequency.
type honeypotSimulator struct{}

// NewHoneypotSimulator constructs the honeypot scenario.
func NewHoneypotSimulator() Simulator { return &honeypotSimulator{} }

func (s *honeypotSimulator) Name() string { return "honeypot" }

func (s *honeypotSimulator) Description() string {
	return "Simulates a connection to a decoy port (fake SSH/MySQL/admin panel) to trigger an instant CRITICAL honeypot incident."
}

// honeypotMetadata is the structured payload stored in Incident.Metadata.
type honeypotMetadata struct {
	Simulated      bool           `json:"simulated"`
	DecoyPort      int            `json:"decoy_port"`
	DecoyService   string         `json:"decoy_service"`
	ConnectedAt    time.Time      `json:"connected_at"`
	PayloadPreview string         `json:"payload_preview,omitempty"`
	ScoreBreakdown risk.Breakdown `json:"score_breakdown"`
}

func (s *honeypotSimulator) Run(ctx context.Context, db *database.DB, opts Options) (*Result, error) {
	// Honeypot bans are long by default (24h) unlike the shorter SSH
	// brute-force TTL; frequency/window options are meaningless here (a
	// single touch is enough) so they're left at whatever the caller set
	// but not used for scoring.
	opts = opts.withDefaults(1, 1, honeypotDefaultBanDuration)

	sourceIP := opts.SourceIP
	if sourceIP == "" {
		sourceIP = randomPublicIP()
	}

	decoy := decoyPorts[rand.Intn(len(decoyPorts))]

	narrative := []string{
		fmt.Sprintf("[1/4] Simulating inbound connection from %s to decoy port %d (%s)", sourceIP, decoy.Port, decoy.Service),
		"[2/4] Honeypot Engine treats ANY connection to a decoy port as malicious intent -- no threshold required (instant CRITICAL by policy)",
	}

	breakdown := risk.Score(risk.Input{
		Type:                database.IncidentHoneypotTrigger,
		EventCount:          1,
		Threshold:           0, // no threshold: any single touch counts
		MaxFrequencyBonus:   0,
		RecentIncidentCount: reputationFor(db, sourceIP, 24*time.Hour),
		Escalate:            true, // honeypot contact is always a hard escalation
		EscalationNote:      "honeypot connection (deception layer triggered)",
	})

	result := &Result{Scenario: s.Name(), DryRun: opts.DryRun}
	meta := honeypotMetadata{
		Simulated:      true,
		DecoyPort:      decoy.Port,
		DecoyService:   decoy.Service,
		ConnectedAt:    time.Now().UTC(),
		PayloadPreview: fmt.Sprintf("SSH-2.0-libssh2_1.10.0\\r\\n (scanner banner grab against %s)", decoy.Service),
		ScoreBreakdown: breakdown,
	}

	if opts.DryRun {
		severity := risk.Severity(breakdown.Total)
		narrative = append(narrative, fmt.Sprintf("[3/4] Risk score calculated: %d/100 (%s) -- %s", breakdown.Total, severity, breakdown.Explanation))
		narrative = append(narrative, "[4/4] DRY RUN: incident would be created (no DB write performed)")
		if opts.AutoBan {
			narrative = append(narrative, fmt.Sprintf("      DRY RUN: Autopilot would issue a %s ban on %s", opts.BanDuration, sourceIP))
		}
		result.SourceIP = sourceIP
		result.AttemptCount = 1
		result.RiskScore = breakdown.Total
		result.Severity = severity
		result.Narrative = narrative
		return result, nil
	}

	persisted, err := persistIncident(db, persistParams{
		IncidentType:   database.IncidentHoneypotTrigger,
		SourceIP:       sourceIP,
		AttemptCount:   1,
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
