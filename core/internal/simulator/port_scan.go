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

// Port scan detection defaults, matching the real detector's thresholds:
// "One IP touching multiple ports rapidly."
const (
	portScanDefaultPortsTouched = 22 // distinct ports touched, safely above threshold
	portScanDefaultWindowSecs   = 20
	portScanDefaultBanDuration  = 3 * time.Hour
)

// commonScannedPorts is a realistic pool of ports an automated scanner
// (nmap, masscan, etc) would probe, mixing well-known service ports with a
// handful of high ports to look like a real sweep.
var commonScannedPorts = []int{21, 22, 23, 25, 80, 110, 135, 139, 143, 443, 445, 993, 995,
	1433, 1723, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 9200, 27017}

// portScanSimulator implements `vanguard simulate port-scan`: fabricates one
// source IP rapidly touching many distinct destination ports, exercising
// the reconnaissance detector's distinct-port-count threshold.
type portScanSimulator struct{}

// NewPortScanSimulator constructs the port-scan scenario.
func NewPortScanSimulator() Simulator { return &portScanSimulator{} }

func (s *portScanSimulator) Name() string { return "port-scan" }

func (s *portScanSimulator) Description() string {
	return "Simulates one IP rapidly touching multiple ports to trigger port-scan reconnaissance detection."
}

// portTouch is the synthetic equivalent of a single observed connection
// attempt to one destination port, as if parsed from firewall/connection
// logs.
type portTouch struct {
	Timestamp time.Time `json:"timestamp"`
	Port      int       `json:"port"`
	Protocol  string    `json:"protocol"`
}

// portScanMetadata is the structured payload stored in Incident.Metadata.
type portScanMetadata struct {
	Simulated      bool           `json:"simulated"`
	DistinctPorts  int            `json:"distinct_ports"`
	WindowSeconds  int            `json:"window_seconds"`
	Touches        []portTouch    `json:"touches"`
	ScoreBreakdown risk.Breakdown `json:"score_breakdown"`
}

func (s *portScanSimulator) Run(ctx context.Context, db *database.DB, opts Options) (*Result, error) {
	opts = opts.withDefaults(portScanDefaultPortsTouched, portScanDefaultWindowSecs, portScanDefaultBanDuration)

	sourceIP := opts.SourceIP
	if sourceIP == "" {
		sourceIP = randomPublicIP()
	}

	narrative := []string{
		fmt.Sprintf("[1/4] Generating scan of %d distinct ports from %s over a %ds window", opts.AttemptCount, sourceIP, opts.WindowSeconds),
	}

	touches := generatePortTouches(opts.AttemptCount, opts.WindowSeconds)
	narrative = append(narrative, fmt.Sprintf("[2/4] Detection engine evaluated events: threshold '>%d distinct ports/IP' EXCEEDED", thresholds.PortScanDistinctPorts))

	breakdown := risk.Score(risk.Input{
		Type:                database.IncidentPortScan,
		EventCount:          opts.AttemptCount,
		Threshold:           thresholds.PortScanDistinctPorts,
		MaxFrequencyBonus:   25,
		RecentIncidentCount: reputationFor(db, sourceIP, 24*time.Hour),
	})

	result := &Result{Scenario: s.Name(), DryRun: opts.DryRun}
	meta := portScanMetadata{
		Simulated:      true,
		DistinctPorts:  opts.AttemptCount,
		WindowSeconds:  opts.WindowSeconds,
		Touches:        touches,
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
		result.AttemptCount = opts.AttemptCount
		result.RiskScore = breakdown.Total
		result.Severity = severity
		result.Narrative = narrative
		return result, nil
	}

	persisted, err := persistIncident(db, persistParams{
		IncidentType:   database.IncidentPortScan,
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

// generatePortTouches fabricates `count` distinct-port connection attempts
// spread evenly across windowSeconds, ending at time.Now(). If count
// exceeds the size of commonScannedPorts, ports are allowed to repeat only
// after the pool is exhausted (still realistic for a broad sweep).
func generatePortTouches(count, windowSeconds int) []portTouch {
	now := time.Now().UTC()
	start := now.Add(-time.Duration(windowSeconds) * time.Second)
	step := time.Duration(0)
	if count > 1 {
		step = time.Duration(windowSeconds) * time.Second / time.Duration(count)
	}

	pool := make([]int, len(commonScannedPorts))
	copy(pool, commonScannedPorts)
	rand.Shuffle(len(pool), func(i, j int) { pool[i], pool[j] = pool[j], pool[i] })

	touches := make([]portTouch, 0, count)
	for i := 0; i < count; i++ {
		port := pool[i%len(pool)]
		if i >= len(pool) {
			// exhausted the well-known pool; extend into high ports
			port = 20000 + rand.Intn(40000)
		}
		touches = append(touches, portTouch{
			Timestamp: start.Add(step * time.Duration(i)),
			Port:      port,
			Protocol:  "tcp",
		})
	}
	return touches
}
