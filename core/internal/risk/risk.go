// Package risk implements VANGUARD's dynamic risk-scoring formula, shared
// by both the real deterministic detection engine (internal/detection) and
// the attack Simulation Engine (internal/simulator) so a simulated incident
// and a real one are scored identically and are indistinguishable in the
// dashboard.
//
// Per the spec: "Risk is not simply additive. It calculates based on
// context: Risk Score = Base Severity + Frequency + Threat Reputation",
// bucketed into LOW (0-29) / MEDIUM (30-59) / HIGH (60-79) / CRITICAL (80-100).
package risk

import (
	"fmt"

	"vanguard/core/internal/database"
)

// BaseSeverity is the starting-point score for each deterministic signature,
// before frequency/reputation/escalation adjustments. These are the
// "how bad is this category of event, in isolation" weights.
var BaseSeverity = map[database.IncidentType]int{
	database.IncidentSSHBruteForce:     40,
	database.IncidentFailedThenSuccess: 55, // spec explicitly calls this CRITICAL-tier
	database.IncidentPortScan:          25,
	database.IncidentWebDirScan:        20,
	database.IncidentPathTraversal:     35,
	database.IncidentSQLiXSS:           35,
	database.IncidentHTTPFlood:         30,
	database.IncidentHoneypotTrigger:   70, // spec: "ANY connection = CRITICAL"
}

// Breakdown documents how a RiskScore was derived. Every detector (real or
// simulated) populates one of these so the dashboard and the AI Analyst can
// explain *why* a score is what it is, rather than presenting an opaque
// number.
type Breakdown struct {
	BaseSeverity    int    `json:"base_severity"`
	FrequencyBonus  int    `json:"frequency_bonus"`
	ReputationBonus int    `json:"reputation_bonus"`
	EscalationBonus int    `json:"escalation_bonus"`
	Total           int    `json:"total"` // clamped 0-100
	Explanation     string `json:"explanation"`
}

// Input carries everything the scorer needs to compute a Breakdown for one
// incident-in-progress.
type Input struct {
	Type IncidentTypeOrRaw

	// EventCount is the number of matched events that make up this
	// incident (failed logins, distinct ports touched, requests in the
	// flood window, etc). Used to compute FrequencyBonus relative to the
	// signature's own detection threshold.
	EventCount int
	// Threshold is the minimum EventCount that triggers this detector at
	// all (e.g. 10 for SSH brute force, 300 for HTTP flood). FrequencyBonus
	// scales with how far EventCount exceeds Threshold.
	Threshold int
	// MaxFrequencyBonus caps how much the frequency component alone can
	// contribute, so no single factor can push a score to CRITICAL by
	// itself (mirrors the "not simply additive" framing in the spec).
	MaxFrequencyBonus int

	// RecentIncidentCount is how many prior incidents this same source IP
	// has triggered recently (e.g. in the last 24h) - the "Threat
	// Reputation" input for repeat offenders.
	RecentIncidentCount int
	// ThreatIntelHit indicates the IP appeared on an OSINT malicious-IP
	// feed synced by the Python toolkit's Threat Intel Sync job.
	ThreatIntelHit bool

	// Escalate marks a hard policy escalation independent of the above,
	// e.g. the failed-then-successful-login CRITICAL rule, or a honeypot
	// trigger. EscalationBonus is added on top of everything else.
	Escalate       bool
	EscalationNote string
}

// IncidentTypeOrRaw lets callers score either a real database.IncidentType
// or a raw string not yet promoted to the enum, without an import cycle.
type IncidentTypeOrRaw = database.IncidentType

// Score computes a full Breakdown for the given Input using the shared
// formula. It never panics on unknown types; an unknown IncidentType simply
// contributes a conservative BaseSeverity of 20.
func Score(in Input) Breakdown {
	base, ok := BaseSeverity[in.Type]
	if !ok {
		base = 20
	}

	// Frequency: how far past the trigger threshold are we, capped.
	freq := 0
	if in.Threshold > 0 && in.EventCount > in.Threshold {
		freq = in.EventCount - in.Threshold
	}
	freqCap := in.MaxFrequencyBonus
	if freqCap <= 0 {
		freqCap = 30
	}
	if freq > freqCap {
		freq = freqCap
	}

	// Threat Reputation: repeat offenders + known-bad IPs from threat intel.
	rep := in.RecentIncidentCount * 5
	if rep > 20 {
		rep = 20
	}
	if in.ThreatIntelHit {
		rep += 15
	}
	if rep > 30 {
		rep = 30
	}

	// Escalation: hard policy override for CRITICAL-by-definition events.
	esc := 0
	if in.Escalate {
		esc = 25
	}

	total := clamp(base + freq + rep + esc)

	explanation := fmt.Sprintf(
		"base=%d (%s) + frequency=%d (%d events, threshold %d) + reputation=%d (%d recent incidents, threat_intel=%v) + escalation=%d (%s) = %d",
		base, in.Type, freq, in.EventCount, in.Threshold, rep, in.RecentIncidentCount, in.ThreatIntelHit, esc,
		nonEmpty(in.EscalationNote, "none"), total,
	)

	return Breakdown{
		BaseSeverity:    base,
		FrequencyBonus:  freq,
		ReputationBonus: rep,
		EscalationBonus: esc,
		Total:           total,
		Explanation:     explanation,
	}
}

// Severity maps a total score to the documented LOW/MEDIUM/HIGH/CRITICAL
// bucket. Thin wrapper kept here so callers only need to import one
// package for both scoring and bucketing.
func Severity(total int) database.Severity {
	return database.SeverityFromScore(total)
}

func clamp(v int) int {
	if v < 0 {
		return 0
	}
	if v > 100 {
		return 100
	}
	return v
}

func nonEmpty(s, fallback string) string {
	if s == "" {
		return fallback
	}
	return s
}
