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
	"vanguard/core/internal/thresholds"
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
	database.IncidentWebScanner:        45, // heuristic automated-scanner behavior

	// IncidentAttackChain is scored via ScoreChain, not the generic Score()
	// formula below (it needs the aggregated-then-x1.5 treatment the spec
	// calls for), but it still needs an entry here so any caller that falls
	// back to the generic map (e.g. an unrelated FrequencyBonus/reputation
	// lookup, or a future dashboard "expected base severity" display) never
	// silently gets the conservative default of 20 for what is VANGUARD's
	// most severe signature.
	database.IncidentAttackChain: 90,

	// IncidentWebAttackChain is likewise scored via ScoreChain (see
	// ChainTracker.EvaluateWebAttackChain in correlation.go), needing
	// this map entry for the same fallback reasons as IncidentAttackChain
	// above. Its aggregated constituent severities (Web Probing + Auth
	// Probing + Exploitation stage) are naturally lower than the classic
	// recon/web/auth chain's, since Phase 3's own constituent base
	// severities are deliberately conservative -- still VANGUARD's
	// second web-focused most-severe signature after a direct
	// IncidentHighConfidenceCompromise correlation.
	database.IncidentWebAttackChain: 75,

	// --- Host Security (Phase 1) ---
	// These base severities are intentionally high: every one of these
	// signatures represents host-local evidence with essentially no
	// legitimate-traffic false-positive surface (unlike, say, a single
	// 404), so per Phase 16's "confidence-threshold" guidance the prior
	// (base severity) itself should already reflect high confidence.
	// Specific escalations (e.g. SUID binary in /tmp) still use the
	// Escalate/EscalationBonus mechanism on top of these.
	database.IncidentFIMChange:           60, // HIGH tier: modification of a sensitive file baseline
	database.IncidentPersistenceDetected: 55, // HIGH tier: new/changed persistence mechanism
	database.IncidentPrivilegeEscalation: 65, // HIGH tier: privilege escalation indicator
	database.IncidentAccountChange:       50, // MEDIUM/HIGH boundary: account/group mutation
	database.IncidentSUIDSGIDAnomaly:     55, // HIGH tier; Escalate bumps to CRITICAL if in a writable dir

	// --- Host Security Phase 2 (Process/File/Network Correlation, System
	// Binary Integrity) ---
	database.IncidentSuspiciousProcess:        50, // MEDIUM/HIGH boundary: best-effort userspace signal, deliberately not as high-confidence as the Phase 1 signatures
	database.IncidentSystemBinaryIntegrity:    70, // HIGH tier: a replaced security-critical executable is a strong post-compromise indicator
	database.IncidentHighConfidenceCompromise: 85, // CRITICAL tier: correlated process+file(+network/threat-intel) evidence -- VANGUARD's second-most-severe signature after IncidentAttackChain

	// --- Web Security (Phase 3) ---
	// Deliberately conservative starting severities: every one of these
	// is an INDICATOR or heuristic built from log-visible evidence only
	// (per this phase's explicit "no overclaiming" rule) -- none of them
	// alone constitutes confirmed exploitation. Escalation to HIGH/
	// CRITICAL happens via the same Escalate/EscalationBonus mechanism
	// (a stronger single occurrence, e.g. a metadata-endpoint SSRF hit)
	// or via correlation (e.g. a web-shell indicator corroborated by a
	// Phase 1/2 FIM/process finding), never by inflating the base value.
	database.IncidentPasswordSpraying:          45, // MEDIUM/HIGH boundary: many distinct accounts targeted, same shape-of-evidence tier as SSH brute force
	database.IncidentCredentialStuffing:        50, // MEDIUM/HIGH boundary: broader/higher-rate than spraying alone
	database.IncidentWebShellIndicator:         35, // MEDIUM: a single request-shaped indicator; Escalate bumps this when corroborated by filesystem/process evidence
	database.IncidentSSRFIndicator:             35, // MEDIUM: a single request containing an internal/reserved target string; Escalate bumps this for a metadata-endpoint hit specifically
	database.IncidentOASTIndicator:             30, // LOW/MEDIUM boundary: an external callback-shaped hostname observed in traffic, with no local proof of actual outbound interaction
	database.IncidentHostHeaderAnomaly:         25, // LOW/MEDIUM boundary: a single unexpected Host value alone is often just a misconfigured client or a bot
	database.IncidentHTTPProtocolAnomaly:       25, // LOW/MEDIUM boundary: malformed HTTP is extremely common from broken clients and casual scanners
	database.IncidentRequestSmugglingIndicator: 40, // MEDIUM: symptom-only (status-code-sequence) evidence, explicitly not confirmed smuggling
	database.IncidentAPIAbuse:                  35, // MEDIUM: endpoint-enumeration-shaped traffic; frequency/ratio components push it higher via the standard formula

	// --- System Posture & Drift Detection (Phase 4) ---
	// Every base value below is deliberately a MIDPOINT, not a fixed
	// extreme: the mega-prompt explicitly calls for "contextual
	// escalation" (via Escalate/EscalationBonus on individual findings,
	// e.g. a world-writable /etc/shadow, or a 0.0.0.0 listener on a
	// privileged port) rather than baking the worst case into the base
	// severity itself. A benign/expected occurrence of any of these
	// four signatures should land LOW/MEDIUM; only a genuinely
	// dangerous instance should reach HIGH/CRITICAL, and it does so via
	// risk.Input.Escalate, never by raising the table value below.
	//
	// IncidentConfigurationPosture: a CURRENTLY-unsafe state (unexpected
	// world-writable sensitive config, ownership mismatch). Base is
	// MEDIUM because "currently unsafe" is already more actionable than
	// a single stray log line, but a specific check still escalates
	// (Critical=true) for e.g. a world-writable /etc/shadow or
	// /etc/sudoers -- see hostsec/posture.go's per-check EscalationNote.
	database.IncidentConfigurationPosture: 45,

	// IncidentConfigurationDrift: an ORDINARY monitored-resource change
	// (mode/owner/group/content) is routine system administration most
	// of the time (a package upgrade touching a config file, an admin
	// editing sshd_config) -- base is LOW/MEDIUM. Escalates to
	// Critical=true only when the specific resource is itself
	// security-authentication-relevant (see hostsec/config_drift.go's
	// criticalDriftPaths, mirroring FIM's criticalFIMPaths pattern).
	database.IncidentConfigurationDrift: 35,

	// IncidentListeningServiceDrift: base reflects "a new/changed
	// listener was observed", which by itself is often entirely benign
	// (a service restarting, an admin starting a legitimate tool).
	// Escalates when the listener binds 0.0.0.0/[::] (vs. loopback-only,
	// which stays at or below base), uses a privileged port, or has no
	// process identity resolvable at all -- see hostsec/listening.go's
	// risk-contextualization logic.
	database.IncidentListeningServiceDrift: 40,

	// IncidentPackageDrift: base reflects an ORDINARY package change
	// (install/update), the overwhelmingly common case on any
	// actively-maintained host. Escalates for removal of a
	// security-sensitive watched package, a version DOWNGRADE, or an
	// install from the configured high-risk-pattern list -- see
	// hostsec/package_drift.go's classification.
	database.IncidentPackageDrift: 30,
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

	// ContextAdjust is a signed, graded contextual adjustment (Phase 4
	// System Posture detectors): positive for aggravating context (an
	// all-interface listener, a package downgrade), negative for
	// mitigating context (loopback-only listener, routine package
	// update). It is folded into EscalationBonus so the Breakdown shape
	// is unchanged, and the final total is still clamped to 0-100.
	ContextAdjust int
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

	esc += in.ContextAdjust

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

// ChainInput carries the three composite signals that fed a detected
// ATTACK_CHAIN correlation (recon -> web probing -> auth probing), each
// expressed as an already-scored constituent-incident-type severity, plus
// the shared reputation/threat-intel context every other rule also
// considers.
type ChainInput struct {
	// ConstituentTypes are the incident types whose BaseSeverity values are
	// aggregated to form the chain's pre-multiplier score. Spec example:
	// PortScan (recon) + WebDirScan (web probing) + SSHBruteForce (auth
	// probing).
	ConstituentTypes []database.IncidentType

	RecentIncidentCount int
	ThreatIntelHit      bool
}

// ScoreChain computes the Breakdown for a correlated ATTACK_CHAIN
// incident. Per spec ("multiply the incident's aggregated Risk Score by
// 1.5"), this does NOT reuse the generic additive Score() formula
// unmodified -- it sums the BaseSeverity of every constituent signal that
// made up the chain into a single "aggregated" base, then applies the
// 1.5x multiplier, then still adds the same Threat Reputation component
// every other rule uses (so a chain from a known-bad IP scores even
// higher), and finally clamps to 100. The multiplier is applied to the
// aggregated base ALONE (before the reputation add-on) so the "x1.5"
// requirement has one unambiguous meaning: it amplifies the severity of
// the coordinated behavior itself, not the unrelated reputation signal.
func ScoreChain(in ChainInput) Breakdown {
	aggregated := 0
	for _, t := range in.ConstituentTypes {
		if v, ok := BaseSeverity[t]; ok {
			aggregated += v
		}
	}

	multiplied := int(float64(aggregated) * thresholds.AttackChainRiskMultiplier)

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

	total := clamp(multiplied + rep)

	explanation := fmt.Sprintf(
		"attack_chain: aggregated_base=%d (from %v) x %.1f = %d + reputation=%d (%d recent incidents, threat_intel=%v) = %d",
		aggregated, in.ConstituentTypes, thresholds.AttackChainRiskMultiplier, multiplied, rep, in.RecentIncidentCount, in.ThreatIntelHit, total,
	)

	return Breakdown{
		BaseSeverity:    aggregated,
		FrequencyBonus:  multiplied - aggregated, // the delta the x1.5 multiplier contributed
		ReputationBonus: rep,
		EscalationBonus: 0,
		Total:           total,
		Explanation:     explanation,
	}
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
