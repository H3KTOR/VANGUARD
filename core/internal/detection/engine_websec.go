package detection

import (
	"vanguard/core/internal/database"
	"vanguard/core/internal/risk"
	"vanguard/core/internal/thresholds"
)

// ---------------------------------------------------------------------------
// Engine wiring for VANGUARD Mega Expansion Phase 3: Advanced Web Security
// Detection. Every rule below follows the EXACT same Detection -> Evidence
// -> Risk -> Correlation -> Response -> Verification pipeline every
// existing rule in engine.go uses: record into a bounded per-IP tracker,
// evaluate a pure decision function, dedupe, score via internal/risk, and
// persist through the single createIncident() choke point. No detector
// here creates a second incident-persistence path, a second notifier, or
// bans an IP directly.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Rule: Password Spraying & Credential Stuffing (features 5 & 6)
//
// Both share the SAME AuthAbuseTracker recording call (one failed-login
// event, one record) since they operate on identical evidence -- the
// SSH-auth-failure Event stream with Username populated by AuthLogParser.
// PasswordSprayingWindow and CredentialStuffingWindow currently share the
// same 10-minute value; RecordFailure is called once with that shared
// window so a single failure is never double-counted into two different
// sliding windows that could drift apart in size.
// ---------------------------------------------------------------------------

func (e *Engine) ruleAuthAbuse(ev *Event) {
	window := thresholds.PasswordSprayingWindow
	snap := e.authAbuse.RecordFailure(ev.SourceIP, ev.Username, ev.Timestamp, window)

	e.rulePasswordSpraying(ev, snap)
	e.ruleCredentialStuffing(ev, snap)
}

func (e *Engine) rulePasswordSpraying(ev *Event, snap AuthAbuseSnapshot) {
	qualifying, matched := evaluatePasswordSpraying(snap)
	if !matched {
		return
	}
	if !e.dedupe.allow(ev.SourceIP, database.IncidentPasswordSpraying) {
		return
	}

	breakdown := risk.Score(risk.Input{
		Type:                database.IncidentPasswordSpraying,
		EventCount:          qualifying,
		Threshold:           thresholds.PasswordSprayingMinDistinctUsernames,
		MaxFrequencyBonus:   20,
		RecentIncidentCount: e.recentCount(ev.SourceIP),
		ThreatIntelHit:      e.intel.IsMalicious(ev.SourceIP),
	})

	e.createIncident(database.IncidentPasswordSpraying, ev, qualifying, breakdown, map[string]any{
		"window_seconds":        int(thresholds.PasswordSprayingWindow.Seconds()),
		"qualifying_accounts":   qualifying,
		"max_attempts_per_user": thresholds.PasswordSprayingMaxAttemptsPerUser,
		"last_username":         ev.Username,
		"note":                  "indicator only: distinct-account/attempt SHAPE observed in auth log evidence, not a confirmed credential-spraying campaign",
	})
}

func (e *Engine) ruleCredentialStuffing(ev *Event, snap AuthAbuseSnapshot) {
	matched, distinctUsernames, totalAttempts, failureRatioTenths := evaluateCredentialStuffing(snap)
	if !matched {
		return
	}
	if !e.dedupe.allow(ev.SourceIP, database.IncidentCredentialStuffing) {
		return
	}

	breakdown := risk.Score(risk.Input{
		Type:                database.IncidentCredentialStuffing,
		EventCount:          totalAttempts,
		Threshold:           thresholds.CredentialStuffingMinTotalAttempts,
		MaxFrequencyBonus:   25,
		RecentIncidentCount: e.recentCount(ev.SourceIP),
		ThreatIntelHit:      e.intel.IsMalicious(ev.SourceIP),
	})

	e.createIncident(database.IncidentCredentialStuffing, ev, totalAttempts, breakdown, map[string]any{
		"window_seconds":       int(thresholds.CredentialStuffingWindow.Seconds()),
		"distinct_usernames":   distinctUsernames,
		"total_attempts":       totalAttempts,
		"failure_ratio_tenths": failureRatioTenths,
		"note":                 "indicator only: observable auth-failure SHAPE (many accounts, high volume, high failure ratio) from one source; VANGUARD cannot confirm credentials were sourced from a prior breach",
	})
}
