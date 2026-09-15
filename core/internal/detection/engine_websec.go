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

// ---------------------------------------------------------------------------
// Rule: API Abuse Detection (feature 13)
//
// Deliberately complements (never duplicates) ruleWebDirScan (sensitive-
// path 404 repetition), ruleHTTPFlood (raw request volume), and
// ruleWebScannerBehavior (4xx frequency + suspicious UA): this rule keys
// off DISTINCT PATH DIVERSITY combined with a FAILURE RATIO, catching
// "one client enumerating many different endpoints, mostly
// unsuccessfully" -- a shape none of those other rules specifically
// target. Applies to every HTTP request regardless of status code so
// successful requests count toward path diversity too, but the failure
// ratio only credits 401/403/404 responses.
// ---------------------------------------------------------------------------

func (e *Engine) ruleAPIAbuse(ev *Event) {
	failure := isAPIAbuseFailureStatus(ev.StatusCode)
	snap := e.apiAbuse.RecordRequest(ev.SourceIP, ev.Path, failure, ev.Timestamp, thresholds.APIAbuseWindow)

	matched, failureRatioTenths := evaluateAPIAbuse(snap)
	if !matched {
		return
	}
	if !e.dedupe.allow(ev.SourceIP, database.IncidentAPIAbuse) {
		return
	}

	breakdown := risk.Score(risk.Input{
		Type:                database.IncidentAPIAbuse,
		EventCount:          snap.DistinctPaths,
		Threshold:           thresholds.APIAbuseMinDistinctPaths,
		MaxFrequencyBonus:   20,
		RecentIncidentCount: e.recentCount(ev.SourceIP),
		ThreatIntelHit:      e.intel.IsMalicious(ev.SourceIP),
	})

	e.createIncident(database.IncidentAPIAbuse, ev, snap.DistinctPaths, breakdown, map[string]any{
		"window_seconds":       int(thresholds.APIAbuseWindow.Seconds()),
		"distinct_paths":       snap.DistinctPaths,
		"total_requests":       snap.TotalRequests,
		"failure_ratio_tenths": failureRatioTenths,
		"last_path":            ev.Path,
		"note":                 "indicator only: endpoint-enumeration-SHAPED traffic (high path diversity + high 401/403/404 ratio), layered on top of (not duplicating) Web Scanner Behavior/HTTP Flood/Web Dir Scan",
	})
}

// ---------------------------------------------------------------------------
// Rule: HTTP Protocol Anomaly Detection (feature 11)
//
// A single malformed request (bad method, non-standard protocol token, or
// a 400/414/431 response) is never itself an incident -- scanners and
// broken clients produce these constantly. Only records into the
// WindowCounterTracker when isProtocolAnomalous(ev) is true at all, so
// well-formed traffic never touches this tracker's memory; the incident
// only fires once the SUSTAINED RATE within the window crosses
// HTTPProtocolAnomalyMinCount.
// ---------------------------------------------------------------------------

func (e *Engine) ruleHTTPProtocolAnomaly(ev *Event) {
	if !isProtocolAnomalous(ev) {
		return
	}
	count := e.protoAnomaly.Record(ev.SourceIP, ev.Timestamp, thresholds.HTTPProtocolAnomalyWindow)
	if count < thresholds.HTTPProtocolAnomalyMinCount {
		return
	}
	if !e.dedupe.allow(ev.SourceIP, database.IncidentHTTPProtocolAnomaly) {
		return
	}

	breakdown := risk.Score(risk.Input{
		Type:                database.IncidentHTTPProtocolAnomaly,
		EventCount:          count,
		Threshold:           thresholds.HTTPProtocolAnomalyMinCount,
		MaxFrequencyBonus:   20,
		RecentIncidentCount: e.recentCount(ev.SourceIP),
		ThreatIntelHit:      e.intel.IsMalicious(ev.SourceIP),
	})

	e.createIncident(database.IncidentHTTPProtocolAnomaly, ev, count, breakdown, map[string]any{
		"window_seconds":   int(thresholds.HTTPProtocolAnomalyWindow.Seconds()),
		"anomaly_count":    count,
		"last_method":      ev.Method,
		"last_protocol":    ev.Protocol,
		"last_status_code": ev.StatusCode,
		"note":             "indicator only: sustained rate of malformed-method/non-standard-protocol/400-414-431 requests from one source; a single malformed request is never itself flagged",
	})
}

// ---------------------------------------------------------------------------
// Rule: Request-Smuggling Indicators (feature 12)
//
// SYMPTOM-ONLY: VANGUARD's log-line visibility cannot see raw
// Content-Length/Transfer-Encoding header values at all -- this only
// watches for an abnormal burst of 400/408/502/503 responses from one
// source in a short window, which is consistent with, but nowhere near
// proof of, a smuggling attempt against a front-end/back-end pair.
// ---------------------------------------------------------------------------

func (e *Engine) ruleRequestSmuggling(ev *Event) {
	if !isRequestSmugglingSymptomStatus(ev.StatusCode) {
		return
	}
	count := e.smuggling.Record(ev.SourceIP, ev.Timestamp, thresholds.RequestSmugglingWindow)
	if count < thresholds.RequestSmugglingMinCount {
		return
	}
	if !e.dedupe.allow(ev.SourceIP, database.IncidentRequestSmugglingIndicator) {
		return
	}

	breakdown := risk.Score(risk.Input{
		Type:                database.IncidentRequestSmugglingIndicator,
		EventCount:          count,
		Threshold:           thresholds.RequestSmugglingMinCount,
		MaxFrequencyBonus:   20,
		RecentIncidentCount: e.recentCount(ev.SourceIP),
		ThreatIntelHit:      e.intel.IsMalicious(ev.SourceIP),
	})

	e.createIncident(database.IncidentRequestSmugglingIndicator, ev, count, breakdown, map[string]any{
		"window_seconds":   int(thresholds.RequestSmugglingWindow.Seconds()),
		"symptom_count":    count,
		"last_status_code": ev.StatusCode,
		"note":             "SYMPTOM-ONLY: VANGUARD cannot see request headers (Content-Length/Transfer-Encoding) from standard access logs; this is a burst of 400/408/502/503 responses consistent with, but nowhere near proof of, request smuggling",
	})
}

// ---------------------------------------------------------------------------
// Rule: SSRF Indicators (feature 8)
//
// A single matching request is enough (unlike the sustained-rate
// detectors above) -- see rules_ssrf.go's doc comment for the full
// evidence/visibility-limitation rationale. Escalates only for a
// cloud-metadata-endpoint hit specifically, never for an ordinary
// RFC1918/loopback reference alone.
// ---------------------------------------------------------------------------

func (e *Engine) ruleSSRFIndicator(ev *Event) {
	matched, metadataHit, target := isSSRFIndicator(ev.Path)
	if !matched {
		return
	}
	if !e.dedupe.allow(ev.SourceIP, database.IncidentSSRFIndicator) {
		return
	}
	e.state.Touch(ev.SourceIP, ev.Timestamp)

	breakdown := risk.Score(risk.Input{
		Type:                database.IncidentSSRFIndicator,
		EventCount:          1,
		Threshold:           0,
		RecentIncidentCount: e.recentCount(ev.SourceIP),
		ThreatIntelHit:      e.intel.IsMalicious(ev.SourceIP),
		Escalate:            metadataHit,
		EscalationNote:      "request target references a cloud-metadata endpoint",
	})

	e.createIncident(database.IncidentSSRFIndicator, ev, 1, breakdown, map[string]any{
		"path":                  ev.Path,
		"matched_target":        target,
		"metadata_endpoint_hit": metadataHit,
		"note":                  "indicator only: VANGUARD only sees the request path/query (never the body) and cannot confirm the backend actually issued the resulting internal request",
	})
}

// ---------------------------------------------------------------------------
// Rule: Host Header / Virtual Host Abuse (feature 10)
//
// Only evaluated when ev.Host is non-empty -- the stock Nginx/Apache
// "combined" access-log format most deployments run does NOT log Host at
// all (see parser_web.go), and a missing Host field must never itself be
// treated as suspicious. Four independent signals, any one of which is
// sufficient: IP-literal Host, loopback/private Host, a Host that fails
// to match an operator-configured allowlist (only when configured), or
// enumeration (many distinct Host values from one IP in a short window).
// ---------------------------------------------------------------------------

func (e *Engine) ruleHostHeaderAbuse(ev *Event) {
	if ev.Host == "" {
		return
	}

	distinctHosts := e.hostHeader.Record(ev.SourceIP, ev.Host, ev.Timestamp, thresholds.HostHeaderEnumerationWindow)

	ipLiteral := hostLooksLikeIPLiteral(ev.Host)
	loopbackOrPrivate := hostIsLoopbackOrPrivate(ev.Host)
	applicable, expectedMatch := hostMatchesExpected(ev.Host)
	unexpectedHost := applicable && !expectedMatch
	enumeration := distinctHosts >= thresholds.HostHeaderEnumerationMinDistinctHosts

	if !ipLiteral && !loopbackOrPrivate && !unexpectedHost && !enumeration {
		return
	}
	if !e.dedupe.allow(ev.SourceIP, database.IncidentHostHeaderAnomaly) {
		return
	}

	// Escalate (rather than rely on frequency alone) when the single
	// current request itself is the strong signal (IP literal or
	// loopback/private Host) -- these are meaningful on a single
	// occurrence, unlike enumeration which is inherently frequency-based.
	escalate := ipLiteral || loopbackOrPrivate

	breakdown := risk.Score(risk.Input{
		Type:                database.IncidentHostHeaderAnomaly,
		EventCount:          distinctHosts,
		Threshold:           thresholds.HostHeaderEnumerationMinDistinctHosts,
		MaxFrequencyBonus:   15,
		RecentIncidentCount: e.recentCount(ev.SourceIP),
		ThreatIntelHit:      e.intel.IsMalicious(ev.SourceIP),
		Escalate:            escalate,
		EscalationNote:      "Host header names a raw IP literal or a loopback/private address",
	})

	e.createIncident(database.IncidentHostHeaderAnomaly, ev, distinctHosts, breakdown, map[string]any{
		"window_seconds":              int(thresholds.HostHeaderEnumerationWindow.Seconds()),
		"distinct_hosts":              distinctHosts,
		"last_host":                   ev.Host,
		"host_is_ip_literal":          ipLiteral,
		"host_is_loopback_or_private": loopbackOrPrivate,
		"host_unexpected":             unexpectedHost,
		"host_enumeration":            enumeration,
		"note":                        "indicator only: an unexpected Host value alone is often just a misconfigured client or bot; escalated only for IP-literal/loopback/private Host values or sustained enumeration",
	})
}
