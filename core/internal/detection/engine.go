package detection

import (
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"vanguard/core/internal/database"
	"vanguard/core/internal/risk"
	"vanguard/core/internal/thresholds"
)

// ThreatIntelChecker abstracts the OSINT malicious-IP lookup populated by
// the Python toolkit's Threat Intel Sync job, so the detection engine can
// factor it into risk scoring without importing the toolkit (which is a
// separate, ephemeral process that only touches the DB directly).
// Implementations should be fast (in-memory set or single indexed query)
// since this is called on every event.
type ThreatIntelChecker interface {
	IsMalicious(ip string) bool
}

// noopThreatIntel is used when no checker is configured; every IP is
// treated as unknown/clean.
type noopThreatIntel struct{}

func (noopThreatIntel) IsMalicious(string) bool { return false }

// Notifier receives a callback for every newly created Incident, letting
// the firewall/Autopilot package react immediately (e.g. issue a TTL ban)
// without the detection engine importing the firewall package directly.
type Notifier interface {
	OnIncident(inc *database.Incident)
}

// noopNotifier is used when no notifier is configured.
type noopNotifier struct{}

func (noopNotifier) OnIncident(*database.Incident) {}

// Engine evaluates normalized Events against VANGUARD's fixed V1 rule set,
// maintaining per-IP sliding-window state and persisting Incidents (via
// internal/risk for scoring) whenever a rule's threshold is crossed.
//
// Engine is safe for concurrent use: multiple tailers (auth.log, web
// access log, honeypot) can feed it events from separate goroutines.
type Engine struct {
	db     *database.DB
	state  *State
	intel  ThreatIntelChecker
	notify Notifier
	authP  *AuthLogParser
	webP   *WebLogParser
	dedupe *dedupeWindow
}

// Config controls Engine construction.
type Config struct {
	DB *database.DB
	// MaxIdle bounds how long per-IP in-memory state is retained with no
	// activity (see State.Reap). Defaults to 30 minutes.
	MaxIdle time.Duration
	// ThreatIntel is consulted for the "Threat Reputation" risk component.
	// Optional; defaults to a no-op (never flags an IP).
	ThreatIntel ThreatIntelChecker
	// Notifier is invoked synchronously whenever a new Incident is
	// created. Optional; defaults to a no-op. The firewall/Autopilot
	// package should implement this to react in real time.
	Notifier Notifier
}

// NewEngine constructs a detection Engine bound to db.
func NewEngine(cfg Config) *Engine {
	intel := cfg.ThreatIntel
	if intel == nil {
		intel = noopThreatIntel{}
	}
	notify := cfg.Notifier
	if notify == nil {
		notify = noopNotifier{}
	}
	return &Engine{
		db:     cfg.DB,
		state:  NewState(cfg.MaxIdle),
		intel:  intel,
		notify: notify,
		authP:  NewAuthLogParser(),
		webP:   NewWebLogParser(),
		dedupe: newDedupeWindow(2 * time.Minute),
	}
}

// State exposes the underlying sliding-window state, primarily so
// cmd/vanguard's background maintenance loop can call Reap() periodically.
func (e *Engine) State() *State { return e.state }

// IngestAuthLogLine parses one /var/log/auth.log line and applies the SSH
// brute-force / failed-then-success rules if it matches.
func (e *Engine) IngestAuthLogLine(line string) {
	ev, ok := e.authP.Parse(line)
	if !ok {
		return
	}
	e.handleEvent(ev)
}

// IngestWebLogLine parses one Nginx/Apache access-log line and applies the
// port-scan-adjacent web rules (dir scanning, path traversal, SQLi/XSS,
// HTTP flood) if it matches.
func (e *Engine) IngestWebLogLine(line string) {
	ev, ok := e.webP.Parse(line)
	if !ok {
		return
	}
	e.handleEvent(ev)
}

// IngestPortTouch feeds a single observed connection attempt to
// (ip, port) into the port-scan rule. Intended to be called by a raw
// connection-tracking source (e.g. conntrack, or the honeypot's own
// listeners for non-decoy ports) rather than parsed from a log file.
func (e *Engine) IngestPortTouch(ip string, port int, ts time.Time) {
	e.handleEvent(&Event{Kind: EventPortTouch, SourceIP: ip, Port: port, Timestamp: ts})
}

// IngestHoneypotHit feeds a single connection to a decoy port. Per spec
// this is CRITICAL regardless of frequency -- no threshold, no dedupe
// suppression beyond the standard incident cooldown.
func (e *Engine) IngestHoneypotHit(ip string, port int, service string, ts time.Time, rawLine string) {
	e.handleEvent(&Event{
		Kind: EventHoneypotHit, SourceIP: ip, Port: port, Timestamp: ts,
		RawLine: rawLine, UserAgent: service, // reuse UserAgent field to carry the decoy service name
	})
}

// handleEvent is the single dispatch point every Ingest* method funnels
// through, applying whichever rule(s) are relevant to ev.Kind.
func (e *Engine) handleEvent(ev *Event) {
	if ev.Timestamp.IsZero() {
		ev.Timestamp = time.Now().UTC()
	}
	if ev.SourceIP == "" {
		return
	}

	switch ev.Kind {
	case EventSSHAuthFailure:
		e.ruleSSHBruteForce(ev)
	case EventSSHAuthSuccess:
		e.ruleFailedThenSuccess(ev)
	case EventPortTouch:
		e.rulePortScan(ev)
	case EventHTTPRequest:
		e.ruleWebDirScan(ev)
		e.rulePathTraversal(ev)
		e.ruleSQLiXSS(ev)
		e.ruleHTTPFlood(ev)
	case EventHoneypotHit:
		e.ruleHoneypot(ev)
	}
}

// ---------------------------------------------------------------------------
// Rule: SSH Brute Force ("> 10 failed attempts from one IP in a short window")
// ---------------------------------------------------------------------------

func (e *Engine) ruleSSHBruteForce(ev *Event) {
	count := e.state.RecordSSHFailure(ev.SourceIP, ev.Timestamp, thresholds.SSHBruteForceWindow)
	if count <= thresholds.SSHBruteForceMinAttempts {
		return
	}
	if !e.dedupe.allow(ev.SourceIP, database.IncidentSSHBruteForce) {
		return
	}

	breakdown := risk.Score(risk.Input{
		Type:                database.IncidentSSHBruteForce,
		EventCount:          count,
		Threshold:           thresholds.SSHBruteForceMinAttempts,
		MaxFrequencyBonus:   30,
		RecentIncidentCount: e.recentCount(ev.SourceIP),
		ThreatIntelHit:      e.intel.IsMalicious(ev.SourceIP),
	})

	e.createIncident(database.IncidentSSHBruteForce, ev, count, breakdown, map[string]any{
		"window_seconds": int(thresholds.SSHBruteForceWindow.Seconds()),
		"last_username":  ev.Username,
		"sample_line":    ev.RawLine,
	})
}

// ---------------------------------------------------------------------------
// Rule: Failed -> Successful Login Sequence (CRITICAL)
// ---------------------------------------------------------------------------

func (e *Engine) ruleFailedThenSuccess(ev *Event) {
	failedBefore, escalate := e.state.RecordSSHSuccess(
		ev.SourceIP, ev.Timestamp, thresholds.FailedThenSuccessWindow, thresholds.FailedThenSuccessMinFailed)
	if !escalate {
		return
	}
	if !e.dedupe.allow(ev.SourceIP, database.IncidentFailedThenSuccess) {
		return
	}

	breakdown := risk.Score(risk.Input{
		Type:                database.IncidentFailedThenSuccess,
		EventCount:          failedBefore,
		Threshold:           thresholds.FailedThenSuccessMinFailed,
		MaxFrequencyBonus:   20,
		RecentIncidentCount: e.recentCount(ev.SourceIP),
		ThreatIntelHit:      e.intel.IsMalicious(ev.SourceIP),
		Escalate:            true,
		EscalationNote:      "failed-then-successful login sequence (possible compromise)",
	})

	e.createIncident(database.IncidentFailedThenSuccess, ev, failedBefore, breakdown, map[string]any{
		"failed_attempts_before_success": failedBefore,
		"successful_username":            ev.Username,
		"sample_line":                    ev.RawLine,
	})
}

// ---------------------------------------------------------------------------
// Rule: Port Scanning ("One IP touching multiple ports rapidly.")
// ---------------------------------------------------------------------------

func (e *Engine) rulePortScan(ev *Event) {
	distinct := e.state.RecordPortTouch(ev.SourceIP, ev.Port, ev.Timestamp, thresholds.PortScanWindow)
	if distinct <= thresholds.PortScanDistinctPorts {
		return
	}
	if !e.dedupe.allow(ev.SourceIP, database.IncidentPortScan) {
		return
	}

	breakdown := risk.Score(risk.Input{
		Type:                database.IncidentPortScan,
		EventCount:          distinct,
		Threshold:           thresholds.PortScanDistinctPorts,
		MaxFrequencyBonus:   25,
		RecentIncidentCount: e.recentCount(ev.SourceIP),
		ThreatIntelHit:      e.intel.IsMalicious(ev.SourceIP),
	})

	e.createIncident(database.IncidentPortScan, ev, distinct, breakdown, map[string]any{
		"window_seconds": int(thresholds.PortScanWindow.Seconds()),
		"last_port":      ev.Port,
	})
}

// ---------------------------------------------------------------------------
// Rule: Web Directory Scanning ("Repeated 404s on sensitive paths.")
// ---------------------------------------------------------------------------

func (e *Engine) ruleWebDirScan(ev *Event) {
	if ev.StatusCode != 404 || !isSensitivePath(ev.Path) {
		return
	}
	count := e.state.RecordSensitive404(ev.SourceIP, ev.Timestamp, thresholds.WebDirScanWindow)
	if count < thresholds.WebDirScanMin404s {
		return
	}
	if !e.dedupe.allow(ev.SourceIP, database.IncidentWebDirScan) {
		return
	}

	breakdown := risk.Score(risk.Input{
		Type:                database.IncidentWebDirScan,
		EventCount:          count,
		Threshold:           thresholds.WebDirScanMin404s,
		MaxFrequencyBonus:   20,
		RecentIncidentCount: e.recentCount(ev.SourceIP),
		ThreatIntelHit:      e.intel.IsMalicious(ev.SourceIP),
	})

	e.createIncident(database.IncidentWebDirScan, ev, count, breakdown, map[string]any{
		"last_path":      ev.Path,
		"user_agent":     ev.UserAgent,
		"window_seconds": int(thresholds.WebDirScanWindow.Seconds()),
	})
}

// ---------------------------------------------------------------------------
// Rule: Vulnerability Probing / Path Traversal
// ---------------------------------------------------------------------------

func (e *Engine) rulePathTraversal(ev *Event) {
	if !containsAny(ev.Path, thresholds.PathTraversalPatterns) {
		return
	}
	if !e.dedupe.allow(ev.SourceIP, database.IncidentPathTraversal) {
		return
	}
	e.state.Touch(ev.SourceIP, ev.Timestamp)

	breakdown := risk.Score(risk.Input{
		Type:                database.IncidentPathTraversal,
		EventCount:          1,
		Threshold:           0,
		RecentIncidentCount: e.recentCount(ev.SourceIP),
		ThreatIntelHit:      e.intel.IsMalicious(ev.SourceIP),
	})

	e.createIncident(database.IncidentPathTraversal, ev, 1, breakdown, map[string]any{
		"path":        ev.Path,
		"user_agent":  ev.UserAgent,
		"sample_line": ev.RawLine,
	})
}

// ---------------------------------------------------------------------------
// Rule: SQLi & XSS Indicators (detection only, no exploitation attempted)
// ---------------------------------------------------------------------------

func (e *Engine) ruleSQLiXSS(ev *Event) {
	if !containsAny(strings.ToLower(ev.Path), thresholds.SQLiXSSPatterns) {
		return
	}
	if !e.dedupe.allow(ev.SourceIP, database.IncidentSQLiXSS) {
		return
	}
	e.state.Touch(ev.SourceIP, ev.Timestamp)

	breakdown := risk.Score(risk.Input{
		Type:                database.IncidentSQLiXSS,
		EventCount:          1,
		Threshold:           0,
		RecentIncidentCount: e.recentCount(ev.SourceIP),
		ThreatIntelHit:      e.intel.IsMalicious(ev.SourceIP),
	})

	e.createIncident(database.IncidentSQLiXSS, ev, 1, breakdown, map[string]any{
		"path":        ev.Path,
		"user_agent":  ev.UserAgent,
		"sample_line": ev.RawLine,
	})
}

// ---------------------------------------------------------------------------
// Rule: HTTP Flood ("> 300 requests from one IP within 60 seconds.")
// ---------------------------------------------------------------------------

func (e *Engine) ruleHTTPFlood(ev *Event) {
	count := e.state.RecordHTTPRequest(ev.SourceIP, ev.Timestamp, thresholds.HTTPFloodWindow)
	if count <= thresholds.HTTPFloodMaxRequests {
		return
	}
	if !e.dedupe.allow(ev.SourceIP, database.IncidentHTTPFlood) {
		return
	}

	breakdown := risk.Score(risk.Input{
		Type:                database.IncidentHTTPFlood,
		EventCount:          count,
		Threshold:           thresholds.HTTPFloodMaxRequests,
		MaxFrequencyBonus:   25,
		RecentIncidentCount: e.recentCount(ev.SourceIP),
		ThreatIntelHit:      e.intel.IsMalicious(ev.SourceIP),
	})

	e.createIncident(database.IncidentHTTPFlood, ev, count, breakdown, map[string]any{
		"window_seconds": int(thresholds.HTTPFloodWindow.Seconds()),
	})
}

// ---------------------------------------------------------------------------
// Rule: Honeypot Trigger ("ANY connection to designated fake ports (CRITICAL)")
// ---------------------------------------------------------------------------

func (e *Engine) ruleHoneypot(ev *Event) {
	// Deliberately no threshold and a much shorter dedupe window than
	// other rules: even a repeat connection from the same scanner a few
	// seconds later is worth a fresh look, but we still avoid a flood of
	// duplicate incidents from one lingering TCP client.
	if !e.dedupe.allow(ev.SourceIP, database.IncidentHoneypotTrigger) {
		return
	}
	e.state.Touch(ev.SourceIP, ev.Timestamp)

	breakdown := risk.Score(risk.Input{
		Type:                database.IncidentHoneypotTrigger,
		EventCount:          1,
		Threshold:           0,
		RecentIncidentCount: e.recentCount(ev.SourceIP),
		ThreatIntelHit:      e.intel.IsMalicious(ev.SourceIP),
		Escalate:            true,
		EscalationNote:      "honeypot connection (deception layer triggered)",
	})

	e.createIncident(database.IncidentHoneypotTrigger, ev, 1, breakdown, map[string]any{
		"decoy_port":    ev.Port,
		"decoy_service": ev.UserAgent,
		"sample_line":   ev.RawLine,
	})
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

func (e *Engine) recentCount(ip string) int {
	if e.db == nil {
		return 0
	}
	count, err := e.db.CountRecentEventsByIP(ip, time.Now().UTC().Add(-24*time.Hour))
	if err != nil {
		return 0
	}
	return int(count)
}

// createIncident persists the Incident and notifies e.notify. Errors are
// logged rather than returned/panicked since this is called from the hot
// path of log ingestion -- a DB hiccup must never crash the tailer or drop
// subsequent events.
func (e *Engine) createIncident(itype database.IncidentType, ev *Event, attemptCount int, breakdown risk.Breakdown, extra map[string]any) {
	if e.db == nil {
		log.Printf("[detection] WARNING: no database configured, dropping %s incident for %s", itype, ev.SourceIP)
		return
	}

	inc := &database.Incident{
		Type:         itype,
		SourceIP:     ev.SourceIP,
		RiskScore:    breakdown.Total,
		Severity:     risk.Severity(breakdown.Total),
		Status:       database.StatusOpen,
		AttemptCount: attemptCount,
		DetectedAt:   ev.Timestamp,
	}

	meta := map[string]any{
		"score_breakdown": breakdown,
	}
	for k, v := range extra {
		meta[k] = v
	}
	if err := inc.SetMetadata(meta); err != nil {
		log.Printf("[detection] failed to encode metadata for %s incident on %s: %v", itype, ev.SourceIP, err)
	}

	if err := e.db.CreateIncident(inc); err != nil {
		log.Printf("[detection] failed to persist %s incident on %s: %v", itype, ev.SourceIP, err)
		return
	}

	log.Printf("[detection] incident #%d: %s from %s (risk=%d/%s)", inc.ID, itype, ev.SourceIP, breakdown.Total, inc.Severity)
	e.notify.OnIncident(inc)
}

func isSensitivePath(path string) bool {
	lower := strings.ToLower(path)
	for _, p := range thresholds.SensitivePaths {
		if strings.HasPrefix(lower, strings.ToLower(p)) {
			return true
		}
	}
	return false
}

func containsAny(haystack string, needles []string) bool {
	lower := strings.ToLower(haystack)
	for _, n := range needles {
		if strings.Contains(lower, strings.ToLower(n)) {
			return true
		}
	}
	return false
}

// dedupeWindow suppresses re-raising the same (ip, incident type) incident
// more than once per cooldown period, so a sustained attack that keeps
// exceeding the threshold every event doesn't flood the incidents table
// with near-duplicates. The Autopilot still keeps the IP banned via TTL
// renewal logic in the firewall package, independent of this cooldown.
type dedupeWindow struct {
	cooldown time.Duration
	last     map[string]time.Time
	mu       sync.Mutex
}

func newDedupeWindow(cooldown time.Duration) *dedupeWindow {
	return &dedupeWindow{cooldown: cooldown, last: make(map[string]time.Time)}
}

func (d *dedupeWindow) allow(ip string, itype database.IncidentType) bool {
	key := fmt.Sprintf("%s|%s", ip, itype)
	d.mu.Lock()
	defer d.mu.Unlock()
	now := time.Now()
	if last, ok := d.last[key]; ok && now.Sub(last) < d.cooldown {
		return false
	}
	d.last[key] = now
	return true
}
