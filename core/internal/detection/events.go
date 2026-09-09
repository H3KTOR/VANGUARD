// Package detection implements VANGUARD's V1 deterministic Detection
// Engine: parsers that turn raw log lines into structured Events, and a
// stateful Engine that applies fixed rules (sliding-window counters, no
// ML/heuristics) to those events to raise Incidents.
//
// VANGUARD observes and flags attacks deterministically. It does not
// exploit or validate payloads against the host application.
package detection

import "time"

// EventKind classifies a single normalized log event before rule
// evaluation.
type EventKind string

const (
	EventSSHAuthFailure EventKind = "ssh_auth_failure"
	EventSSHAuthSuccess EventKind = "ssh_auth_success"
	EventPortTouch      EventKind = "port_touch"
	EventHTTPRequest    EventKind = "http_request"
	EventHoneypotHit    EventKind = "honeypot_hit"

	// EventHostSecurityFinding marks an Event synthesized from a
	// internal/hostsec periodic scanner finding (FIM, Persistence,
	// Account, Privilege Escalation, SUID/SGID -- Phase 1), rather than
	// parsed from a tailed log line. It is never passed to handleEvent
	// (see engine_hostsec.go's ReportHostFinding, which calls
	// createIncident directly) -- this constant exists purely so the
	// resulting Incident's evidence Event carries a self-describing Kind
	// for any future code/tests that inspect it.
	EventHostSecurityFinding EventKind = "host_security_finding"
)

// Event is the normalized representation of one observed occurrence,
// regardless of source (auth.log, nginx access log, honeypot listener,
// raw connection tracking). The rule Engine only ever operates on Events,
// never on raw log text, so new log sources just need a parser that emits
// Events -- no rule code has to change.
type Event struct {
	Kind      EventKind
	SourceIP  string
	Timestamp time.Time

	// --- SSH-specific fields ---
	Username string

	// --- Port-scan-specific fields ---
	Port int

	// --- HTTP-specific fields ---
	Method     string
	Path       string
	StatusCode int
	UserAgent  string

	// RawLine is the original log line, kept for incident evidence /
	// forensics and shown in the dashboard's "matched log lines" panel.
	RawLine string
}
