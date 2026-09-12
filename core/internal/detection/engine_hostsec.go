// engine_hostsec.go wires internal/hostsec's periodic host-security
// scanners (FIM, Persistence, Account, Privilege Escalation, SUID/SGID --
// VANGUARD Mega Expansion, Phase 1; Process Anomaly Detection, System
// Binary Integrity, and Process->File->Network Correlation -- Phase 2)
// into the same Incident pipeline every log-driven rule in engine.go
// already uses.
//
// hostsec scanners are NOT log-event-driven (see events.go's doc comment
// on EventKind): they are periodic, host-wide filesystem/proc scans with
// no natural per-request dispatch point, so rather than forcing them
// through handleEvent's per-Event switch, the Engine instead implements
// hostsec.Reporter directly and each scanner calls ReportHostFinding
// whenever a scan tick detects a real change. This still funnels through
// the exact same createIncident() choke point as every other rule, so
// host-security incidents get identical risk scoring, dedupe, dashboard
// visibility, and Autopilot notification with zero duplicated logic --
// satisfying the mega-prompt's "never create duplicate detection
// engines" rule.
package detection

import (
	"time"

	"vanguard/core/internal/database"
	"vanguard/core/internal/hostsec"
	"vanguard/core/internal/risk"
	"vanguard/core/internal/thresholds"
)

// ReportHostFinding implements hostsec.Reporter. Every host-security
// finding is scored and persisted as an Incident with
// SourceIP = database.HostLocalIP (see that constant's doc comment for
// the full rationale: there is no attacker IP to attribute a local
// file/process change to, and 127.0.0.1 is unconditionally whitelisted so
// this can never trigger an accidental self-ban).
func (e *Engine) ReportHostFinding(f hostsec.Finding) {
	now := time.Now().UTC()

	// Feature 7 feed-in, part 1: every FIM (Feature 1) and System Binary
	// Integrity (Feature 8) finding is "Sensitive File Activity" evidence
	// for the correlator, regardless of whether dedupe below ends up
	// suppressing its own standalone incident -- the underlying fact
	// (a sensitive/binary file changed just now) is still real and still
	// corroborating evidence for a concurrent Suspicious Process finding.
	if f.Type == database.IncidentFIMChange || f.Type == database.IncidentSystemBinaryIntegrity {
		e.hostCor.RecordFileFinding(now, thresholds.HostCorrelationWindow)
	}

	if !e.dedupe.allow(database.HostLocalIP+"|"+f.Subject, f.Type) {
		return
	}

	breakdown := risk.Score(risk.Input{
		Type:                f.Type,
		EventCount:          1,
		Threshold:           0,
		RecentIncidentCount: e.recentCount(database.HostLocalIP),
		ThreatIntelHit:      false, // host-local findings have no IP to check against threat intel
		Escalate:            f.Critical,
		EscalationNote:      f.EscalationNote,
	})

	ev := &Event{
		Kind:      EventHostSecurityFinding,
		SourceIP:  database.HostLocalIP,
		Timestamp: now,
		RawLine:   f.Subject,
	}

	extra := map[string]any{
		"change":      f.Change,
		"subject":     f.Subject,
		"best_effort": f.BestEffort,
	}
	for k, v := range f.Details {
		extra[k] = v
	}

	e.createIncident(f.Type, ev, 1, breakdown, extra)

	// Feature 7, part 2: a Suspicious Process finding is the trigger that
	// may complete a Process -> File -> Network correlation. Evaluated
	// AFTER the standalone incident above is created (order matters: the
	// correlated HIGH_CONFIDENCE_COMPROMISE incident is deliberately
	// additional/stronger evidence layered on top of, not a replacement
	// for, the underlying Suspicious Process incident).
	if f.Type == database.IncidentSuspiciousProcess {
		e.correlateHostFinding(f, ev, now)
	}
}

// correlateHostFinding implements Feature 7 (Process -> File -> Network
// Correlation): it combines the just-reported Suspicious Process finding
// with (a) any recent Sensitive File Activity (Feature 1/8 findings
// within thresholds.HostCorrelationWindow, tracked by e.hostCor) and/or
// (b) a Threat Intelligence hit on any of the finding's discovered
// outbound RemoteAddrs, and -- only when at least one of those two
// corroborating signals is present -- raises a single
// IncidentHighConfidenceCompromise on top of the standalone finding
// already persisted by the caller.
//
// This is intentionally conservative: a Suspicious Process finding with
// NEITHER recent file activity NOR a malicious-reputation outbound
// connection stays exactly what it already is (a standalone
// IncidentSuspiciousProcess) -- correlation only fires when the
// mega-prompt's own worked example condition is actually met ("suspicious
// process -> accesses sensitive file -> creates network connection ->
// destination has malicious reputation"), not merely "a process looked
// odd".
func (e *Engine) correlateHostFinding(f hostsec.Finding, ev *Event, now time.Time) {
	recentFileCount := e.hostCor.RecentFileFindingCount(now, thresholds.HostCorrelationWindow)

	var maliciousAddr string
	for _, addr := range f.RemoteAddrs {
		ip, _, ok := splitHostPort(addr)
		if !ok {
			continue
		}
		if e.intel.IsMalicious(ip) {
			maliciousAddr = addr
			break
		}
	}

	if recentFileCount == 0 && maliciousAddr == "" {
		return // no corroborating evidence yet -- stays a standalone Suspicious Process incident
	}

	if !e.dedupe.allow(database.HostLocalIP+"|hcc:"+f.Subject, database.IncidentHighConfidenceCompromise) {
		return
	}

	breakdown := risk.Score(risk.Input{
		Type:                database.IncidentHighConfidenceCompromise,
		EventCount:          1,
		Threshold:           0,
		RecentIncidentCount: e.recentCount(database.HostLocalIP),
		ThreatIntelHit:      maliciousAddr != "",
		Escalate:            true,
		EscalationNote:      "correlated process + file/network evidence of active compromise",
	})

	e.createIncident(database.IncidentHighConfidenceCompromise, ev, 1, breakdown, map[string]any{
		"change":                               "process_file_network_correlation",
		"triggering_process_change":            f.Change,
		"triggering_process":                   f.Subject,
		"remote_addrs":                         f.RemoteAddrs,
		"malicious_remote_addr":                maliciousAddr,
		"recent_sensitive_file_activity_count": recentFileCount,
		"correlation_window_seconds":           int(thresholds.HostCorrelationWindow.Seconds()),
		"note":                                 "Suspicious Process finding corroborated by recent FIM/Binary-Integrity activity and/or a threat-intel hit on a discovered outbound connection",
	})
}

// splitHostPort splits an "ip:port" string (as produced by
// hostsec.ProcessInfo.RemoteAddrs) into its ip component. Deliberately
// tiny/local rather than using net.SplitHostPort, since these addresses
// are always produced internally by hostsec's own decodeHexAddr (IPv4
// dotted-quad, never a bracketed IPv6 literal) and a hand-rolled last-colon
// split avoids importing net into this file for one call site.
func splitHostPort(addr string) (ip string, port string, ok bool) {
	i := lastIndexByte(addr, ':')
	if i < 0 {
		return "", "", false
	}
	return addr[:i], addr[i+1:], true
}

func lastIndexByte(s string, b byte) int {
	for i := len(s) - 1; i >= 0; i-- {
		if s[i] == b {
			return i
		}
	}
	return -1
}
