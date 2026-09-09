// engine_hostsec.go wires internal/hostsec's periodic host-security
// scanners (FIM, Persistence, Account, Privilege Escalation, SUID/SGID --
// VANGUARD Mega Expansion, Phase 1) into the same Incident pipeline every
// log-driven rule in engine.go already uses.
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
)

// ReportHostFinding implements hostsec.Reporter. Every host-security
// finding is scored and persisted as an Incident with
// SourceIP = database.HostLocalIP (see that constant's doc comment for
// the full rationale: there is no attacker IP to attribute a local
// file/process change to, and 127.0.0.1 is unconditionally whitelisted so
// this can never trigger an accidental self-ban).
func (e *Engine) ReportHostFinding(f hostsec.Finding) {
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
		Timestamp: time.Now().UTC(),
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
}
