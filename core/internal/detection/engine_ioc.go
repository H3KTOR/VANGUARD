package detection

// Phase 6: IOC (threat-indicator) matching integrated with the single
// createIncident() choke point.
//
// What is matched, and where it actually comes from:
//
//	source_ip   Event.SourceIP of every log-driven event (auth.log, access
//	            log, honeypot, port touch)
//	host        Event.Host -- ONLY when the access-log format records it
//	url         Event.Host + Event.Path -- same restriction
//	sha256      hashes VANGUARD itself computed for FIM / binary-integrity /
//	            config-drift findings (hostsec.Finding.SHA256)
//	remote_addr outbound addresses attached to process findings
//
// Matching is exact (see internal/intel). A match is a direct observation
// that a locally imported feed lists the value -- not evidence that the
// host is compromised, and never an attribution of the actor.

import (
	"fmt"
	"log"
	"time"

	"vanguard/core/internal/database"
	intelpkg "vanguard/core/internal/intel"
	"vanguard/core/internal/risk"
	"vanguard/core/internal/thresholds"
)

// IOCMatcher is the matching surface the engine needs (implemented by
// *intel.Matcher).
type IOCMatcher interface {
	MatchIP(raw string) []intelpkg.Ref
	MatchHost(host string) []intelpkg.Ref
	MatchURL(host, target string) []intelpkg.Ref
	MatchSHA256(hex string) []intelpkg.Ref
}

// maxEnrichmentRefs bounds how many indicators are attached to one
// unrelated incident's evidence.
const maxEnrichmentRefs = 5

// iocConfidenceAdjust: graded by what the SOURCE asserted. Unrated gets no
// adjustment; low is discounted.
func iocConfidenceAdjust(c database.IOCConfidence) int {
	switch c {
	case database.IOCConfidenceHigh:
		return 10
	case database.IOCConfidenceMedium:
		return 5
	case database.IOCConfidenceLow:
		return -10
	}
	return 0
}

// scoreIOC scores a standalone IOC match: base severity + confidence
// adjustment, clamped to thresholds.MaxIOCOnlyRisk so an indicator match
// alone can never reach the default auto-response threshold. No
// repeat-offender or reputation components are added (the match IS the
// reputation signal; counting it twice would inflate the score).
func scoreIOC(ref intelpkg.Ref) risk.Breakdown {
	b := risk.Score(risk.Input{
		Type:          database.IncidentIOCMatch,
		EventCount:    1,
		ContextAdjust: iocConfidenceAdjust(ref.Confidence),
	})
	if b.Total > thresholds.MaxIOCOnlyRisk {
		b.Total = thresholds.MaxIOCOnlyRisk
		b.Explanation += fmt.Sprintf(" [clamped to the IOC-only cap %d: an indicator match alone never reaches auto-response]", thresholds.MaxIOCOnlyRisk)
	}
	return b
}

func iocSummary(r intelpkg.Ref) map[string]any {
	m := map[string]any{
		"id": r.ID, "type": r.Type, "source": r.Source,
		"confidence_from_source": string(r.Confidence), // "" = source supplied none
	}
	if r.Description != "" {
		m["description"] = r.Description
	}
	if r.Reference != "" {
		m["reference"] = r.Reference // inert text, never fetched
	}
	if r.ExpiresAt != nil {
		m["expires_at"] = r.ExpiresAt.UTC().Format(time.RFC3339)
	}
	return m
}

// checkIOC runs the exact-match checks that apply to a log-driven event.
func (e *Engine) checkIOC(ev *Event) {
	if e.ioc == nil {
		return
	}
	for _, r := range e.ioc.MatchIP(ev.SourceIP) {
		e.raiseIOC(r, "source_ip", r.Value, ev)
	}
	if ev.Kind != EventHTTPRequest {
		return
	}
	for _, r := range e.ioc.MatchHost(ev.Host) {
		e.raiseIOC(r, "host", r.Value, ev)
	}
	for _, r := range e.ioc.MatchURL(ev.Host, ev.Path) {
		e.raiseIOC(r, "url", r.Value, ev)
	}
}

// raiseIOC creates (at most once per cooldown per indicator+actor+field)
// an ioc_match incident for one direct match.
func (e *Engine) raiseIOC(ref intelpkg.Ref, field, matched string, ev *Event) {
	if !e.iocDedupe.allow(fmt.Sprintf("%s|ioc%d|%s", ev.SourceIP, ref.ID, field), database.IncidentIOCMatch) {
		return
	}
	obs := map[string]any{
		"event_kind":  string(ev.Kind),
		"source_ip":   ev.SourceIP,
		"observed_at": ev.Timestamp.UTC().Format(time.RFC3339),
	}
	// Deliberately NOT copied: raw log line, query string, user agent,
	// headers or cookies -- they can carry credentials or tokens.
	if ev.Kind == EventHTTPRequest {
		obs["method"], obs["status"] = ev.Method, ev.StatusCode
		if ev.Host != "" {
			obs["host"] = ev.Host
		}
	}
	inc := e.createIncident(database.IncidentIOCMatch, ev, 1, scoreIOC(ref), map[string]any{
		"match_kind":    "direct",
		"matched_field": field,
		"matched_value": matched,
		"ioc":           iocSummary(ref),
		"observation":   obs,
	})
	e.recordIOCMatch(ref, field, matched, ev, "direct", inc)
}

// recordIOCMatch persists the bounded match record used by threat hunting.
func (e *Engine) recordIOCMatch(ref intelpkg.Ref, field, matched string, ev *Event, kind string, inc *database.Incident) {
	if e.db == nil {
		return
	}
	m := &database.IOCMatch{
		IOCID: ref.ID, IOCType: ref.Type, Source: ref.Source, Field: field, Context: matched,
		SourceIP: ev.SourceIP, EventKind: string(ev.Kind), Kind: kind, MatchedAt: ev.Timestamp.UTC(),
	}
	if inc != nil {
		m.IncidentID = inc.ID
	}
	if err := e.db.RecordIOCMatch(m); err != nil {
		// Hunting history is best-effort; detection must not depend on it.
		logIOCErr(err)
	}
}

// enrichWithIOC adds matching-indicator context to an UNRELATED detector's
// incident evidence (same actor address). It is enrichment only: it does
// not change the incident's score and does not claim causation.
func (e *Engine) enrichWithIOC(ev *Event, meta map[string]any) []intelpkg.Ref {
	if e.ioc == nil || ev.SourceIP == "" || ev.SourceIP == database.HostLocalIP {
		return nil
	}
	refs := e.ioc.MatchIP(ev.SourceIP)
	if len(refs) == 0 {
		return nil
	}
	if len(refs) > maxEnrichmentRefs {
		refs = refs[:maxEnrichmentRefs]
	}
	list := make([]map[string]any, 0, len(refs))
	for _, r := range refs {
		list = append(list, iocSummary(r))
	}
	meta["ioc_matches"] = list
	meta["ioc_matches_note"] = "the source address is listed by the local indicator(s) above (exact match); this is context, not proof of intent or attribution"
	return refs
}

// checkHostIOC matches hashes and remote addresses attached to a host
// security finding.
func (e *Engine) checkHostIOC(sha256s, remoteAddrs []string, subject string, now time.Time) {
	if e.ioc == nil {
		return
	}
	ev := &Event{Kind: EventHostSecurityFinding, SourceIP: database.HostLocalIP, Timestamp: now, RawLine: subject}
	for _, h := range sha256s {
		for _, r := range e.ioc.MatchSHA256(h) {
			e.raiseHostIOC(r, "sha256", r.Value, subject, ev)
		}
	}
	for _, a := range remoteAddrs {
		ip, _, ok := splitHostPort(a)
		if !ok {
			continue
		}
		for _, r := range e.ioc.MatchIP(ip) {
			e.raiseHostIOC(r, "remote_addr", r.Value, subject, ev)
		}
	}
}

func (e *Engine) raiseHostIOC(ref intelpkg.Ref, field, matched, subject string, ev *Event) {
	if !e.iocDedupe.allow(fmt.Sprintf("host|ioc%d|%s|%s", ref.ID, field, subject), database.IncidentIOCMatch) {
		return
	}
	inc := e.createIncident(database.IncidentIOCMatch, ev, 1, scoreIOC(ref), map[string]any{
		"match_kind":    "direct",
		"matched_field": field,
		"matched_value": matched,
		"ioc":           iocSummary(ref),
		"observation": map[string]any{
			"event_kind":  string(ev.Kind),
			"subject":     subject,
			"observed_at": ev.Timestamp.UTC().Format(time.RFC3339),
		},
	})
	e.recordIOCMatch(ref, field, matched, ev, "direct", inc)
}

// enrichIfApplicable enriches an unrelated detector's incident (never an
// ioc_match incident itself).
func (e *Engine) enrichIfApplicable(itype database.IncidentType, ev *Event, meta map[string]any) []intelpkg.Ref {
	if itype == database.IncidentIOCMatch {
		return nil
	}
	return e.enrichWithIOC(ev, meta)
}

// recordEnrichment stores the hunting rows for an enriched incident.
func (e *Engine) recordEnrichment(refs []intelpkg.Ref, ev *Event, inc *database.Incident) {
	for _, r := range refs {
		e.recordIOCMatch(r, "source_ip", r.Value, ev, "enrichment", inc)
	}
}

func logIOCErr(err error) {
	log.Printf("[detection] failed to record IOC match history: %v", err)
}
