// Package investigate builds analyst-facing views (timeline, relationship
// list, bounded incident queries, export) from records VANGUARD actually
// persisted. Nothing here invents an event: if something was never stored
// it is reported as a data gap instead.
package investigate

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"vanguard/core/internal/database"
)

// Provenance of a timeline entry.
const (
	ProvObserved   = "observed"   // directly observed by a detector at detection time
	ProvDerived    = "derived"    // context attached afterwards (e.g. indicator enrichment)
	ProvCorrelated = "correlated" // inferred by combining several observations
	ProvAnalyst    = "analyst"    // an analyst's action or note
	ProvResponse   = "response"   // an automated/manual response action or its verification
)

// Entry is one timeline row.
type Entry struct {
	At         time.Time      `json:"at"` // always UTC (RFC 3339)
	Source     string         `json:"source"`
	Ref        string         `json:"ref"` // "<table>#<id>"
	Kind       string         `json:"kind"`
	Provenance string         `json:"provenance"`
	Summary    string         `json:"summary"`
	Detail     map[string]any `json:"detail,omitempty"`

	rank  int
	refID uint
}

// Timeline is the merged view plus honesty metadata.
type Timeline struct {
	IncidentID uint    `json:"incident_id"`
	Total      int     `json:"total"`
	Offset     int     `json:"offset"`
	Limit      int     `json:"limit"`
	Entries    []Entry `json:"entries"`
	// DataGaps lists what this timeline cannot contain and why.
	DataGaps []string `json:"data_gaps"`
}

const (
	MaxTimelinePage = 200
	perSourceCap    = 200
)

func isSystemActor(a string) bool {
	switch a {
	case "system", "autopilot", "simulator", "":
		return true
	}
	return false
}

// BuildTimeline merges the incident's persisted records into one ordered
// list. Ordering: time ascending, then a fixed source rank, then record
// id -- fully deterministic.
func BuildTimeline(db *database.DB, inc *database.Incident, offset, limit int) (*Timeline, error) {
	if limit <= 0 || limit > MaxTimelinePage {
		limit = 100
	}
	if offset < 0 {
		offset = 0
	}
	var meta map[string]any
	if inc.Metadata != "" {
		_ = json.Unmarshal([]byte(inc.Metadata), &meta) // legacy/odd metadata => nil, handled below
	}

	var entries []Entry
	var gaps []string
	capHit := func(what string) {
		gaps = append(gaps, fmt.Sprintf("Only the first %d %s are shown (retention/page cap); older or further records exist.", perSourceCap, what))
	}

	// 1. The detection itself.
	prov := ProvObserved
	if database.IsCorrelatedType(inc.Type) {
		prov = ProvCorrelated
	}
	det := map[string]any{"rule_id": string(inc.Type), "severity": string(inc.Severity), "risk_score": inc.RiskScore, "attempt_count": inc.AttemptCount}
	if p, ok := meta["provenance"].(map[string]any); ok {
		if k, ok := p["evidence_kind"].(string); ok {
			det["evidence_kind"] = k
		}
		if l, ok := p["limitations"].(string); ok && l != "" {
			gaps = append(gaps, "Detector limitation: "+l)
		}
	} else {
		gaps = append(gaps, "This incident predates evidence provenance; its detector limitations are not recorded.")
	}
	entries = append(entries, Entry{
		At: inc.DetectedAt.UTC(), Source: "detector", Ref: fmt.Sprintf("incidents#%d", inc.ID), Kind: "detection",
		Provenance: prov, rank: 0, refID: inc.ID,
		Summary: fmt.Sprintf("Detector %s raised this incident (risk %d, %s)", inc.Type, inc.RiskScore, inc.Severity),
		Detail:  det,
	})

	// 2. Indicator matches recorded for this incident.
	var matches []database.IOCMatch
	if err := db.Where("incident_id = ?", inc.ID).Order("matched_at ASC, id ASC").Limit(perSourceCap + 1).Find(&matches).Error; err != nil {
		return nil, err
	}
	if len(matches) > perSourceCap {
		matches = matches[:perSourceCap]
		capHit("indicator matches")
	}
	for _, m := range matches {
		p, kindText := ProvObserved, "direct match"
		if m.Kind == "enrichment" {
			p, kindText = ProvDerived, "context only: the source address is listed; another detector raised this incident"
		}
		entries = append(entries, Entry{
			At: m.MatchedAt.UTC(), Source: "threat_intel", Ref: fmt.Sprintf("ioc_matches#%d", m.ID), Kind: "ioc_match",
			Provenance: p, rank: 1, refID: m.ID,
			Summary: fmt.Sprintf("%s indicator %q (source %q) exactly matched %s — %s", m.IOCType, m.Context, m.Source, m.Field, kindText),
			Detail:  map[string]any{"ioc_id": m.IOCID, "match_kind": m.Kind, "field": m.Field},
		})
	}

	// 3. Lifecycle / response / verification / note audit events.
	var evs []database.IncidentEvent
	if err := db.Where("incident_id = ?", inc.ID).Order("id ASC").Limit(perSourceCap + 1).Find(&evs).Error; err != nil {
		return nil, err
	}
	if len(evs) > perSourceCap {
		evs = evs[:perSourceCap]
		capHit("audit events")
	}
	for _, e := range evs {
		en := Entry{At: e.At.UTC(), Source: "incident_events", Ref: fmt.Sprintf("incident_events#%d", e.ID), Kind: e.Kind, refID: e.ID}
		switch e.Kind {
		case database.EventStatusChange:
			en.rank = 4
			en.Provenance = ProvAnalyst
			if isSystemActor(e.Actor) || e.Actor == "autopilot" {
				en.Provenance = ProvResponse
			}
			en.Summary = fmt.Sprintf("Status %s → %s by %s", e.FromStatus, e.ToStatus, orUnknown(e.Actor))
		case database.EventResponse:
			en.rank, en.Provenance = 2, ProvResponse
			en.Summary = fmt.Sprintf("Response %s", e.Outcome)
		case database.EventVerification:
			en.rank, en.Provenance = 3, ProvResponse
			en.Summary = fmt.Sprintf("Verification %s", e.Outcome)
		case database.EventNote:
			en.rank, en.Provenance = 5, ProvAnalyst
			en.Summary = fmt.Sprintf("Note %s by %s", e.Outcome, orUnknown(e.Actor))
		default:
			en.rank, en.Provenance = 6, ProvDerived
			en.Summary = e.Kind
		}
		en.Detail = map[string]any{"outcome": e.Outcome, "actor": e.Actor}
		if e.Detail != "" {
			en.Detail["detail"] = e.Detail
		}
		entries = append(entries, en)
	}

	// 4. Firewall rules created for this incident.
	rules, err := db.ListFirewallRulesForIncident(inc.ID, 50)
	if err != nil {
		return nil, err
	}
	for _, r := range rules {
		d := map[string]any{"rule_id": r.ID, "source": string(r.Source), "active_now": r.IsActive}
		if r.UnbanAt != nil {
			d["scheduled_expiry"] = r.UnbanAt.UTC().Format(time.RFC3339)
		}
		entries = append(entries, Entry{
			At: r.BannedAt.UTC(), Source: "firewall", Ref: fmt.Sprintf("firewall_rules#%d", r.ID), Kind: "ban_rule",
			Provenance: ProvResponse, rank: 2, refID: r.ID,
			Summary: fmt.Sprintf("Ban rule recorded for %s (%s); expiry is scheduled, not an observed event", r.IPAddress, r.Source),
			Detail:  d,
		})
	}

	// 5. Analyst notes.
	notes, err := db.ListIncidentNotes(inc.ID)
	if err != nil {
		return nil, err
	}
	for _, n := range notes {
		entries = append(entries, Entry{
			At: n.CreatedAt.UTC(), Source: "analyst_notes", Ref: fmt.Sprintf("incident_notes#%d", n.ID), Kind: "note",
			Provenance: ProvAnalyst, rank: 5, refID: n.ID,
			Summary: fmt.Sprintf("Note by %s", n.Author),
			Detail:  map[string]any{"text": n.Text, "edited": n.EditedAt != nil},
		})
	}

	sort.SliceStable(entries, func(i, j int) bool {
		a, b := entries[i], entries[j]
		if !a.At.Equal(b.At) {
			return a.At.Before(b.At)
		}
		if a.rank != b.rank {
			return a.rank < b.rank
		}
		if a.Source != b.Source {
			return a.Source < b.Source
		}
		return a.refID < b.refID
	})

	// Standing gaps (always true for this product).
	gaps = append(gaps,
		"Raw events and log lines are not retained: only the records listed here were persisted.",
		"Scanner-health history is not persisted; only the current scanner state is available (/api/detectors/status).",
	)
	if database.IsCorrelatedType(inc.Type) {
		gaps = append(gaps, "This incident is a correlation: its constituent observations are summarized by counts in its evidence and were not stored as separate references.")
	}
	if inc.SourceIP == database.HostLocalIP {
		gaps = append(gaps, "Host-local finding: there is no remote actor; the 127.0.0.1 source is a sentinel.")
	}
	if !hasKind(entries, "ioc_match") && !hasKind(entries, database.EventResponse) {
		gaps = append(gaps, "No indicator match or response action was recorded for this incident (this is the absence of a retained record, not proof that none occurred).")
	}

	total := len(entries)
	end := offset + limit
	if offset > total {
		offset = total
	}
	if end > total {
		end = total
	}
	return &Timeline{IncidentID: inc.ID, Total: total, Offset: offset, Limit: limit, Entries: entries[offset:end], DataGaps: gaps}, nil
}

func hasKind(es []Entry, k string) bool {
	for _, e := range es {
		if e.Kind == k {
			return true
		}
	}
	return false
}

func orUnknown(s string) string {
	if strings.TrimSpace(s) == "" {
		return "unknown"
	}
	return s
}
