package investigate

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"vanguard/core/internal/database"
	"vanguard/core/internal/redact"
)

// Export format identity.
const (
	ExportFormat     = "vanguard-investigation"
	ExportVersion    = 1
	MaxExportBytes   = 2 * 1024 * 1024
	maxExportEntries = 2000
)

// Export is the documented JSON shape of a single-incident investigation.
type Export struct {
	Format     string `json:"format"`
	Version    int    `json:"version"`
	ExportedAt string `json:"exported_at"`
	// Disclaimer is part of the document on purpose: this file is a
	// convenience copy with secrets masked, not signed evidence.
	Disclaimer string         `json:"disclaimer"`
	Incident   map[string]any `json:"incident"`
	Timeline   []Entry        `json:"timeline"`
	Graph      *Graph         `json:"relationships"`
	Notes      []NoteOut      `json:"analyst_notes"`
	DataGaps   []string       `json:"data_gaps"`
	Truncated  bool           `json:"truncated"`
}

// NoteOut is an analyst note as exported (text redacted).
type NoteOut struct {
	ID        uint   `json:"id"`
	Author    string `json:"author"`
	Text      string `json:"text"`
	CreatedAt string `json:"created_at"`
	Edited    bool   `json:"edited"`
}

const exportDisclaimer = "Local export from VANGUARD. Secrets are masked heuristically and may be incomplete. " +
	"It is not cryptographically signed or tamper-evident and is not proof of authenticity or of compromise. " +
	"Analyst notes are human statements, kept separate from detector evidence."

// BuildExport assembles the export for one incident and serializes it
// within MaxExportBytes. Ordering is deterministic. The returned bytes are
// the exact document (indented JSON).
func BuildExport(db *database.DB, inc *database.Incident, now time.Time) ([]byte, *Export, error) {
	tl, err := BuildTimeline(db, inc, 0, MaxTimelinePage)
	if err != nil {
		return nil, nil, err
	}
	// Collect every timeline page up to the export entry cap.
	entries := append([]Entry(nil), tl.Entries...)
	for len(entries) < tl.Total && len(entries) < maxExportEntries {
		next, err := BuildTimeline(db, inc, len(entries), MaxTimelinePage)
		if err != nil {
			return nil, nil, err
		}
		if len(next.Entries) == 0 {
			break
		}
		entries = append(entries, next.Entries...)
	}
	gaps := append([]string(nil), tl.DataGaps...)
	truncated := false
	if len(entries) < tl.Total {
		truncated = true
		gaps = append(gaps, fmt.Sprintf("Export holds the first %d of %d timeline entries.", len(entries), tl.Total))
	}

	g, err := BuildGraph(db, inc)
	if err != nil {
		return nil, nil, err
	}
	notes, err := db.ListIncidentNotes(inc.ID)
	if err != nil {
		return nil, nil, err
	}

	ex := &Export{
		Format: ExportFormat, Version: ExportVersion, ExportedAt: now.UTC().Format(time.RFC3339),
		Disclaimer: exportDisclaimer, Incident: incidentMap(inc), Graph: g, DataGaps: gaps, Truncated: truncated,
	}
	for _, e := range entries {
		e.Summary = redact.Text(e.Summary)
		if e.Detail != nil {
			if d, ok := redact.Value(e.Detail).(map[string]any); ok {
				e.Detail = d
			}
		}
		ex.Timeline = append(ex.Timeline, e)
	}
	if ex.Timeline == nil {
		ex.Timeline = []Entry{}
	}
	ex.Notes = []NoteOut{}
	for _, n := range notes {
		ex.Notes = append(ex.Notes, NoteOut{ID: n.ID, Author: n.Author, Text: redact.Text(n.Text), CreatedAt: n.CreatedAt.UTC().Format(time.RFC3339), Edited: n.EditedAt != nil})
	}

	b, err := json.MarshalIndent(ex, "", "  ")
	if err != nil {
		return nil, nil, err
	}
	// Redaction bounds very long text values; say so rather than letting a
	// shortened value pass as the original.
	if strings.Contains(string(b), "...(truncated)") {
		ex.Truncated = true
		ex.DataGaps = append(ex.DataGaps, "Some very long text values were truncated during redaction (limit 64 KiB per value).")
		b, _ = json.MarshalIndent(ex, "", "  ")
	}
	// Size enforcement: shed detail first, then entries, deterministically.
	if len(b) > MaxExportBytes {
		ex.Truncated = true
		ex.DataGaps = append(ex.DataGaps, "Export exceeded the size limit: per-entry detail was dropped.")
		for i := range ex.Timeline {
			ex.Timeline[i].Detail = nil
		}
		b, _ = json.MarshalIndent(ex, "", "  ")
	}
	for len(b) > MaxExportBytes && len(ex.Timeline) > 1 {
		ex.Timeline = ex.Timeline[:len(ex.Timeline)/2]
		ex.DataGaps = append(ex.DataGaps, fmt.Sprintf("Export exceeded the size limit: timeline cut to the first %d entries.", len(ex.Timeline)))
		b, _ = json.MarshalIndent(ex, "", "  ")
	}
	if len(b) > MaxExportBytes { // pathological incident evidence
		ex.Incident["metadata"] = map[string]any{"omitted": "evidence too large for export"}
		ex.Notes = ex.Notes[:0]
		b, _ = json.MarshalIndent(ex, "", "  ")
	}
	return b, ex, nil
}

// incidentMap renders the incident with its metadata parsed and redacted.
func incidentMap(inc *database.Incident) map[string]any {
	m := map[string]any{
		"id": inc.ID, "type": string(inc.Type), "source_ip": inc.SourceIP, "severity": string(inc.Severity),
		"risk_score": inc.RiskScore, "status": string(inc.Status), "attempt_count": inc.AttemptCount,
		"detected_at": inc.DetectedAt.UTC().Format(time.RFC3339),
	}
	if inc.ResolvedAt != nil {
		m["resolved_at"] = inc.ResolvedAt.UTC().Format(time.RFC3339)
	}
	if inc.Metadata != "" {
		var parsed any
		if err := json.Unmarshal([]byte(inc.Metadata), &parsed); err == nil {
			m["metadata"] = redact.Value(parsed)
		} else {
			m["metadata"] = redact.Text(inc.Metadata)
		}
	}
	return m
}
