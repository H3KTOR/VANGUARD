package investigate

import (
	"time"

	"vanguard/core/internal/database"
)

// Query limits.
const (
	MaxQueryLimit  = 200
	MaxQueryOffset = 10000
	// DefaultWindow bounds a query that gives no other scoping filter.
	DefaultWindow = 30 * 24 * time.Hour
)

// Filter is a validated incident query. Callers (the API) validate input
// into this struct; Query only ever binds values as SQL parameters.
type Filter struct {
	ID                  uint
	Rule                database.IncidentType
	Status              database.IncidentStatus
	Severity            database.Severity
	RiskMin, RiskMax    *int
	Since, Until        time.Time
	SourceIP            string
	IOCID               uint
	HasIOCMatch         *bool
	EvidenceKind        string // "observed" | "correlated" | ""
	ResponseOutcome     string // outcome label of a response event
	VerificationOutcome string // outcome label of a verification event
	Limit, Offset       int
}

// Result carries rows and the honesty metadata.
type Result struct {
	Incidents       []database.Incident `json:"incidents"`
	Count           int                 `json:"count"`
	Limit           int                 `json:"limit"`
	Offset          int                 `json:"offset"`
	WindowDefaulted bool                `json:"window_defaulted"`
	Since           *time.Time          `json:"since,omitempty"`
	RetentionNotes  []string            `json:"retention_notes"`
}

// Query runs the bounded, parameterized investigation query.
func Query(db *database.DB, f Filter, now time.Time) (*Result, error) {
	limit := f.Limit
	if limit <= 0 || limit > MaxQueryLimit {
		limit = 50
	}
	offset := f.Offset
	if offset < 0 {
		offset = 0
	}
	if offset > MaxQueryOffset {
		offset = MaxQueryOffset
	}

	res := &Result{Limit: limit, Offset: offset, RetentionNotes: []string{
		"Results cover persisted incidents only. Raw events are not retained, so an empty page means no retained incident matched, not that nothing happened.",
		"Indicator-match filters apply to the bounded match history (30 days / 100000 rows).",
		"Scanner failures are reported live by /api/detectors/status; their history is not persisted and cannot be queried.",
	}}

	q := db.Model(&database.Incident{})
	scoped := f.ID != 0 || f.SourceIP != "" || f.IOCID != 0 || !f.Since.IsZero() || !f.Until.IsZero()
	since := f.Since
	if !scoped {
		since = now.Add(-DefaultWindow)
		res.WindowDefaulted = true
	}
	if !since.IsZero() {
		s := since.UTC()
		res.Since = &s
		q = q.Where("detected_at >= ?", s)
	}
	if !f.Until.IsZero() {
		q = q.Where("detected_at < ?", f.Until.UTC())
	}
	if f.ID != 0 {
		q = q.Where("id = ?", f.ID)
	}
	if f.Rule != "" {
		q = q.Where("type = ?", f.Rule)
	}
	if f.Status != "" {
		q = q.Where("status = ?", f.Status)
	}
	if f.Severity != "" {
		q = q.Where("severity = ?", f.Severity)
	}
	if f.RiskMin != nil {
		q = q.Where("risk_score >= ?", *f.RiskMin)
	}
	if f.RiskMax != nil {
		q = q.Where("risk_score <= ?", *f.RiskMax)
	}
	if f.SourceIP != "" {
		q = q.Where("source_ip = ?", f.SourceIP)
	}
	if f.IOCID != 0 {
		q = q.Where("EXISTS (SELECT 1 FROM ioc_matches m WHERE m.incident_id = incidents.id AND m.ioc_id = ?)", f.IOCID)
	}
	if f.HasIOCMatch != nil {
		if *f.HasIOCMatch {
			q = q.Where("EXISTS (SELECT 1 FROM ioc_matches m WHERE m.incident_id = incidents.id)")
		} else {
			q = q.Where("NOT EXISTS (SELECT 1 FROM ioc_matches m WHERE m.incident_id = incidents.id)")
		}
	}
	switch f.EvidenceKind {
	case "correlated":
		q = q.Where("type IN ?", database.CorrelatedTypes())
	case "observed":
		q = q.Where("type NOT IN ?", database.CorrelatedTypes())
	}
	if f.ResponseOutcome != "" {
		q = q.Where("EXISTS (SELECT 1 FROM incident_events e WHERE e.incident_id = incidents.id AND e.kind = ? AND e.outcome = ?)", database.EventResponse, f.ResponseOutcome)
	}
	if f.VerificationOutcome != "" {
		q = q.Where("EXISTS (SELECT 1 FROM incident_events e WHERE e.incident_id = incidents.id AND e.kind = ? AND e.outcome = ?)", database.EventVerification, f.VerificationOutcome)
	}

	var rows []database.Incident
	if err := q.Order("detected_at DESC, id DESC").Limit(limit).Offset(offset).Find(&rows).Error; err != nil {
		return nil, err
	}
	if rows == nil {
		rows = []database.Incident{}
	}
	res.Incidents, res.Count = rows, len(rows)
	return res, nil
}
