package database

// Phase 6: local threat-intelligence storage.
//
// Three additive tables: iocs (indicators), ioc_imports (one row per
// import attempt, including rejected ones) and ioc_matches (a bounded
// record of observed matches that the hunting API queries). Values are
// always stored in the normalized form produced by internal/intel.

import (
	"time"

	"gorm.io/gorm"
)

// IOCType enumerates the indicator types VANGUARD can reliably match
// against data it actually observes.
type IOCType string

const (
	IOCIP     IOCType = "ip"
	IOCDomain IOCType = "domain"
	IOCURL    IOCType = "url"
	IOCSHA256 IOCType = "sha256"
)

// IOCConfidence is the confidence the SOURCE assigned to the indicator.
// Empty means the source supplied none ("unrated") -- VANGUARD never
// invents one.
type IOCConfidence string

const (
	IOCConfidenceNone   IOCConfidence = ""
	IOCConfidenceLow    IOCConfidence = "low"
	IOCConfidenceMedium IOCConfidence = "medium"
	IOCConfidenceHigh   IOCConfidence = "high"
)

// Field and table bounds.
const (
	MaxIOCDescriptionLen = 512
	MaxIOCReferenceLen   = 512
	MaxIOCValueLen       = 2048
	MaxIOCSourceLen      = 64
	// MaxIOCMatchRows bounds the ioc_matches table; the oldest rows are
	// pruned past this (and past IOCMatchRetention).
	MaxIOCMatchRows   = 100000
	IOCMatchRetention = 30 * 24 * time.Hour
	// MaxIOCImportRows bounds import history.
	MaxIOCImportRows = 500
)

// IOC is one threat indicator. (Type, Value, Source) is unique: the same
// value from two feeds is two indicators with their own provenance,
// confidence and lifecycle.
type IOC struct {
	ID uint `gorm:"primaryKey" json:"id"`

	Type   IOCType `gorm:"size:16;not null;uniqueIndex:idx_ioc_identity,priority:1;index:idx_ioc_type_value,priority:1" json:"type"`
	Value  string  `gorm:"size:2048;not null;uniqueIndex:idx_ioc_identity,priority:2;index:idx_ioc_type_value,priority:2" json:"value"`
	Source string  `gorm:"size:64;not null;uniqueIndex:idx_ioc_identity,priority:3;index" json:"source"`

	Description string        `gorm:"size:512" json:"description,omitempty"`
	Reference   string        `gorm:"size:512" json:"reference,omitempty"` // inert text, never fetched
	Confidence  IOCConfidence `gorm:"size:16" json:"confidence,omitempty"`

	// SourceCreatedAt is the creation time the feed claimed, if any.
	SourceCreatedAt *time.Time `json:"source_created_at,omitempty"`
	// ExpiresAt nil means "no expiry supplied" -- NOT expired.
	ExpiresAt *time.Time `gorm:"index" json:"expires_at,omitempty"`

	Enabled bool `gorm:"not null;index" json:"enabled"` // no gorm default: a zero (false) must be stored as false
	// DisabledByOperator pins an operator's disable so a re-import cannot
	// silently re-enable an indicator that was judged incorrect.
	DisabledByOperator bool `gorm:"not null;default:false" json:"disabled_by_operator"`

	ImportID uint `gorm:"index" json:"import_id"`

	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// IsActive reports whether the indicator may produce matches at now.
func (i *IOC) IsActive(now time.Time) bool {
	if !i.Enabled {
		return false
	}
	return i.ExpiresAt == nil || now.Before(*i.ExpiresAt)
}

// IOCImport records one import attempt (accepted or rejected) for
// provenance and the dashboard's import summary.
type IOCImport struct {
	ID          uint   `gorm:"primaryKey" json:"id"`
	Source      string `gorm:"size:64;index" json:"source"`
	FormatVer   int    `json:"format_version"`
	Status      string `gorm:"size:16;not null" json:"status"` // applied | rejected
	Error       string `gorm:"size:512" json:"error,omitempty"`
	InputSHA256 string `gorm:"size:64" json:"input_sha256,omitempty"`
	InputBytes  int    `json:"input_bytes"`
	Records     int    `json:"records"`
	Accepted    int    `json:"accepted"`
	Updated     int    `json:"updated"`
	Duplicate   int    `json:"duplicate"`
	Rejected    int    `json:"rejected"`
	Expired     int    `json:"expired"`
	Disabled    int    `json:"disabled"`
	Removed     int    `json:"removed"`
	Replace     bool   `json:"replace_source"`
	Strict      bool   `json:"strict"`
	// RejectSample holds up to a few bounded "line N: reason" strings.
	RejectSample string     `gorm:"type:text" json:"reject_sample,omitempty"`
	GeneratedAt  *time.Time `json:"generated_at,omitempty"`
	CreatedAt    time.Time  `gorm:"index" json:"created_at"`
}

// IOCMatch is one recorded match of an observation against an indicator.
type IOCMatch struct {
	ID         uint      `gorm:"primaryKey" json:"id"`
	IOCID      uint      `gorm:"not null;index:idx_ioc_matches_ioc_time,priority:1" json:"ioc_id"`
	IncidentID uint      `gorm:"index" json:"incident_id"`
	MatchedAt  time.Time `gorm:"not null;index:idx_ioc_matches_ioc_time,priority:2;index" json:"matched_at"`
	IOCType    IOCType   `gorm:"size:16;not null;index" json:"ioc_type"`
	Source     string    `gorm:"size:64" json:"source"`
	Field      string    `gorm:"size:32" json:"field"`           // which observed field matched: source_ip, host, url, sha256, remote_addr
	Context    string    `gorm:"size:256" json:"context"`        // normalized matched value (bounded, no secrets)
	SourceIP   string    `gorm:"size:64;index" json:"source_ip"` // actor address of the observation
	EventKind  string    `gorm:"size:32" json:"event_kind"`
	// Kind: "direct" for an exact observation match; "enrichment" when an
	// unrelated detector's incident merely shares the matching address.
	Kind string `gorm:"size:16;not null" json:"kind"`
}

// ---------------------------------------------------------------------------
// Repository
// ---------------------------------------------------------------------------

// IOCFilter narrows ListIOCs. Zero values are ignored.
type IOCFilter struct {
	Type    IOCType
	Source  string
	Value   string // exact (already normalized) value
	Enabled *bool
	// ActiveAt, when non-zero, keeps only indicators active at that time.
	ActiveAt time.Time
	Limit    int
	Offset   int
}

// ListIOCs returns indicators ordered newest first with a bounded page.
func (db *DB) ListIOCs(f IOCFilter) ([]IOC, error) {
	q := db.Model(&IOC{})
	if f.Type != "" {
		q = q.Where("type = ?", f.Type)
	}
	if f.Source != "" {
		q = q.Where("source = ?", f.Source)
	}
	if f.Value != "" {
		q = q.Where("value = ?", f.Value)
	}
	if f.Enabled != nil {
		q = q.Where("enabled = ?", *f.Enabled)
	}
	if !f.ActiveAt.IsZero() {
		q = q.Where("enabled = ? AND (expires_at IS NULL OR expires_at > ?)", true, f.ActiveAt)
	}
	limit := f.Limit
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	offset := f.Offset
	if offset < 0 {
		offset = 0
	}
	if offset > 100000 {
		offset = 100000
	}
	var out []IOC
	err := q.Order("id DESC").Limit(limit).Offset(offset).Find(&out).Error
	return out, err
}

// GetIOC fetches one indicator.
func (db *DB) GetIOC(id uint) (*IOC, error) {
	var i IOC
	if err := db.First(&i, id).Error; err != nil {
		return nil, err
	}
	return &i, nil
}

// SetIOCEnabled enables/disables an indicator. A disable made here is
// pinned (DisabledByOperator) so a later import cannot re-enable it.
func (db *DB) SetIOCEnabled(id uint, enabled bool) (*IOC, error) {
	res := db.Model(&IOC{}).Where("id = ?", id).Updates(map[string]any{
		"enabled": enabled, "disabled_by_operator": !enabled,
	})
	if res.Error != nil {
		return nil, res.Error
	}
	if res.RowsAffected == 0 {
		return nil, ErrNotFound
	}
	return db.GetIOC(id)
}

// DeleteIOC permanently removes an indicator (its recorded matches stay,
// as historical evidence, referencing the now-absent ID).
func (db *DB) DeleteIOC(id uint) error {
	res := db.Delete(&IOC{}, id)
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return ErrNotFound
	}
	return nil
}

// ActiveIOCs returns up to limit indicators active at now, plus the total
// number active (so callers can report truncation instead of hiding it).
func (db *DB) ActiveIOCs(now time.Time, limit int) (rows []IOC, total int64, err error) {
	q := db.Model(&IOC{}).Where("enabled = ? AND (expires_at IS NULL OR expires_at > ?)", true, now)
	if err = q.Count(&total).Error; err != nil {
		return nil, 0, err
	}
	err = q.Order("id ASC").Limit(limit).Find(&rows).Error
	return rows, total, err
}

// CountIOCs returns total / active counts for status reporting.
func (db *DB) CountIOCs(now time.Time) (total, active int64, err error) {
	if err = db.Model(&IOC{}).Count(&total).Error; err != nil {
		return
	}
	err = db.Model(&IOC{}).Where("enabled = ? AND (expires_at IS NULL OR expires_at > ?)", true, now).Count(&active).Error
	return
}

// RecordIOCMatch stores a match and opportunistically prunes old rows.
func (db *DB) RecordIOCMatch(m *IOCMatch) error {
	if m.MatchedAt.IsZero() {
		m.MatchedAt = time.Now().UTC()
	}
	if len(m.Context) > 256 {
		m.Context = m.Context[:256]
	}
	if err := db.Create(m).Error; err != nil {
		return err
	}
	// Cheap amortized prune: every ~256th row.
	if m.ID%256 == 0 {
		return db.PruneIOCMatches(time.Now().UTC())
	}
	return nil
}

// PruneIOCMatches enforces the age and row-count bounds.
func (db *DB) PruneIOCMatches(now time.Time) error {
	if err := db.Where("matched_at < ?", now.Add(-IOCMatchRetention)).Delete(&IOCMatch{}).Error; err != nil {
		return err
	}
	var n int64
	if err := db.Model(&IOCMatch{}).Count(&n).Error; err != nil {
		return err
	}
	if over := int(n) - MaxIOCMatchRows; over > 0 {
		sub := db.Model(&IOCMatch{}).Select("id").Order("id ASC").Limit(over)
		return db.Where("id IN (?)", sub).Delete(&IOCMatch{}).Error
	}
	return nil
}

// SetMatchIncident links earlier-recorded matches to the incident that
// was created for them.
func (db *DB) SetMatchIncident(matchID, incidentID uint) error {
	return db.Model(&IOCMatch{}).Where("id = ?", matchID).Update("incident_id", incidentID).Error
}

// HuntFilter drives the threat-hunting query. Zero values are ignored.
type HuntFilter struct {
	IOCID          uint
	IOCType        IOCType
	Source         string
	SourceIP       string
	Context        string // exact normalized matched value (domain/url/hash/ip)
	Kind           string // direct | enrichment
	Since, Until   time.Time
	IncidentType   IncidentType
	IncidentStatus IncidentStatus
	Limit, Offset  int
}

// HuntRow is one result: the match plus (when linked) its incident.
type HuntRow struct {
	IOCMatch
	IncidentType   IncidentType   `json:"incident_type,omitempty"`
	IncidentStatus IncidentStatus `json:"incident_status,omitempty"`
	IncidentRisk   int            `json:"incident_risk_score,omitempty"`
}

// HuntMatches runs the bounded, parameterized hunt query. Ordering is
// stable (matched_at DESC, id DESC); limit is capped at 200 and offset at
// 10 000 so an interactive request can never become a full scan.
func (db *DB) HuntMatches(f HuntFilter) ([]HuntRow, error) {
	q := db.Table("ioc_matches AS m").
		Select("m.*, i.type AS incident_type, i.status AS incident_status, i.risk_score AS incident_risk").
		Joins("LEFT JOIN incidents AS i ON i.id = m.incident_id")
	if f.IOCID != 0 {
		q = q.Where("m.ioc_id = ?", f.IOCID)
	}
	if f.IOCType != "" {
		q = q.Where("m.ioc_type = ?", f.IOCType)
	}
	if f.Source != "" {
		q = q.Where("m.source = ?", f.Source)
	}
	if f.SourceIP != "" {
		q = q.Where("m.source_ip = ?", f.SourceIP)
	}
	if f.Context != "" {
		q = q.Where("m.context = ?", f.Context)
	}
	if f.Kind != "" {
		q = q.Where("m.kind = ?", f.Kind)
	}
	if !f.Since.IsZero() {
		q = q.Where("m.matched_at >= ?", f.Since)
	}
	if !f.Until.IsZero() {
		q = q.Where("m.matched_at < ?", f.Until)
	}
	if f.IncidentType != "" {
		q = q.Where("i.type = ?", f.IncidentType)
	}
	if f.IncidentStatus != "" {
		q = q.Where("i.status = ?", f.IncidentStatus)
	}
	limit := f.Limit
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	offset := f.Offset
	if offset < 0 {
		offset = 0
	}
	if offset > 10000 {
		offset = 10000
	}
	var rows []HuntRow
	err := q.Order("m.matched_at DESC, m.id DESC").Limit(limit).Offset(offset).Scan(&rows).Error
	return rows, err
}

// ListIOCImports returns the most recent import attempts.
func (db *DB) ListIOCImports(limit int) ([]IOCImport, error) {
	if limit <= 0 || limit > MaxIOCImportRows {
		limit = 50
	}
	var out []IOCImport
	err := db.Order("id DESC").Limit(limit).Find(&out).Error
	return out, err
}

// pruneIOCImports keeps import history bounded.
func pruneIOCImports(tx *gorm.DB) error {
	var n int64
	if err := tx.Model(&IOCImport{}).Count(&n).Error; err != nil {
		return err
	}
	if over := int(n) - MaxIOCImportRows; over > 0 {
		sub := tx.Model(&IOCImport{}).Select("id").Order("id ASC").Limit(over)
		return tx.Where("id IN (?)", sub).Delete(&IOCImport{}).Error
	}
	return nil
}

// RecordIOCImport persists an import attempt row (used for rejected
// imports; applied imports are written inside the import transaction).
func (db *DB) RecordIOCImport(imp *IOCImport) error {
	return db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Create(imp).Error; err != nil {
			return err
		}
		return pruneIOCImports(tx)
	})
}

// BeforeSave forces timestamps to UTC. SQLite stores times as text and the
// active/expired filters compare them lexicographically, which is only
// correct when every stored value uses the same zone.
func (i *IOC) BeforeSave(tx *gorm.DB) error {
	if i.ExpiresAt != nil {
		u := i.ExpiresAt.UTC()
		i.ExpiresAt = &u
	}
	if i.SourceCreatedAt != nil {
		u := i.SourceCreatedAt.UTC()
		i.SourceCreatedAt = &u
	}
	return nil
}
