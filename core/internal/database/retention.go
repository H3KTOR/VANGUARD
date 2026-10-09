package database

import (
	"errors"
	"time"

	"gorm.io/gorm"
)

// RetentionPolicy is the single-row (ID = 1) operator policy for deleting old
// operational records (Phase 12). It lives in the database - not in flags or
// .env - so it is the same for the daemon and the CLI and is carried by
// backups. IncidentRetentionDays == 0 means "keep everything" (the default and
// the behaviour of every earlier release).
type RetentionPolicy struct {
	ID                    uint      `gorm:"primaryKey" json:"-"`
	Revision              int       `gorm:"not null" json:"revision"`
	IncidentRetentionDays int       `gorm:"not null" json:"incident_retention_days"`
	BatchSize             int       `gorm:"not null" json:"batch_size"`
	MaxBatchesPerRun      int       `gorm:"not null" json:"max_batches_per_run"`
	KeepWithNotes         bool      `gorm:"not null" json:"keep_incidents_with_notes"`
	UpdatedBy             string    `gorm:"size:128" json:"updated_by"`
	UpdatedAt             time.Time `json:"updated_at"`
}

// Retention run modes and statuses (stored as text; new values need no migration).
const (
	RetentionModeDryRun       = "dry_run"
	RetentionModeExecute      = "execute"
	RetentionModePolicyChange = "policy_change"

	RetentionStatusCompleted = "completed" // nothing left that is eligible
	RetentionStatusPartial   = "partial"   // stopped early (batch cap, cancel or error); more may remain
	RetentionStatusFailed    = "failed"
	RetentionStatusSkipped   = "skipped"
	RetentionStatusDisabled  = "disabled"
	RetentionStatusPreview   = "preview"
	RetentionStatusRecorded  = "recorded"
)

// RetentionRun is one append-only audit row describing a retention action. It
// records what was done and by whom, NOT the deleted content. Rows are never
// deleted by VANGUARD, and the table is not tamper-evident.
type RetentionRun struct {
	ID         uint       `gorm:"primaryKey" json:"id"`
	StartedAt  time.Time  `gorm:"not null;index" json:"started_at"`
	FinishedAt *time.Time `json:"finished_at,omitempty"`
	Actor      string     `gorm:"size:128;not null" json:"actor"`
	Mode       string     `gorm:"size:16;not null" json:"mode"`
	Status     string     `gorm:"size:16;not null" json:"status"`

	PolicyRevision int       `json:"policy_revision"`
	PolicyDays     int       `json:"policy_days"`
	Cutoff         time.Time `json:"cutoff"`

	EligibleTotal    int64 `json:"eligible_total"` // matching rows at the start of the run
	IncidentsDeleted int64 `json:"incidents_deleted"`
	EventsDeleted    int64 `json:"events_deleted"`
	NotesDeleted     int64 `json:"notes_deleted"`
	MatchesUnlinked  int64 `json:"ioc_matches_unlinked"`
	RulesUnlinked    int64 `json:"firewall_rules_unlinked"`
	SkippedActive    int64 `json:"skipped_active_ban"`
	SkippedNotes     int64 `json:"skipped_with_notes"`
	Batches          int   `json:"batches"`
	MinID            uint  `json:"min_incident_id"`
	MaxID            uint  `json:"max_incident_id"`

	Detail string `gorm:"size:512" json:"detail,omitempty"` // bounded, sanitized
}

// ErrRetentionPolicyConflict: the caller's expected revision is stale.
var ErrRetentionPolicyConflict = errors.New("retention policy changed since you read it (revision mismatch)")

// DefaultRetentionPolicy is what applies when no row exists.
func DefaultRetentionPolicy() RetentionPolicy {
	return RetentionPolicy{IncidentRetentionDays: 0, BatchSize: 200, MaxBatchesPerRun: 20, KeepWithNotes: true}
}

// GetRetentionPolicy returns the stored policy, or the defaults (revision 0).
func (db *DB) GetRetentionPolicy() (RetentionPolicy, error) {
	var p RetentionPolicy
	err := db.Where("id = ?", 1).First(&p).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return DefaultRetentionPolicy(), nil
	}
	return p, err
}

// SetRetentionPolicy stores p if expectedRevision matches the current
// revision, and appends a policy_change audit row in the same transaction.
func (db *DB) SetRetentionPolicy(p RetentionPolicy, expectedRevision int, actor string, now time.Time) (RetentionPolicy, error) {
	var out RetentionPolicy
	err := db.Transaction(func(tx *gorm.DB) error {
		var cur RetentionPolicy
		err := tx.Where("id = ?", 1).First(&cur).Error
		if errors.Is(err, gorm.ErrRecordNotFound) {
			cur = DefaultRetentionPolicy()
		} else if err != nil {
			return err
		}
		if cur.Revision != expectedRevision {
			return ErrRetentionPolicyConflict
		}
		p.ID, p.Revision, p.UpdatedBy, p.UpdatedAt = 1, cur.Revision+1, sanitizeText(actor, 128), now.UTC()
		if err := tx.Save(&p).Error; err != nil {
			return err
		}
		fin := now.UTC()
		out = p
		return tx.Create(&RetentionRun{
			StartedAt: now.UTC(), FinishedAt: &fin, Actor: p.UpdatedBy, Mode: RetentionModePolicyChange,
			Status: RetentionStatusRecorded, PolicyRevision: p.Revision, PolicyDays: p.IncidentRetentionDays,
			Detail: sanitizeText("policy revision "+itoa(uint(p.Revision))+" (was "+itoa(uint(cur.Revision))+"; days "+itoa(uint(cur.IncidentRetentionDays))+" -> "+itoa(uint(p.IncidentRetentionDays))+")", 512),
		}).Error
	})
	return out, err
}

// RecordRetentionRun appends an audit row.
func (db *DB) RecordRetentionRun(r *RetentionRun) error {
	r.Actor = sanitizeText(r.Actor, 128)
	r.Detail = sanitizeText(r.Detail, 512)
	return db.Create(r).Error
}

// ListRetentionRuns returns the most recent audit rows (limit capped at 100).
func (db *DB) ListRetentionRuns(limit int) ([]RetentionRun, error) {
	if limit <= 0 || limit > 100 {
		limit = 20
	}
	var out []RetentionRun
	err := db.Order("id DESC").Limit(limit).Find(&out).Error
	return out, err
}
