package database

import (
	"errors"
	"time"

	"gorm.io/gorm"
)

// AdminAudit is an append-only record of a privileged API action (Phase 13):
// who (the authenticated account), what, against which target, and whether it
// worked. It deliberately stores identifiers and short outcomes, never request
// bodies, tokens, passwords, feed contents or free-form payloads.
//
// It is NOT tamper-evident: anyone who can write the database file can edit or
// delete rows. VANGUARD never deletes it automatically.
type AdminAudit struct {
	ID        uint      `gorm:"primaryKey" json:"id"`
	At        time.Time `gorm:"not null;index" json:"at"`
	Actor     string    `gorm:"size:128;not null" json:"actor"`
	ActorRole string    `gorm:"size:16" json:"actor_role"`
	Action    string    `gorm:"size:48;not null;index" json:"action"`
	Target    string    `gorm:"size:128" json:"target,omitempty"`
	Result    string    `gorm:"size:16;not null" json:"result"` // ok | refused | failed
	Detail    string    `gorm:"size:256" json:"detail,omitempty"`
}

// RecordAdminAudit appends a row (text fields are sanitized and bounded).
func (db *DB) RecordAdminAudit(a *AdminAudit) error {
	if a.At.IsZero() {
		a.At = time.Now().UTC()
	}
	a.Actor = sanitizeText(a.Actor, 128)
	a.ActorRole = sanitizeText(a.ActorRole, 16)
	a.Action = sanitizeText(a.Action, 48)
	a.Target = sanitizeText(a.Target, 128)
	a.Result = sanitizeText(a.Result, 16)
	a.Detail = sanitizeText(a.Detail, 256)
	return db.Create(a).Error
}

// ListAdminAudit returns the newest rows first (limit capped at 200).
func (db *DB) ListAdminAudit(limit int) ([]AdminAudit, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	var out []AdminAudit
	err := db.Order("id DESC").Limit(limit).Find(&out).Error
	return out, err
}

// GetUserByID loads one account by primary key (used to re-validate a token
// against the live account on every request).
func (db *DB) GetUserByID(id uint) (*User, error) {
	var u User
	if err := db.First(&u, id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &u, nil
}

// ListFirewallRulesPage is the bounded form of ListFirewallRules.
func (db *DB) ListFirewallRulesPage(activeOnly bool, limit, offset int) ([]FirewallRule, error) {
	if limit <= 0 || limit > 500 {
		limit = 200
	}
	if offset < 0 || offset > 10000 {
		offset = 0
	}
	q := db.Model(&FirewallRule{})
	if activeOnly {
		q = q.Where("is_active = ?", true)
	}
	var out []FirewallRule
	err := q.Order("banned_at DESC, id DESC").Limit(limit).Offset(offset).Find(&out).Error
	return out, err
}
