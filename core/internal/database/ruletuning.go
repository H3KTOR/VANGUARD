package database

import "time"

// RuleTuningRevision is one entry in the append-only history of operator
// threshold overrides (Phase 10). Exactly one row has Status "active" at a
// time; revision 0 (no row) means compiled defaults. Rows are never edited
// except to flip an earlier row from "active" to "superseded". The table
// lives in the local SQLite file and is not tamper-evident.
type RuleTuningRevision struct {
	ID        uint      `gorm:"primaryKey" json:"revision"` // the revision number
	CreatedAt time.Time `gorm:"not null" json:"created_at"`
	Actor     string    `gorm:"size:128;not null" json:"actor"`
	Reason    string    `gorm:"size:256" json:"reason"`
	Kind      string    `gorm:"size:16;not null" json:"kind"`         // apply | rollback
	Status    string    `gorm:"size:16;not null;index" json:"status"` // active | superseded
	Values    string    `gorm:"type:text;not null" json:"-"`          // JSON of the full effective value set
	Changes   string    `gorm:"type:text" json:"-"`                   // JSON diff against the previous revision
	// WeakeningAcknowledged records that the operator explicitly accepted a
	// change that makes at least one rule less sensitive.
	WeakeningAcknowledged bool `gorm:"not null" json:"weakening_acknowledged"`
	// RolledBackTo is the revision whose values a rollback restored.
	RolledBackTo uint `json:"rolled_back_to,omitempty"`
}
