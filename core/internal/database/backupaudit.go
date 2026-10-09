package database

import "time"

// BackupAudit records backup and restore operations (Phase 11). It lives
// in the same local SQLite file it describes, so it is an operational log,
// not tamper-evident evidence. A restore replaces the database file, so the
// restore entry is written into the NEWLY restored database; the replaced
// database is kept next to it under a *.pre-restore-* name.
type BackupAudit struct {
	ID         uint      `gorm:"primaryKey" json:"id"`
	At         time.Time `gorm:"not null;index" json:"at"`
	Kind       string    `gorm:"size:16;not null" json:"kind"` // create | restore
	Actor      string    `gorm:"size:128" json:"actor"`
	BackupName string    `gorm:"size:96" json:"backup_name"`
	DBSHA256   string    `gorm:"size:64" json:"db_sha256"`
	Result     string    `gorm:"size:16;not null" json:"result"` // ok | failed
	Detail     string    `gorm:"size:256" json:"detail"`
}

// RecordBackupAudit appends an audit entry (detail is sanitized/bounded).
func (db *DB) RecordBackupAudit(a *BackupAudit) error {
	if a.At.IsZero() {
		a.At = time.Now().UTC()
	}
	a.Actor = sanitizeText(a.Actor, 128)
	a.Detail = sanitizeText(a.Detail, 256)
	return db.Create(a).Error
}

// ListBackupAudit returns the most recent entries (max 100).
func (db *DB) ListBackupAudit(limit int) ([]BackupAudit, error) {
	if limit <= 0 || limit > 100 {
		limit = 50
	}
	var out []BackupAudit
	err := db.Order("id DESC").Limit(limit).Find(&out).Error
	return out, err
}
