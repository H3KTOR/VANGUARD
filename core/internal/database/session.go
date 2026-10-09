package database

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"time"

	"gorm.io/gorm"
)

// Session is one server-side record backing a bearer token (Phase 16). A token
// is honoured only while its session row exists, is not revoked and has not
// expired, in addition to the signature, expiry and live-account checks.
//
// State is bounded: at most MaxActiveSessionsPerUser per account (the oldest
// is DELETED when the limit is exceeded, so a loop of logins cannot grow the
// table), expired rows are purged, and rows of vanished accounts are purged.
type Session struct {
	ID           string     `gorm:"primaryKey;size:32" json:"id"` // random 128-bit hex; also the token's jti
	UserID       uint       `gorm:"not null;index" json:"user_id"`
	CreatedAt    time.Time  `gorm:"not null" json:"created_at"`
	ExpiresAt    time.Time  `gorm:"not null;index" json:"expires_at"`
	ClientIP     string     `gorm:"size:64" json:"client_ip"` // TCP peer at login (never a forwarded header)
	RevokedAt    *time.Time `json:"revoked_at,omitempty"`
	RevokeReason string     `gorm:"size:64" json:"revoke_reason,omitempty"`
}

// MaxActiveSessionsPerUser bounds concurrent sessions per account.
const MaxActiveSessionsPerUser = 10

// Session errors.
var (
	ErrSessionInvalid = errors.New("session not found, revoked or expired")
)

// NewSessionID returns a fresh random session identifier.
func NewSessionID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// CreateSession stores a session and enforces the per-account limit in the
// same transaction.
func (db *DB) CreateSession(s *Session) error {
	if s.CreatedAt.IsZero() {
		s.CreatedAt = time.Now().UTC()
	}
	s.ClientIP = sanitizeText(s.ClientIP, 64)
	return db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Create(s).Error; err != nil {
			return err
		}
		// keep the newest MaxActiveSessionsPerUser; delete the rest
		var keep []string
		if err := tx.Model(&Session{}).Where("user_id = ? AND revoked_at IS NULL AND expires_at > ?", s.UserID, s.CreatedAt).
			Order("created_at DESC, id DESC").Limit(MaxActiveSessionsPerUser).Pluck("id", &keep).Error; err != nil {
			return err
		}
		return tx.Where("user_id = ? AND id NOT IN ?", s.UserID, keep).Delete(&Session{}).Error
	})
}

// ActiveSession returns the session if it is usable for userID at now.
func (db *DB) ActiveSession(id string, userID uint, now time.Time) (*Session, error) {
	if len(id) != 32 {
		return nil, ErrSessionInvalid
	}
	var s Session
	if err := db.Where("id = ?", id).Take(&s).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrSessionInvalid
		}
		return nil, err
	}
	if s.UserID != userID || s.RevokedAt != nil || !now.Before(s.ExpiresAt) {
		return nil, ErrSessionInvalid
	}
	return &s, nil
}

// RevokeSession marks one session of userID revoked (idempotent).
func (db *DB) RevokeSession(id string, userID uint, reason string, now time.Time) (bool, error) {
	r := db.Model(&Session{}).Where("id = ? AND user_id = ? AND revoked_at IS NULL", id, userID).
		Updates(map[string]any{"revoked_at": now.UTC(), "revoke_reason": sanitizeText(reason, 64)})
	return r.RowsAffected > 0, r.Error
}

// RevokeUserSessions revokes every active session of userID, except keepID if
// non-empty. It returns how many were revoked.
func (db *DB) RevokeUserSessions(userID uint, keepID, reason string, now time.Time) (int64, error) {
	q := db.Model(&Session{}).Where("user_id = ? AND revoked_at IS NULL", userID)
	if keepID != "" {
		q = q.Where("id <> ?", keepID)
	}
	r := q.Updates(map[string]any{"revoked_at": now.UTC(), "revoke_reason": sanitizeText(reason, 64)})
	return r.RowsAffected, r.Error
}

// ListSessions returns the account's active sessions, newest first (bounded).
func (db *DB) ListSessions(userID uint, now time.Time) ([]Session, error) {
	var out []Session
	err := db.Where("user_id = ? AND revoked_at IS NULL AND expires_at > ?", userID, now.UTC()).
		Order("created_at DESC").Limit(MaxActiveSessionsPerUser).Find(&out).Error
	return out, err
}

// PurgeSessions deletes sessions expired for more than a day and sessions whose
// account no longer exists, at most limit rows. It returns the number removed.
func (db *DB) PurgeSessions(now time.Time, limit int) (int64, error) {
	if limit <= 0 || limit > 5000 {
		limit = 1000
	}
	var ids []string
	if err := db.Model(&Session{}).
		Where("expires_at < ? OR user_id NOT IN (SELECT id FROM users)", now.Add(-24*time.Hour).UTC()).
		Limit(limit).Pluck("id", &ids).Error; err != nil {
		return 0, err
	}
	if len(ids) == 0 {
		return 0, nil
	}
	r := db.Where("id IN ?", ids).Delete(&Session{})
	return r.RowsAffected, r.Error
}
