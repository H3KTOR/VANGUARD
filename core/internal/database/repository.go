package database

import (
	"errors"
	"time"

	"gorm.io/gorm"
)

// ErrNotFound is returned by lookup helpers when no row matches. Callers can
// compare with errors.Is(err, database.ErrNotFound).
var ErrNotFound = gorm.ErrRecordNotFound

// ---------------------------------------------------------------------------
// Users
// ---------------------------------------------------------------------------

// CreateUser inserts a new user. Caller is responsible for hashing the
// password before calling this.
func (db *DB) CreateUser(u *User) error {
	return db.Create(u).Error
}

// GetUserByEmail looks up a user by email (case-sensitive; normalize at the
// API layer if you want case-insensitive login).
func (db *DB) GetUserByEmail(email string) (*User, error) {
	var u User
	if err := db.Where("email = ?", email).First(&u).Error; err != nil {
		return nil, err
	}
	return &u, nil
}

// TouchLastLogin stamps LastLoginAt = now for the given user id.
func (db *DB) TouchLastLogin(userID uint) error {
	now := time.Now().UTC()
	return db.Model(&User{}).Where("id = ?", userID).Update("last_login_at", now).Error
}

// ---------------------------------------------------------------------------
// System Metrics
// ---------------------------------------------------------------------------

// RecordMetric inserts a single system metric sample.
func (db *DB) RecordMetric(m *SystemMetric) error {
	if m.Timestamp.IsZero() {
		m.Timestamp = time.Now().UTC()
	}
	return db.Create(m).Error
}

// GetMetricsSince returns metrics with Timestamp >= since, oldest first.
// Intended for dashboard time-series charts (e.g. last 1h/24h).
func (db *DB) GetMetricsSince(since time.Time) ([]SystemMetric, error) {
	var metrics []SystemMetric
	err := db.Where("timestamp >= ?", since).
		Order("timestamp asc").
		Find(&metrics).Error
	return metrics, err
}

// LatestMetric returns the most recent sample, or ErrNotFound if the table
// is empty.
func (db *DB) LatestMetric() (*SystemMetric, error) {
	var m SystemMetric
	if err := db.Order("timestamp desc").First(&m).Error; err != nil {
		return nil, err
	}
	return &m, nil
}

// PruneMetricsOlderThan deletes metric rows older than the cutoff, keeping
// the append-only table from growing unbounded on long-running hosts.
func (db *DB) PruneMetricsOlderThan(cutoff time.Time) (int64, error) {
	res := db.Where("timestamp < ?", cutoff).Delete(&SystemMetric{})
	return res.RowsAffected, res.Error
}

// ---------------------------------------------------------------------------
// Incidents
// ---------------------------------------------------------------------------

// CreateIncident inserts a new incident, deriving Severity from RiskScore if
// Severity was left blank.
func (db *DB) CreateIncident(inc *Incident) error {
	if inc.DetectedAt.IsZero() {
		inc.DetectedAt = time.Now().UTC()
	}
	if inc.Severity == "" {
		inc.Severity = SeverityFromScore(inc.RiskScore)
	}
	if inc.Status == "" {
		inc.Status = StatusOpen
	}
	return db.Create(inc).Error
}

// GetIncident fetches a single incident by ID.
func (db *DB) GetIncident(id uint) (*Incident, error) {
	var inc Incident
	if err := db.First(&inc, id).Error; err != nil {
		return nil, err
	}
	return &inc, nil
}

// UpdateIncidentStatus transitions an incident's status (e.g. to
// investigating / resolved / false_positive), stamping ResolvedAt for
// terminal states.
func (db *DB) UpdateIncidentStatus(id uint, status IncidentStatus) error {
	updates := map[string]any{"status": status}
	if status == StatusResolved || status == StatusFalsePositive {
		now := time.Now().UTC()
		updates["resolved_at"] = &now
	}
	return db.Model(&Incident{}).Where("id = ?", id).Updates(updates).Error
}

// SetIncidentAIAnalysis stores the AI-generated summary text produced by the
// Python toolkit for a given incident.
func (db *DB) SetIncidentAIAnalysis(id uint, analysis string) error {
	return db.Model(&Incident{}).Where("id = ?", id).Update("ai_analysis", analysis).Error
}

// IncidentFilter narrows ListIncidents results. Zero values are ignored.
type IncidentFilter struct {
	Status   IncidentStatus
	Severity Severity
	Type     IncidentType
	SourceIP string
	Since    time.Time
	Limit    int
	Offset   int
}

// ListIncidents returns incidents matching the filter, newest first.
func (db *DB) ListIncidents(f IncidentFilter) ([]Incident, error) {
	q := db.Model(&Incident{})
	if f.Status != "" {
		q = q.Where("status = ?", f.Status)
	}
	if f.Severity != "" {
		q = q.Where("severity = ?", f.Severity)
	}
	if f.Type != "" {
		q = q.Where("type = ?", f.Type)
	}
	if f.SourceIP != "" {
		q = q.Where("source_ip = ?", f.SourceIP)
	}
	if !f.Since.IsZero() {
		q = q.Where("detected_at >= ?", f.Since)
	}
	limit := f.Limit
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	var incidents []Incident
	err := q.Order("detected_at desc").Limit(limit).Offset(f.Offset).Find(&incidents).Error
	return incidents, err
}

// CountIncidentsWithoutAnalysis returns pending-analysis incidents, used by
// the Python AI Analyst cron job to know how much work is queued.
func (db *DB) CountIncidentsWithoutAnalysis() (int64, error) {
	var count int64
	err := db.Model(&Incident{}).
		Where("ai_analysis = '' OR ai_analysis IS NULL").
		Count(&count).Error
	return count, err
}

// IncidentsPendingAnalysis returns up to limit incidents that have no
// AIAnalysis yet, oldest first (FIFO processing for the toolkit).
func (db *DB) IncidentsPendingAnalysis(limit int) ([]Incident, error) {
	if limit <= 0 {
		limit = 20
	}
	var incidents []Incident
	err := db.Where("ai_analysis = '' OR ai_analysis IS NULL").
		Order("detected_at asc").
		Limit(limit).
		Find(&incidents).Error
	return incidents, err
}

// CountRecentEventsByIP counts how many incidents of the given type a
// source IP has triggered since `since`. This is a building block the
// detection engine's frequency-scoring uses on top of raw log counters
// (which live in-memory, not in SQLite) to factor historical repeat-offender
// behavior into RiskScore.
func (db *DB) CountRecentEventsByIP(ip string, since time.Time) (int64, error) {
	var count int64
	err := db.Model(&Incident{}).
		Where("source_ip = ? AND detected_at >= ?", ip, since).
		Count(&count).Error
	return count, err
}

// ---------------------------------------------------------------------------
// Firewall Rules
// ---------------------------------------------------------------------------

// CreateFirewallRule inserts a new ban/whitelist rule.
func (db *DB) CreateFirewallRule(r *FirewallRule) error {
	if r.BannedAt.IsZero() {
		r.BannedAt = time.Now().UTC()
	}
	return db.Create(r).Error
}

// IsWhitelisted reports whether ip has an active whitelist rule. The
// Autopilot MUST call this (or rely on an equivalent in-memory cache seeded
// from it) before ever issuing a block, per the fail-safe whitelisting
// requirement.
func (db *DB) IsWhitelisted(ip string) (bool, error) {
	var count int64
	err := db.Model(&FirewallRule{}).
		Where("ip_address = ? AND is_whitelisted = ? AND is_active = ?", ip, true, true).
		Count(&count).Error
	return count > 0, err
}

// IsBanned reports whether ip currently has an active (non-expired) ban.
func (db *DB) IsBanned(ip string) (bool, error) {
	var count int64
	now := time.Now().UTC()
	err := db.Model(&FirewallRule{}).
		Where("ip_address = ? AND is_whitelisted = ? AND is_active = ? AND (unban_at IS NULL OR unban_at > ?)",
			ip, false, true, now).
		Count(&count).Error
	return count > 0, err
}

// ActiveBans returns all currently active, non-expired ban rules -- used to
// reconcile VANGUARD's DB state against the live UFW/iptables rule set on
// startup.
func (db *DB) ActiveBans() ([]FirewallRule, error) {
	var rules []FirewallRule
	now := time.Now().UTC()
	err := db.Where("is_whitelisted = ? AND is_active = ? AND (unban_at IS NULL OR unban_at > ?)",
		false, true, now).Find(&rules).Error
	return rules, err
}

// ExpiredBans returns active TTL bans whose UnbanAt has passed and have not
// yet been deactivated. The firewall package's reaper loop polls this.
func (db *DB) ExpiredBans() ([]FirewallRule, error) {
	var rules []FirewallRule
	now := time.Now().UTC()
	err := db.Where("is_active = ? AND is_whitelisted = ? AND unban_at IS NOT NULL AND unban_at <= ?",
		true, false, now).Find(&rules).Error
	return rules, err
}

// DeactivateFirewallRule marks a rule inactive (used after unbanning an
// expired rule, or when an admin manually lifts a block).
func (db *DB) DeactivateFirewallRule(id uint) error {
	return db.Model(&FirewallRule{}).Where("id = ?", id).Update("is_active", false).Error
}

// ListFirewallRules returns rules ordered newest-first, optionally filtered
// to only active rows.
func (db *DB) ListFirewallRules(activeOnly bool) ([]FirewallRule, error) {
	q := db.Model(&FirewallRule{})
	if activeOnly {
		q = q.Where("is_active = ?", true)
	}
	var rules []FirewallRule
	err := q.Order("banned_at desc").Find(&rules).Error
	return rules, err
}

// compile-time: ensure errors.Is usage pattern documented above type-checks
// against the aliased ErrNotFound.
var _ = errors.Is
