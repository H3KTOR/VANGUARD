// Package database defines the persistent data model for VANGUARD and
// exposes a small repository layer on top of GORM + SQLite.
//
// Design notes:
//   - SQLite is the only storage engine (zero external services, per the
//     project constraints). We use the pure-Go glebarez/sqlite driver so the
//     final binary stays CGO-free and fully static.
//   - Time-series-ish tables (SystemMetric, Incident) get explicit
//     composite indexes tailored to the query patterns the detection engine
//     and dashboard will actually run (range scans by time, look-ups by
//     source IP, filtering by status/severity).
package database

import (
	"encoding/json"
	"time"

	"gorm.io/gorm"
)

// ---------------------------------------------------------------------------
// Enums / constants
// ---------------------------------------------------------------------------

// Role identifies a user's access level within the dashboard/API.
type Role string

const (
	RoleAdmin  Role = "admin"
	RoleViewer Role = "viewer"
)

// IncidentType enumerates the deterministic detection signatures VANGUARD
// V1 is capable of raising. Kept as a string (not a DB enum) so SQLite
// migrations never need an ALTER TYPE-style change when new signatures
// are added.
type IncidentType string

const (
	IncidentSSHBruteForce     IncidentType = "ssh_bruteforce"
	IncidentFailedThenSuccess IncidentType = "failed_then_success_login"
	IncidentPortScan          IncidentType = "port_scan"
	IncidentWebDirScan        IncidentType = "web_directory_scan"
	IncidentPathTraversal     IncidentType = "path_traversal"
	IncidentSQLiXSS           IncidentType = "sqli_xss_probe"
	IncidentHTTPFlood         IncidentType = "http_flood"
	IncidentHoneypotTrigger   IncidentType = "honeypot_trigger"
)

// Severity is the human-readable bucket derived from RiskScore.
// See RiskScore.Severity() for the authoritative mapping (0-29 LOW,
// 30-59 MEDIUM, 60-79 HIGH, 80-100 CRITICAL).
type Severity string

const (
	SeverityLow      Severity = "LOW"
	SeverityMedium   Severity = "MEDIUM"
	SeverityHigh     Severity = "HIGH"
	SeverityCritical Severity = "CRITICAL"
)

// IncidentStatus tracks the lifecycle of an incident through triage.
type IncidentStatus string

const (
	StatusOpen          IncidentStatus = "open"
	StatusAutoBlocked   IncidentStatus = "auto_blocked"
	StatusInvestigating IncidentStatus = "investigating"
	StatusResolved      IncidentStatus = "resolved"
	StatusFalsePositive IncidentStatus = "false_positive"
)

// FirewallSource records what subsystem created a firewall rule, which
// matters for audit trails and for the Autopilot's "never touch manual
// rules" safety behavior.
type FirewallSource string

const (
	FirewallSourceAutopilot FirewallSource = "autopilot"
	FirewallSourceManual    FirewallSource = "manual"
	FirewallSourceHoneypot  FirewallSource = "honeypot"
	FirewallSourceSimulator FirewallSource = "simulator"
)

// SeverityFromScore applies the dynamic risk scoring bands from the spec.
func SeverityFromScore(score int) Severity {
	switch {
	case score >= 80:
		return SeverityCritical
	case score >= 60:
		return SeverityHigh
	case score >= 30:
		return SeverityMedium
	default:
		return SeverityLow
	}
}

// ---------------------------------------------------------------------------
// User
// ---------------------------------------------------------------------------

// User is a dashboard/API account. Passwords are never stored in plaintext;
// PasswordHash must always contain a bcrypt (or equivalent) digest produced
// by the API layer, never by this package.
type User struct {
	ID           uint       `gorm:"primaryKey" json:"id"`
	Email        string     `gorm:"uniqueIndex;size:255;not null" json:"email"`
	PasswordHash string     `gorm:"size:255;not null" json:"-"`
	Role         Role       `gorm:"size:32;not null;default:viewer" json:"role"`
	IsActive     bool       `gorm:"not null;default:true" json:"is_active"`
	LastLoginAt  *time.Time `json:"last_login_at,omitempty"`
	CreatedAt    time.Time  `json:"created_at"`
	UpdatedAt    time.Time  `json:"updated_at"`
}

// ---------------------------------------------------------------------------
// SystemMetric
// ---------------------------------------------------------------------------

// SystemMetric is a single point-in-time host resource sample, written on a
// fixed interval (e.g. every 10-30s) by the metric collector. The table is
// purely append-only and read via time-range queries, so it only needs a
// single index on Timestamp (DESC scans for "last N minutes" dashboards).
type SystemMetric struct {
	ID                uint      `gorm:"primaryKey" json:"id"`
	CPUPercent        float64   `gorm:"not null" json:"cpu_percent"`
	MemoryPercent     float64   `gorm:"not null" json:"memory_percent"`
	MemoryUsedMB      uint64    `gorm:"not null" json:"memory_used_mb"`
	DiskPercent       float64   `gorm:"not null" json:"disk_percent"`
	ActiveConnections int       `gorm:"not null;default:0" json:"active_connections"`
	Timestamp         time.Time `gorm:"index:idx_metrics_timestamp;not null" json:"timestamp"`
}

// ---------------------------------------------------------------------------
// Incident
// ---------------------------------------------------------------------------

// Incident is a single detected security event. Metadata carries
// detection-specific structured context (matched log lines, request paths,
// port lists, etc.) as a raw JSON string so the schema never has to change
// when a new detector adds new fields - callers use SetMetadata/GetMetadata
// to marshal/unmarshal it safely.
type Incident struct {
	ID uint `gorm:"primaryKey" json:"id"`

	Type      IncidentType   `gorm:"size:64;not null;index:idx_incidents_type_time,priority:1" json:"type"`
	SourceIP  string         `gorm:"size:64;not null;index:idx_incidents_ip_time,priority:1" json:"source_ip"`
	Severity  Severity       `gorm:"size:16;not null;index" json:"severity"`
	RiskScore int            `gorm:"not null;default:0" json:"risk_score"`
	Status    IncidentStatus `gorm:"size:32;not null;default:open;index" json:"status"`

	AttemptCount int    `gorm:"not null;default:1" json:"attempt_count"`
	AIAnalysis   string `gorm:"type:text" json:"ai_analysis,omitempty"`
	Metadata     string `gorm:"type:text" json:"metadata,omitempty"`

	DetectedAt time.Time  `gorm:"not null;index:idx_incidents_ip_time,priority:2;index:idx_incidents_type_time,priority:2" json:"detected_at"`
	ResolvedAt *time.Time `json:"resolved_at,omitempty"`

	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// SetMetadata marshals v into the Metadata column as JSON.
func (i *Incident) SetMetadata(v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	i.Metadata = string(b)
	return nil
}

// GetMetadata unmarshals the Metadata column into v. Returns nil (no-op) if
// Metadata is empty.
func (i *Incident) GetMetadata(v any) error {
	if i.Metadata == "" {
		return nil
	}
	return json.Unmarshal([]byte(i.Metadata), v)
}

// ---------------------------------------------------------------------------
// FirewallRule
// ---------------------------------------------------------------------------

// FirewallRule represents a single IP-level firewall decision (block or
// whitelist) applied via UFW/iptables. UnbanAt is nil for permanent rules;
// non-nil TTL rules are swept by a background reaper in the firewall
// package that re-allows the IP and flips IsActive to false once expired.
type FirewallRule struct {
	ID uint `gorm:"primaryKey" json:"id"`

	IPAddress     string         `gorm:"size:64;not null;index:idx_firewall_ip_active,priority:1" json:"ip_address"`
	Reason        string         `gorm:"size:255" json:"reason"`
	Source        FirewallSource `gorm:"size:32;not null;default:manual" json:"source"`
	IsWhitelisted bool           `gorm:"not null;default:false;index" json:"is_whitelisted"`
	IsActive      bool           `gorm:"not null;default:true;index:idx_firewall_ip_active,priority:2" json:"is_active"`

	IncidentID *uint `json:"incident_id,omitempty"`

	BannedAt time.Time  `gorm:"not null;index" json:"banned_at"`
	UnbanAt  *time.Time `gorm:"index" json:"unban_at,omitempty"`

	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// IsExpired reports whether a TTL-bound rule's ban window has elapsed.
// Permanent rules (UnbanAt == nil) are never expired.
func (f *FirewallRule) IsExpired(now time.Time) bool {
	return f.UnbanAt != nil && now.After(*f.UnbanAt)
}

// AllModels returns every struct that must be migrated by AutoMigrate, in a
// safe dependency order.
func AllModels() []any {
	return []any{
		&User{},
		&SystemMetric{},
		&Incident{},
		&FirewallRule{},
	}
}

// compile-time assurance the gorm import is used even if models above change.
var _ = gorm.ErrRecordNotFound
