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

	// IncidentAttackChain is VANGUARD's Task 3 "Smart Detection" signature:
	// a single source IP exhibiting the coordinated multi-stage sequence
	// Recon (port scan) -> Web Probing (403/404s) -> Auth Probing (SSH
	// failures) within one sliding window. This is a *correlation* of
	// existing weaker signals, not a new log pattern, so it is always the
	// most severe signature VANGUARD can raise (see risk.ScoreChain).
	IncidentAttackChain IncidentType = "attack_chain"
	// IncidentWebScanner is a heuristic (not purely signature-based)
	// detection of automated web vulnerability scanners (Nikto, Dirbuster,
	// wpscan, etc.): a high frequency of 403/404 responses combined with a
	// missing or known-scanner User-Agent string.
	IncidentWebScanner IncidentType = "web_scanner_behavior"

	// IncidentWebAttackChain extends the same correlation architecture as
	// IncidentAttackChain (Task 3) to a Phase 3 web-focused multi-stage
	// sequence from one source IP: Web Probing (403/404 reconnaissance
	// OR API-abuse-shaped endpoint enumeration) -> Auth Probing (SSH
	// brute-force/spraying-shaped failures) -> Exploitation (a Web Shell
	// Indicator or SSRF Indicator-shaped request), all within
	// thresholds.WebAttackChainWindow. This is a *correlation* of
	// existing weaker Phase 3 signals, reusing the SAME ChainTracker
	// state machine and risk.ScoreChain aggregation as
	// IncidentAttackChain (see correlation.go's ChainTracker.
	// EvaluateWebAttackChain) -- never a second/duplicate correlation
	// engine. Matches the mega-prompt's worked examples: "Recon -> Web
	// Probing -> Auth Abuse -> Web Shell Indicator" and "Web Probe ->
	// SSRF -> Suspicious Outbound" (VANGUARD cannot observe the actual
	// outbound connection an SSRF-shaped request may have triggered, so
	// that third stage is represented here by the SSRF-Indicator request
	// itself, not a confirmed outbound connection).
	IncidentWebAttackChain IncidentType = "web_attack_chain"

	// -----------------------------------------------------------------
	// Host Security signatures (VANGUARD Mega Expansion, Phase 1).
	//
	// Unlike every incident type above -- which is always attributable
	// to a remote SourceIP observed in a log line -- these five are
	// raised by periodic HOST-LOCAL inspection (filesystem, /etc,
	// /proc) with no network origin at all. By convention they are
	// persisted with SourceIP = HostLocalIP ("127.0.0.1"), which is
	// unconditionally seeded into the Autopilot fail-safe whitelist
	// (see firewall.DefaultConfig) so a host-security finding can NEVER
	// trigger an accidental self-ban of the loopback address. Autopilot
	// still records/logs these incidents; it simply never *bans* them,
	// since there is no attacker IP to block -- containment for this
	// class of finding is a human-in-the-loop / future-phase concern,
	// not an automatic firewall action.
	// -----------------------------------------------------------------

	// IncidentFIMChange: a monitored sensitive file's SHA-256, size,
	// permissions, owner, group, or existence changed relative to its
	// last-known-good baseline (created/deleted/modified/perm_changed/
	// owner_changed/group_changed -- see the "change" field in Metadata).
	IncidentFIMChange IncidentType = "fim_change"

	// IncidentPersistenceDetected: a new or modified persistence
	// mechanism was observed (cron entry, systemd unit/timer, SSH
	// authorized_keys addition, shell startup file, /etc/profile.d
	// script, or sudoers entry).
	IncidentPersistenceDetected IncidentType = "persistence_detected"

	// IncidentPrivilegeEscalation: an indicator consistent with a
	// privilege-escalation attempt or successful escalation (new UID 0
	// account, privileged group membership change, a new SUID/SGID
	// binary in a world-writable/temp directory, or -- best-effort,
	// since VANGUARD has no eBPF/kernel visibility -- an unexpected
	// root-owned process).
	IncidentPrivilegeEscalation IncidentType = "privilege_escalation_indicator"

	// IncidentAccountChange: a user or group was created/deleted, or an
	// existing account's UID/GID or privileged-group membership changed.
	IncidentAccountChange IncidentType = "account_security_change"

	// IncidentSUIDSGIDAnomaly: a SUID/SGID-bit binary appeared,
	// disappeared, or had its owner/mode changed relative to the last
	// baseline scan. CRITICAL-escalated when the binary lives under a
	// world-writable or temp directory (/tmp, /var/tmp, /dev/shm, or any
	// directory whose own mode is world-writable) -- a classic
	// privilege-escalation-via-dropped-SUID-binary pattern.
	IncidentSUIDSGIDAnomaly IncidentType = "suid_sgid_anomaly"

	// -----------------------------------------------------------------
	// Phase 2 signatures (VANGUARD Mega Expansion): Process Anomaly
	// Detection, Process->File->Network Correlation, System Binary
	// Integrity. Like the Phase 1 signatures above, these are host-local
	// (SourceIP = HostLocalIP) with one exception: IncidentHighConfidenceCompromise
	// carries whatever remote IP triggered its network leg (a genuine
	// attacker/C2 IP, not host-local), since that IP IS meaningful
	// evidence -- Autopilot can safely act on it exactly like any other
	// network-sourced incident.
	// -----------------------------------------------------------------

	// IncidentSuspiciousProcess: BEST-EFFORT DETECTION (periodic /proc
	// snapshot only, no eBPF/kernel visibility -- see hostsec/process.go's
	// doc comment). Raised for a process whose executable has been
	// unlinked from disk while still running ("(deleted)" in
	// /proc/<pid>/exe -- classic fileless-malware/rootkit evasion), a
	// process executing from a world-writable/temp directory, a
	// suspicious parent-child relationship (a shell/interpreter spawned
	// by a network-facing service such as nginx/sshd/mysqld), or an
	// abnormal burst of new process creation within one scan interval.
	// Deliberately does NOT duplicate PrivEsc's own "unexpected root
	// process" check (database.IncidentPrivilegeEscalation) -- see that
	// type's doc comment -- to avoid two detectors raising overlapping
	// signatures for the same underlying evidence.
	IncidentSuspiciousProcess IncidentType = "suspicious_process"

	// IncidentHighConfidenceCompromise: a correlation (internal/detection's
	// ProcessNetCorrelator, mirroring ChainTracker's shape) of a
	// Suspicious Process finding with at least one of (a) a recent
	// sensitive-file FIM change or (b) that same process owning an
	// outbound connection to an IP flagged by Threat Intelligence, within
	// a bounded window. This is VANGUARD's second-most-severe signature
	// after IncidentAttackChain (which correlates network-only signals);
	// this one additionally incorporates host-local process/file
	// evidence, which is why it carries its own elevated base severity
	// (see risk.BaseSeverity) rather than reusing ScoreChain's aggregate-
	// then-multiply formula.
	IncidentHighConfidenceCompromise IncidentType = "high_confidence_compromise"

	// IncidentSystemBinaryIntegrity: a security-critical system binary's
	// SHA-256/size/mode/owner/group changed relative to its last-known
	// baseline (created/deleted/modified/perm_changed/owner_changed/
	// group_changed). Distinct from IncidentFIMChange (which watches
	// config files, not executables) per the mega-prompt's explicit
	// feature split; internally reuses the exact same statFile/
	// compareMeta/fileMeta diff helpers FIMWatcher already uses (see
	// hostsec/hostsec.go), just against a different target list and its
	// own baseline category/incident type -- not a second, independent
	// detection engine.
	IncidentSystemBinaryIntegrity IncidentType = "system_binary_integrity_violation"

	// -----------------------------------------------------------------
	// Web Security signatures (VANGUARD Mega Expansion, Phase 3).
	//
	// All nine are indicator/heuristic detectors built entirely from
	// what internal/detection's existing WebLogParser and AuthLogParser
	// already expose (source IP, username, path, method, status code,
	// User-Agent, Protocol, and -- only when the operator has customized
	// their nginx log_format -- Host). None of these claim payload-level
	// exploit confirmation, packet-level HTTP parsing, or WAF-grade
	// protection; every doc comment below states its specific visibility
	// limitation. See internal/detection/web_security.go and
	// http_anomaly.go for the detectors themselves.
	// -----------------------------------------------------------------

	// IncidentPasswordSpraying: many DISTINCT usernames, each receiving
	// relatively few failed SSH auth attempts, from one source IP within
	// a bounded window -- the inverse shape of SSH brute force (one
	// account, many attempts). Requires the auth log source to expose a
	// username per attempt (auth.log's "Failed password for X" always
	// does); if a future log source cannot expose usernames, this
	// correlation is simply never fed for that source rather than
	// inventing a placeholder username.
	IncidentPasswordSpraying IncidentType = "password_spraying"

	// IncidentCredentialStuffing: a source IP driving a high AUTHENTICATION
	// FAILURE RATE against MANY distinct usernames within a bounded
	// window -- stronger/broader than password spraying's own threshold
	// (more usernames AND a sustained attempt rate). This is an
	// authentication-anomaly classification based on observable failure
	// volume/diversity; VANGUARD has no way to know whether the
	// attempted credentials were actually sourced from a prior breach,
	// so it never claims that.
	IncidentCredentialStuffing IncidentType = "credential_stuffing"

	// IncidentWebShellIndicator: a request to a script/executable path
	// under a webroot-like or upload-like location, using a web-shell-
	// associated extension (.php, .phtml, .php5, .jsp, .jspx, .asp,
	// .aspx) and/or a suspicious command-like query parameter. A single
	// such request is LOW/MEDIUM confidence by itself (ordinary legitimate
	// applications serve .php/.jsp all day); confidence only escalates
	// with corroborating evidence -- Phase 1/2's FIM/Binary-Integrity/
	// Process findings on the same host within the correlation window
	// (see the Phase 3 correlation wiring in engine_web_security.go).
	IncidentWebShellIndicator IncidentType = "web_shell_indicator"

	// IncidentSSRFIndicator: a request whose PATH OR QUERY STRING (the
	// only per-request fields VANGUARD's log format exposes -- request
	// bodies are never logged, so body-based SSRF payloads are simply
	// invisible to this detector, and that limitation is real, not a
	// bug) contains a literal reference to a loopback, RFC1918/link-local
	// private address, or a well-known cloud metadata endpoint
	// (169.254.169.254). Indicator-only: VANGUARD cannot confirm the
	// backend application actually issued the resulting internal
	// request, only that a client asked it to.
	IncidentSSRFIndicator IncidentType = "ssrf_indicator"

	// IncidentOASTIndicator: a request whose path/query references an
	// external hostname that looks callback/interaction-oriented (a
	// long, high-entropy, single-use-looking subdomain of a domain not
	// otherwise seen from this source), OFTEN alongside (but not
	// required to have) an SSRF-indicator-shaped request in the same
	// short window from the same IP. VANGUARD has no DNS resolver log
	// and no outbound packet capture, so it can NEVER prove an
	// out-of-band interaction actually completed -- this is purely an
	// indicator that an attacker-supplied callback-shaped value appeared
	// in observed web traffic. That limitation is stated up front in
	// every finding's Details, never silently assumed away.
	IncidentOASTIndicator IncidentType = "oast_indicator"

	// IncidentHostHeaderAnomaly: a Host header value that does not match
	// any configured expected/allowed host (thresholds.ExpectedHosts),
	// is a bare IP address, targets a loopback/private address, uses an
	// unexpected port suffix, or a single source IP cycles through an
	// abnormal number of distinct Host values in a short window. Only
	// evaluated when Event.Host is non-empty -- the stock Nginx
	// "combined" log format most hosts run does not log Host at all, and
	// a missing Host field must never itself be treated as suspicious
	// (see WebLogParser's doc comment).
	IncidentHostHeaderAnomaly IncidentType = "host_header_anomaly"

	// IncidentHTTPProtocolAnomaly: a source IP generating an abnormal
	// rate of malformed/unsupported-method requests, non-standard
	// protocol version tokens, or a burst of 400/414/431 responses
	// within a bounded window. A single 400 is never itself an incident
	// (broken clients and normal scanners produce these constantly) --
	// only sustained frequency from one IP counts.
	IncidentHTTPProtocolAnomaly IncidentType = "http_protocol_anomaly"

	// IncidentRequestSmugglingIndicator: an INDICATOR-ONLY detector.
	// VANGUARD's log-line-based visibility cannot see raw
	// Content-Length/Transfer-Encoding header values at all (the
	// standard Nginx/Apache access-log formats never log request
	// headers), so this can only ever watch for the downstream SYMPTOM
	// visible in status-code sequences: an abnormal burst of
	// 400/408/502/503 responses from one source in a short window,
	// which is consistent with -- but nowhere near proof of -- a
	// smuggling attempt against a front-end/back-end pair. This
	// limitation is documented in the finding's Details on every
	// occurrence, never hidden.
	IncidentRequestSmugglingIndicator IncidentType = "request_smuggling_indicator"

	// IncidentAPIAbuse: endpoint-aware anomaly detection layered on top
	// of (never duplicating) the existing Web Scanner Behavior / HTTP
	// Flood / Web Dir Scan rules -- one source IP touching an abnormal
	// number of DISTINCT paths, with a high 401/403/404 ratio, within a
	// bounded window (endpoint enumeration / credential-stuffing-
	// adjacent API probing), which is qualitatively different evidence
	// than either "many requests to ONE path" (HTTP Flood) or "many 404s
	// on a small fixed sensitive-path list" (Web Dir Scan).
	IncidentAPIAbuse IncidentType = "api_abuse"

	// --- System Posture & Drift Detection (VANGUARD Mega Expansion,
	// Phase 4). All four signatures below are host-local findings
	// (SourceIP=HostLocalIP, same rationale as every Phase 1/2 hostsec
	// incident type above) produced by internal/hostsec's periodic
	// scanners and routed through the identical ReportHostFinding ->
	// createIncident() pipeline -- no new incident plumbing, only four
	// new type labels. ---

	// IncidentConfigurationPosture: a single point-in-time posture check
	// (dangerous filesystem permissions, unexpected sensitive-file
	// ownership, or a bounded service-configuration check) found the
	// CURRENT state to already be unsafe, independent of whether it has
	// ever changed. This is an "is this currently dangerous" signal, not
	// a "did this change" signal -- see IncidentConfigurationDrift for
	// the latter. A missing optional monitored path is never itself a
	// posture finding (see hostsec/posture.go).
	IncidentConfigurationPosture IncidentType = "configuration_posture"

	// IncidentConfigurationDrift: a monitored configuration
	// resource's baseline-comparable state (existence, mode, owner,
	// group, content hash or size when hashing was skipped) changed
	// since the last-known-good baseline. Distinct from
	// IncidentConfigurationPosture: drift says "this changed", posture
	// says "this is currently unsafe" -- a resource can drift into a
	// perfectly safe new state (no posture finding) or drift into an
	// unsafe one (both fire, independently, from their own detectors).
	// First-observation (cold-start baseline establishment) never fires
	// this; only a genuine change relative to an established baseline
	// does.
	IncidentConfigurationDrift IncidentType = "configuration_drift"

	// IncidentListeningServiceDrift: the set of listening (not
	// transient/connected) sockets observed via /proc/net/{tcp,tcp6,udp,
	// udp6} changed relative to the established baseline -- a new
	// listener appeared, a previously-seen one disappeared, or an
	// existing one's protocol/bind-address/port/owning-process changed.
	// A configurable baseline-initialization grace period (see
	// thresholds.ListeningServiceGracePeriod) prevents a storm of
	// "new listener" findings during VANGUARD's own startup window.
	IncidentListeningServiceDrift IncidentType = "listening_service_drift"

	// IncidentPackageDrift: the dpkg package inventory (name+architecture
	// identity, version, install state) changed relative to the
	// established baseline -- installed, removed, or version/state
	// changed. Never fires for the bulk first-scan inventory itself,
	// only for an actual delta on a later scan. Self-disables
	// gracefully (no incidents, no fabricated "all packages removed")
	// when /var/lib/dpkg/status is unavailable or unparseable -- see
	// hostsec/package_drift.go.
	IncidentPackageDrift IncidentType = "package_drift"

	// IncidentIOCMatch (Phase 6): an observed value (source address, Host,
	// URL, or file SHA-256) exactly matched an active local threat
	// indicator. A direct, exact match only -- it says the observation was
	// listed by a feed, not that the host is compromised or who the actor is.
	IncidentIOCMatch IncidentType = "ioc_match"
)

// HostLocalIP is the sentinel SourceIP value used for every host-security
// incident (FIM, Persistence, Privilege Escalation, Account, SUID/SGID) --
// see the doc comment on IncidentFIMChange above for the full rationale.
const HostLocalIP = "127.0.0.1"

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

	// --- Self-telemetry: VANGUARD's OWN process footprint, not the host's. ---
	// Sampled alongside the host-wide fields above on the same tick so the
	// dashboard can prove the "single ~25MB binary, near-zero overhead"
	// claim with real numbers instead of marketing copy. CPU comes from a
	// gopsutil process.Process handle scoped to our own PID; memory comes
	// from the Go runtime's own accounting (runtime.ReadMemStats), per the
	// explicit design requirement -- see internal/metrics/self_sampler.go.
	SelfCPUPercent    float64 `gorm:"not null;default:0" json:"self_cpu_percent"`
	SelfMemoryAllocMB uint64  `gorm:"not null;default:0" json:"self_memory_alloc_mb"`
	SelfMemorySysMB   uint64  `gorm:"not null;default:0" json:"self_memory_sys_mb"`
	SelfGoroutines    int     `gorm:"not null;default:0" json:"self_goroutines"`
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

	IncidentID *uint `gorm:"index" json:"incident_id,omitempty"`

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

// ---------------------------------------------------------------------------
// HostFileBaseline (Host Security, Phase 1)
// ---------------------------------------------------------------------------

// HostBaselineCategory partitions the single HostFileBaseline table by
// scanner, so FIM / Persistence / Account / SUID-SGID each own a disjoint
// key space (Category, Key) without needing four near-identical tables.
type HostBaselineCategory string

const (
	// BaselineFIM: Category=fim, Key=absolute file path. One row per
	// path in the FIM watch list (see hostsec.DefaultFIMPaths).
	BaselineFIM HostBaselineCategory = "fim"
	// BaselinePersistence: Category=persistence, Key=a stable identifier
	// for one persistence entry (e.g. "cron:/etc/crontab:0", "authorized_keys:testuser:<key-fingerprint>",
	// "systemd:ssh.service"). See hostsec/persistence.go for exact key shapes.
	BaselinePersistence HostBaselineCategory = "persistence"
	// BaselineAccount: Category=account, Key="user:<name>" or "group:<name>".
	BaselineAccount HostBaselineCategory = "account"
	// BaselineSUID: Category=suid, Key=absolute binary path. One row per
	// SUID/SGID binary found on the host filesystem.
	BaselineSUID HostBaselineCategory = "suid"
	// BaselinePrivEsc: Category=privesc, Key=a stable identifier for one
	// privilege-escalation-relevant fact (e.g. "group_member:sudo:alice",
	// "uid0:root", "sudoers_rule:<hash>", "root_proc:<exe-path>"). See
	// hostsec/privesc.go for exact key shapes.
	BaselinePrivEsc HostBaselineCategory = "privesc"
	// BaselineSystemBinary: Category=system_binary, Key=absolute binary
	// path. One row per path in the System Binary Integrity watch list
	// (Phase 2, feature 8) -- kept as its own category (rather than
	// reusing BaselineFIM) since it is a distinct feature/incident type
	// per the mega-prompt's explicit split between config-file FIM and
	// executable integrity.
	BaselineSystemBinary HostBaselineCategory = "system_binary"
	// BaselineProcess: Category=process, Key=a stable identifier for one
	// process-anomaly-relevant fact (e.g. "deleted_exe:/tmp/x",
	// "unusual_dir:/dev/shm/payload", "parent_child:nginx:bash"). See
	// hostsec/process.go for exact key shapes. Deliberately dedupes on
	// the underlying FACT (a specific exe path, or a specific
	// parent/child executable pairing) rather than on ephemeral PID, so
	// the same short-lived process pattern recurring doesn't flood
	// incidents once it has already been reported.
	BaselineProcess HostBaselineCategory = "process"

	// --- System Posture & Drift Detection (VANGUARD Mega Expansion,
	// Phase 4). Four new disjoint key spaces in the SAME HostFileBaseline
	// table -- no second storage engine, no new tables, per the
	// mega-prompt's explicit "reuse the existing baseline abstraction"
	// requirement. ---

	// BaselineConfigPosture: Category=config_posture, Key="<check_id>:<path>".
	// One row per (posture check, monitored path) pair, storing the
	// most recently observed/expected/severity state purely so repeated
	// identical findings can be deduped -- NOT a "did it change" diff
	// (that is BaselineConfigDrift's job). See hostsec/posture.go.
	BaselineConfigPosture HostBaselineCategory = "config_posture"

	// BaselineConfigDrift: Category=config_drift, Key=absolute resource
	// path. One row per monitored configuration resource, storing a
	// fileMeta-shaped snapshot (existence/mode/uid/gid/size/hash, with
	// hash omitted and HashSkipped=true above the configured size
	// limit). See hostsec/config_drift.go.
	BaselineConfigDrift HostBaselineCategory = "config_drift"

	// BaselineListeningService: Category=listening_service, a single
	// atomic snapshot row (Key="snapshot") holding the whole bounded
	// listening-socket inventory keyed by a stable normalized identity
	// ("<protocol>:<address>:<port>", e.g. "tcp:0.0.0.0:22" or
	// "tcp6:[::]:22" -- deliberately NOT merged across address
	// families, see hostsec/listening.go's normalization doc comment).
	// One row (not one per socket) so a baseline update is atomic.
	BaselineListeningService HostBaselineCategory = "listening_service"

	// BaselinePackage: Category=package, a single atomic snapshot row
	// (Key="snapshot") holding the bounded dpkg inventory keyed by
	// "<name>:<architecture>". See hostsec/package_drift.go.
	BaselinePackage HostBaselineCategory = "package"
)

// HostFileBaseline is a single last-known-good snapshot used by the Host
// Security scanners (FIM, Persistence, Account, SUID/SGID) to diff the
// current system state against on every scan tick. Persisted (rather than
// held only in memory, like the network-detection State/ChainTracker in
// internal/detection) because these scans are periodic and infrequent
// (minutes, not per-request) -- an in-memory-only baseline would be lost on
// every VANGUARD restart and spuriously re-report every watched path as
// "created" on the first post-restart scan, which is exactly the kind of
// noisy false positive Phase 16 (False Positive Protection) forbids.
//
// Content is a small free-form JSON blob (hash/size/mode/owner/group/extra
// scanner-specific fields) rather than dedicated columns, mirroring
// Incident.Metadata's own "schema never needs an ALTER TABLE for a new
// scanner field" rationale.
type HostFileBaseline struct {
	ID uint `gorm:"primaryKey" json:"id"`

	Category HostBaselineCategory `gorm:"size:32;not null;uniqueIndex:idx_hostbaseline_cat_key,priority:1" json:"category"`
	Key      string               `gorm:"size:512;not null;uniqueIndex:idx_hostbaseline_cat_key,priority:2" json:"key"`

	Content string `gorm:"type:text" json:"content"`

	LastSeenAt time.Time `gorm:"not null" json:"last_seen_at"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
}

// SetContent marshals v into the Content column as JSON.
func (h *HostFileBaseline) SetContent(v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	h.Content = string(b)
	return nil
}

// GetContent unmarshals the Content column into v. Returns nil (no-op) if
// Content is empty.
func (h *HostFileBaseline) GetContent(v any) error {
	if h.Content == "" {
		return nil
	}
	return json.Unmarshal([]byte(h.Content), v)
}

// AllModels returns every struct that must be migrated by AutoMigrate, in a
// safe dependency order.
func AllModels() []any {
	return []any{
		&User{},
		&SystemMetric{},
		&Incident{},
		&FirewallRule{},
		&HostFileBaseline{},
		&IncidentEvent{},
		&IOC{},
		&IOCImport{},
		&IOCMatch{},
		&IncidentNote{},
		&RuleTuningRevision{},
		&BackupAudit{},
	}
}

// compile-time assurance the gorm import is used even if models above change.
var _ = gorm.ErrRecordNotFound
