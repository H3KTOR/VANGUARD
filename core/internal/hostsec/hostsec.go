// Package hostsec implements VANGUARD's Host Security scanners (Mega
// Expansion, Phase 1): File Integrity Monitoring, Persistence Detection,
// Account Manipulation Detection, Privilege Escalation Detection, and
// SUID/SGID Monitoring.
//
// Architectural notes (Non-Negotiable Rules #1 and #3):
//   - Zero external dependencies: every scanner uses only the Go standard
//     library (os, io/fs, path/filepath, crypto/sha256, syscall) plus
//     VANGUARD's own internal/database package for baseline persistence.
//   - No eBPF / kernel modules: detection relies entirely on periodic
//     filesystem inspection, /etc config parsing, and best-effort /proc
//     walks. Anything this constraint makes inherently incomplete is
//     explicitly labeled BEST-EFFORT DETECTION in its own doc comment
//     (see privesc.go's root-process check).
//   - Linux-only: this package uses syscall.Stat_t to read file
//     owner/group, which is a Linux/Unix-specific API. This matches the
//     project's stated production target (systemd on Linux) and is
//     consistent with the rest of the codebase (e.g. UFW/iptables,
//     /var/log/auth.log tailing) already being Linux-only.
//
// Every scanner follows the same Detection -> Evidence -> Risk pipeline
// shape: periodically walk its target (files/config/proc), diff against a
// SQLite-persisted baseline (internal/database.HostFileBaseline), and for
// every actual state change call Reporter.ReportHostFinding with enough
// evidence for the caller (internal/detection.Engine) to score risk and
// persist an Incident through the existing createIncident() choke point --
// per the mega-prompt's explicit "never create duplicate detection
// engines" rule, hostsec does NOT persist Incidents itself.
package hostsec

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log"
	"os"
	"strings"
	"time"

	"vanguard/core/internal/database"
)

// Finding is the evidence package a scanner hands to a Reporter for a
// single detected change. It intentionally carries a database.IncidentType
// rather than a hostsec-local enum, so the detection engine can route it
// straight into risk.Score()/createIncident() with no translation layer.
type Finding struct {
	// Type is the IncidentType this finding should be raised as.
	Type database.IncidentType

	// Change is a short machine-readable label: "created", "deleted",
	// "modified", "perm_changed", "owner_changed", "group_changed", or a
	// scanner-specific label (e.g. "dangerous_sudo_rule").
	Change string

	// Subject is the human-readable identity of what changed (a file
	// path, "user:alice", "group:sudo", a systemd unit name, etc).
	Subject string

	// Critical, when true, tells the caller to apply a hard policy
	// escalation (risk.Input.Escalate) regardless of the base severity --
	// used for e.g. a SUID binary dropped into a world-writable
	// directory, which is CRITICAL by definition per the spec.
	Critical bool
	// EscalationNote documents *why* Critical is set, surfaced in the
	// incident's risk breakdown explanation.
	EscalationNote string

	// BestEffort marks findings from a detector that cannot be fully
	// reliable under the no-eBPF/no-kernel-module constraint (currently
	// the PrivEsc scanner's root-process check and the whole of Feature 6,
	// Process Anomaly Detection). Surfaced in Details so the
	// dashboard/analyst can weight confidence accordingly.
	BestEffort bool

	// RemoteAddrs carries any outbound "ip:port" connections discovered
	// for the subject of this finding (currently populated only by
	// Feature 6's ProcessDetector, from its best-effort /proc/net/tcp
	// association -- see process.go's ProcessInfo.RemoteAddrs). Consumed
	// by Feature 7's correlateHostFinding to check each address against
	// Threat Intelligence. Empty for every other scanner.
	RemoteAddrs []string

	// SHA256 lists file hashes VANGUARD itself computed for this finding
	// (FIM / binary integrity / config drift), for exact IOC matching.
	SHA256 []string

	// RiskAdjust is a signed contextual adjustment applied on top of the
	// incident type's base severity (Phase 4: e.g. a loopback-only
	// listener is -15, an all-interface listener on a privileged port is
	// +25). Zero for every Phase 1-3 scanner. Unlike Critical it never
	// implies a fixed +25 escalation, letting a detector express graded
	// context rather than a binary "escalate / don't".
	RiskAdjust int

	// Details carries every other scanner-specific field (previous/
	// current hash, mode, uid/gid, matched line, etc) for the incident's
	// Metadata JSON blob.
	Details map[string]any
}

// Reporter receives every Finding a scanner produces. internal/detection's
// Engine implements this (see engine_hostsec.go) by routing straight into
// the same createIncident() choke point every log-driven rule already
// uses, so host-security incidents get identical risk scoring, dashboard
// visibility, and (where applicable) Autopilot handling with zero
// duplicated persistence/notification logic.
type Reporter interface {
	ReportHostFinding(f Finding)
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

// seededMarkerKey is a reserved baseline key (per category) that records
// whether a category's very first scan has already completed. This is
// what lets every scanner distinguish "cold start, seed every currently-
// existing entry silently" from "category already established, a
// never-before-seen key showing up now is a genuine CREATED event" -- see
// the package doc comment and each scanner's diff logic.
const seededMarkerKey = "__seeded__"

// isFirstScan reports whether category has never completed an initial
// baseline pass (i.e. VANGUARD just started against a fresh/empty DB, or
// this scanner category was just enabled for the first time).
func isFirstScan(db *database.DB, category database.HostBaselineCategory) (bool, error) {
	_, err := db.GetHostBaseline(category, seededMarkerKey)
	if err == nil {
		return false, nil
	}
	if errors.Is(err, database.ErrNotFound) {
		return true, nil
	}
	return false, err
}

// markSeeded records that category's first scan has completed.
func markSeeded(db *database.DB, category database.HostBaselineCategory) error {
	return db.UpsertHostBaseline(category, seededMarkerKey, `{"seeded_at":"`+time.Now().UTC().Format(time.RFC3339)+`"}`)
}

// shortHash returns a short, stable hex digest of s, used to build
// baseline keys for line-oriented config entries (cron lines, sudoers
// rules, SSH authorized_keys entries) where the line content itself --
// not a file path -- is the natural identity of "this specific entry".
func shortHash(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])[:16]
}

// fileMeta is the comparable snapshot of a single filesystem path used by
// both the FIM and SUID/SGID scanners.
type fileMeta struct {
	Exists bool   `json:"exists"`
	Hash   string `json:"hash,omitempty"`
	Size   int64  `json:"size"`
	Mode   string `json:"mode,omitempty"`
	UID    uint32 `json:"uid"`
	GID    uint32 `json:"gid"`
}

// statFile stats (never follows symlinks -- Lstat) and, for regular files,
// hashes path. A missing path is not an error: it yields
// fileMeta{Exists: false}, letting callers treat "doesn't exist (yet, or
// anymore)" uniformly rather than special-casing os.IsNotExist everywhere.
func statFile(path string) (fileMeta, error) {
	info, err := os.Lstat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return fileMeta{Exists: false}, nil
		}
		return fileMeta{}, err
	}
	m := fileMeta{Exists: true, Size: info.Size(), Mode: info.Mode().String()}
	if uid, gid, ok := ownerOf(info); ok {
		m.UID = uid
		m.GID = gid
	}
	if info.Mode().IsRegular() {
		if h, err := hashFile(path); err == nil {
			m.Hash = h
		}
		// A hashing failure (e.g. permission denied on a file we can
		// stat but not read, such as /etc/shadow for a non-root
		// process) is deliberately non-fatal: metadata-only comparison
		// (size/mode/owner/group) still works, matching the mega-
		// prompt's explicit note that /etc/shadow is monitored for
		// "SHA-256/size/perms/owner/group/mtime" -- hash is one signal
		// among several, not a hard requirement.
	}
	return m, nil
}

// hashFile computes the SHA-256 digest of a regular file's contents.
func hashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// compareMeta diffs two fileMeta snapshots and returns the single most
// significant change label, in priority order matching the mega-prompt's
// feature-1 spec: existence changes first, then content, then metadata.
func compareMeta(prev, curr fileMeta) (change string, changed bool) {
	switch {
	case !prev.Exists && curr.Exists:
		return "created", true
	case prev.Exists && !curr.Exists:
		return "deleted", true
	case !prev.Exists && !curr.Exists:
		return "", false
	case curr.Hash != "" && prev.Hash != "" && prev.Hash != curr.Hash:
		return "modified", true
	case prev.Size != curr.Size && curr.Hash == "":
		// Only reachable for non-regular-file / unreadable entries where
		// we have no hash to compare, e.g. a directory's own size or a
		// file we couldn't open -- size is the next-best signal.
		return "modified", true
	case prev.Mode != curr.Mode:
		return "perm_changed", true
	case prev.UID != curr.UID:
		return "owner_changed", true
	case prev.GID != curr.GID:
		return "group_changed", true
	default:
		return "", false
	}
}

// saveMeta upserts a fileMeta baseline row.
func saveMeta(db *database.DB, category database.HostBaselineCategory, key string, m fileMeta) error {
	return saveJSON(db, category, key, m)
}

// saveJSON marshals v and upserts it as the baseline row for
// (category, key). Generic helper shared by every scanner that stores a
// structured (non-fileMeta) snapshot, e.g. account.go's passwdEntry/
// groupEntry or privesc.go's group-membership records.
func saveJSON(db *database.DB, category database.HostBaselineCategory, key string, v any) error {
	b := &database.HostFileBaseline{}
	if err := b.SetContent(v); err != nil {
		return err
	}
	return db.UpsertHostBaseline(category, key, b.Content)
}

// loadMeta reads back a fileMeta baseline row previously saved by saveMeta.
func loadMeta(row *database.HostFileBaseline) fileMeta {
	var m fileMeta
	_ = row.GetContent(&m)
	return m
}

// truncate bounds s to at most n runes, appending an ellipsis marker when
// truncated, so a Finding's Details can never balloon incident storage
// with e.g. an entire multi-KB config file's contents (Phase 12/13:
// bounded storage growth).
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "...(truncated)"
}

// nonComment reports whether line (already trimmed) is worth treating as a
// real config entry, i.e. not blank and not a '#'-comment.
func nonComment(line string) bool {
	t := strings.TrimSpace(line)
	return t != "" && !strings.HasPrefix(t, "#")
}

// logf is a tiny wrapper so every scanner logs with a consistent prefix.
func logf(scanner, format string, args ...any) {
	log.Printf("[hostsec:%s] "+format, append([]any{scanner}, args...)...)
}

// jsonOrEmpty is a small helper used where a Details value needs to be a
// pre-marshaled JSON string embedded as a map value (rare; most Details
// values are plain Go values marshaled naturally through the Incident's
// own Metadata JSON encoding).
func jsonOrEmpty(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return ""
	}
	return string(b)
}
