package hostsec

// ---------------------------------------------------------------------------
// Feature 1: File Integrity Monitoring (FIM)
//
// Detection:   periodic SHA-256 + size + mode + owner + group snapshot of a
//              configurable list of sensitive paths (thresholds.DefaultFIMPaths),
//              diffed against the last-known-good baseline in SQLite.
// Evidence:    the changed field name(s), previous vs. current metadata.
// Risk:        database.IncidentFIMChange base severity (see risk.BaseSeverity);
//              always Critical-escalated for /etc/shadow and
//              /root/.ssh/authorized_keys (highest-value targets) regardless
//              of *which* attribute changed.
// Correlation: flows into the same Incident pipeline as every other rule;
//              feeds internal/detection's ProcessNetCorrelator (Phase 2,
//              feature 7) as the "Sensitive File Activity" leg of
//              HIGH_CONFIDENCE_COMPROMISE via ReportHostFinding's Subject/
//              Change fields, with zero extra plumbing on this side.
// Response:    left to Autopilot's existing HandleIncident policy. Since
//              SourceIP=HostLocalIP is always whitelisted, this is
//              alert-only today -- see database.IncidentFIMChange doc
//              comment for the rationale (no attacker IP to ban).
// Verification: none automatic yet (host-security containment/verification
//              is Phase 10); the dashboard's generic incident feed is the
//              verification surface for now.
// False positives: a directory (e.g. /etc/systemd/system, /etc/cron.d)
//              is walked non-recursively for *direct* children only, and
//              every legitimate one-off system operation (e.g. `apt`
//              upgrading a package that happens to touch /etc/crontab)
//              will show up as a single "modified" finding rather than a
//              flood, since the baseline is updated after every scan
//              regardless of whether an incident fired (see Scan()).
//
// Implementation note: the actual scan/diff/baseline mechanics below are
// shared, byte-for-byte, with feature 8 (System Binary Integrity, see
// binary_integrity.go) via the internal pathBaselineWatcher type -- per
// the mega-prompt's "do not create duplicate detection engines" rule,
// FIM and Binary Integrity are two *configurations* (different target
// lists, baseline categories, incident types, and critical-path sets) of
// the exact same generic path-diffing engine, not two independent
// implementations of the same idea.
// ---------------------------------------------------------------------------

import (
	"context"

	"vanguard/core/internal/database"
)

// criticalFIMPaths are watched paths whose *any* change is escalated to
// CRITICAL outright -- these are the two single highest-value targets an
// attacker who has gained a foothold would touch to either read
// credentials (/etc/shadow) or plant durable SSH access
// (authorized_keys).
var criticalFIMPaths = map[string]bool{
	"/etc/shadow":                true,
	"/root/.ssh/authorized_keys": true,
}

// FIMWatcher implements File Integrity Monitoring. It is a thin,
// FIM-flavored configuration of the shared pathBaselineWatcher engine.
type FIMWatcher struct {
	w *pathBaselineWatcher
}

// NewFIMWatcher constructs a FIM scanner over paths (each may be a file or
// a directory; directories are scanned one level deep, matching the
// mega-prompt's watch-list, e.g. /etc/systemd/system as a directory of
// unit files rather than a single file).
func NewFIMWatcher(db *database.DB, reporter Reporter, paths []string) *FIMWatcher {
	return &FIMWatcher{w: &pathBaselineWatcher{
		db:            db,
		reporter:      reporter,
		paths:         paths,
		category:      database.BaselineFIM,
		incidentType:  database.IncidentFIMChange,
		scannerName:   "fim",
		criticalPaths: criticalFIMPaths,
		criticalNote:  "change to a highest-value credential/access-control target",
		watchedNote:   "sensitive system files/dirs (passwd, shadow, sudoers, sshd_config, authorized_keys, crontab, systemd units)",
	}}
}

// Scan performs one full FIM pass. See pathBaselineWatcher.Scan for the
// shared mechanics.
func (w *FIMWatcher) Scan(ctx context.Context) { w.w.Scan(ctx) }
