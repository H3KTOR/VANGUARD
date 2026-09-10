package hostsec

// ---------------------------------------------------------------------------
// Feature 8: System Binary Integrity
//
// Detection:   periodic SHA-256 + size + mode + owner + group snapshot of a
//              small, bounded, configurable list of security-critical
//              system binaries (thresholds.DefaultSystemBinaryPaths),
//              diffed against the last-known-good baseline in SQLite.
//              Deliberately does NOT hash an entire filesystem tree (e.g.
//              every file under /bin) by default -- per the mega-prompt's
//              explicit "do not hash the entire filesystem by default...
//              use configurable paths and resource limits" instruction.
// Evidence:    the changed field name(s), previous vs. current metadata.
// Risk:        database.IncidentSystemBinaryIntegrity base severity (see
//              risk.BaseSeverity) -- HIGH tier, since a replaced
//              security-critical binary (sudo, sshd, su, passwd, sh...)
//              is one of the strongest possible post-compromise
//              indicators VANGUARD can observe.
// Correlation: flows into the same Incident pipeline as every other rule;
//              feeds internal/detection's ProcessNetCorrelator (feature 7)
//              exactly like FIM does.
// Response:    alert-only (SourceIP=HostLocalIP is always whitelisted --
//              see database.IncidentFIMChange's doc comment for the
//              shared rationale; there is no attacker IP to ban for a
//              host-local finding).
// False positives: a legitimate package upgrade (e.g. `apt upgrade
//              openssh-server`) will show up as a single "modified"
//              finding, not a flood, since the baseline is updated after
//              every scan regardless of whether an incident fired.
//              Operators upgrading a watched binary should expect (and
//              can safely acknowledge) exactly one finding per upgrade.
//
// Implementation note: reuses the exact same pathBaselineWatcher engine as
// FIM (see fim.go's doc comment and path_watcher.go) -- this is a distinct
// *configuration* of that engine (different target list, baseline
// category, incident type), not a second detection engine.
// ---------------------------------------------------------------------------

import (
	"context"

	"vanguard/core/internal/database"
)

// BinaryIntegrityWatcher implements System Binary Integrity monitoring.
type BinaryIntegrityWatcher struct {
	w *pathBaselineWatcher
}

// NewBinaryIntegrityWatcher constructs a System Binary Integrity scanner
// over paths (a bounded list of individual executable files -- unlike
// FIM's watch list, these are never directories, since "hash an entire
// bin directory" is exactly the unbounded behavior the mega-prompt
// prohibits by default).
func NewBinaryIntegrityWatcher(db *database.DB, reporter Reporter, paths []string) *BinaryIntegrityWatcher {
	return &BinaryIntegrityWatcher{w: &pathBaselineWatcher{
		db:           db,
		reporter:     reporter,
		paths:        paths,
		category:     database.BaselineSystemBinary,
		incidentType: database.IncidentSystemBinaryIntegrity,
		scannerName:  "binary_integrity",
		watchedNote:  "security-critical system binaries (sh, bash, sudo, su, sshd, passwd, ssh, curl, wget, nc)",
	}}
}

// Scan performs one full Binary Integrity pass. See
// pathBaselineWatcher.Scan for the shared mechanics.
func (w *BinaryIntegrityWatcher) Scan(ctx context.Context) { w.w.Scan(ctx) }
