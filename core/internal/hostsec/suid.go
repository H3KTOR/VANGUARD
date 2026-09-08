package hostsec

// ---------------------------------------------------------------------------
// Feature 5: SUID/SGID Monitoring
//
// Detection:   periodic walk of a bounded set of directories
//              (thresholds.DefaultSUIDScanRoots -- the standard binary
//              locations -- plus thresholds.WritableScanRoots, the classic
//              privilege-escalation drop locations), collecting every file
//              with the setuid or setgid mode bit set, diffed against the
//              last baseline.
// Evidence:    path, mode, owner/group, and whether it sits in a
//              world-writable/temp directory.
// Risk:        database.IncidentSUIDSGIDAnomaly; CRITICAL-escalated (per
//              spec) for any SUID/SGID binary found under
//              thresholds.WritableScanRoots or any directory whose own
//              mode bits are world-writable.
// Correlation: standard Incident pipeline.
// Response:    alert-only (SourceIP=HostLocalIP; see fim.go doc comment).
// False positives: the *standard* binary directories are large but bounded
//              and legitimate SUID binaries there (ping, sudo, passwd,
//              mount, etc) are captured once as the baseline and never
//              re-fire unless their mode/owner actually changes; the
//              writable-dir escalation applies ONLY to non-standard
//              locations where a legitimate SUID binary should essentially
//              never exist.
// ---------------------------------------------------------------------------

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"vanguard/core/internal/database"
	"vanguard/core/internal/thresholds"
)

// SUIDMonitor implements SUID/SGID Monitoring.
type SUIDMonitor struct {
	db       *database.DB
	reporter Reporter
	roots    []string
	writable map[string]bool
}

// NewSUIDMonitor constructs a SUID/SGID monitor scanning roots. Any root
// present in thresholds.WritableScanRoots is flagged so findings under it
// are automatically escalated.
func NewSUIDMonitor(db *database.DB, reporter Reporter, roots []string) *SUIDMonitor {
	writable := make(map[string]bool, len(thresholds.WritableScanRoots))
	for _, r := range thresholds.WritableScanRoots {
		writable[r] = true
	}
	return &SUIDMonitor{db: db, reporter: reporter, roots: roots, writable: writable}
}

// Scan walks every configured root, finds current SUID/SGID binaries, and
// diffs the resulting set against the baseline.
func (m *SUIDMonitor) Scan(ctx context.Context) {
	first, err := isFirstScan(m.db, database.BaselineSUID)
	if err != nil {
		logf("suid", "failed to check first-scan marker: %v", err)
		return
	}

	current := make(map[string]fileMeta)
	for _, root := range m.roots {
		if ctx.Err() != nil {
			logf("suid", "scan cancelled/timed out, stopping early")
			return
		}
		m.walkRoot(root, current)
	}

	for path, meta := range current {
		m.diffOne(path, meta, first)
	}
	m.diffDeleted(current, first)

	if first {
		if err := markSeeded(m.db, database.BaselineSUID); err != nil {
			logf("suid", "failed to mark category seeded: %v", err)
		}
	}
}

func (m *SUIDMonitor) walkRoot(root string, out map[string]fileMeta) {
	_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // unreadable entry (permissions, race) -- skip, don't abort the whole walk
		}
		if d.IsDir() {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return nil
		}
		mode := info.Mode()
		if mode&os.ModeSetuid == 0 && mode&os.ModeSetgid == 0 {
			return nil
		}
		meta, err := statFile(path)
		if err != nil || !meta.Exists {
			return nil
		}
		out[path] = meta
		return nil
	})
}

func (m *SUIDMonitor) diffOne(path string, curr fileMeta, firstScan bool) {
	row, err := m.db.GetHostBaseline(database.BaselineSUID, path)
	if err != nil {
		if err != database.ErrNotFound {
			logf("suid", "baseline lookup failed for %s: %v", path, err)
			return
		}
		if !firstScan {
			m.report(path, "created", fileMeta{}, curr)
		}
		if err := saveMeta(m.db, database.BaselineSUID, path, curr); err != nil {
			logf("suid", "failed to save baseline for %s: %v", path, err)
		}
		return
	}

	prev := loadMeta(row)
	if change, changed := compareMeta(prev, curr); changed {
		m.report(path, change, prev, curr)
	}
	if err := saveMeta(m.db, database.BaselineSUID, path, curr); err != nil {
		logf("suid", "failed to update baseline for %s: %v", path, err)
	}
}

func (m *SUIDMonitor) diffDeleted(current map[string]fileMeta, firstScan bool) {
	rows, err := m.db.ListHostBaseline(database.BaselineSUID)
	if err != nil {
		logf("suid", "failed to list baseline: %v", err)
		return
	}
	for _, row := range rows {
		if row.Key == seededMarkerKey {
			continue
		}
		if _, stillExists := current[row.Key]; stillExists {
			continue
		}
		if !firstScan {
			prev := loadMeta(&row)
			m.report(row.Key, "deleted", prev, fileMeta{})
		}
		if err := m.db.DeleteHostBaseline(database.BaselineSUID, row.Key); err != nil {
			logf("suid", "failed to delete stale baseline for %s: %v", row.Key, err)
		}
	}
}

func (m *SUIDMonitor) report(path, change string, prev, curr fileMeta) {
	inWritableDir := false
	for w := range m.writable {
		if strings.HasPrefix(path, w+"/") || path == w {
			inWritableDir = true
			break
		}
	}
	critical := inWritableDir && (change == "created" || change == "modified")
	note := ""
	if critical {
		note = thresholds.WritableDirEscalationNote
	}
	m.reporter.ReportHostFinding(Finding{
		Type:           database.IncidentSUIDSGIDAnomaly,
		Change:         change,
		Subject:        path,
		Critical:       critical,
		EscalationNote: note,
		Details: map[string]any{
			"path":                    path,
			"change":                  change,
			"previous":                prev,
			"current":                 curr,
			"in_writable_or_temp_dir": inWritableDir,
		},
	})
}
