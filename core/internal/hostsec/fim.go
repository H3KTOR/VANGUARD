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
// Correlation: flows into the same Incident pipeline as every other rule,
//              so it is visible to ChainTracker-adjacent future correlation
//              work (Phase 2) with zero extra plumbing.
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
// ---------------------------------------------------------------------------

import (
	"context"
	"os"
	"path/filepath"

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

// FIMWatcher implements File Integrity Monitoring.
type FIMWatcher struct {
	db       *database.DB
	reporter Reporter
	paths    []string
}

// NewFIMWatcher constructs a FIM scanner over paths (each may be a file or
// a directory; directories are scanned one level deep, matching the
// mega-prompt's watch-list, e.g. /etc/systemd/system as a directory of
// unit files rather than a single file).
func NewFIMWatcher(db *database.DB, reporter Reporter, paths []string) *FIMWatcher {
	return &FIMWatcher{db: db, reporter: reporter, paths: paths}
}

// Scan performs one full pass: expand every configured path (resolving
// directories to their direct children), diff each against its baseline,
// report a Finding for every real change, and persist the new baseline
// regardless of whether a change was found (so a legitimate, expected
// modification doesn't re-fire on the next tick).
func (w *FIMWatcher) Scan(ctx context.Context) {
	first, err := isFirstScan(w.db, database.BaselineFIM)
	if err != nil {
		logf("fim", "failed to check first-scan marker: %v", err)
		return
	}

	targets := w.expandTargets()
	for _, path := range targets {
		if ctx.Err() != nil {
			logf("fim", "scan cancelled/timed out, stopping early")
			return
		}
		w.scanOne(path, first)
	}

	if first {
		if err := markSeeded(w.db, database.BaselineFIM); err != nil {
			logf("fim", "failed to mark category seeded: %v", err)
		}
	}
}

// expandTargets turns w.paths (a mix of files and directories) into a flat
// list of concrete file paths to snapshot. Directories are read one level
// deep only -- this matches every mega-prompt FIM target (a flat directory
// of unit files/cron fragments), and deliberately avoids an unbounded
// recursive walk of e.g. an entire /etc tree.
func (w *FIMWatcher) expandTargets() []string {
	seen := make(map[string]bool)
	var out []string
	add := func(p string) {
		if !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	for _, p := range w.paths {
		info, err := os.Stat(p)
		if err != nil {
			// Doesn't exist right now -- still track it (as a
			// zero-value baseline) so its *creation* is detected.
			add(p)
			continue
		}
		if !info.IsDir() {
			add(p)
			continue
		}
		entries, err := os.ReadDir(p)
		if err != nil {
			logf("fim", "failed to read directory %s: %v", p, err)
			continue
		}
		for _, e := range entries {
			add(filepath.Join(p, e.Name()))
		}
	}
	return out
}

func (w *FIMWatcher) scanOne(path string, firstScan bool) {
	curr, err := statFile(path)
	if err != nil {
		logf("fim", "failed to stat %s: %v", path, err)
		return
	}

	row, err := w.db.GetHostBaseline(database.BaselineFIM, path)
	var prev fileMeta
	haveBaseline := false
	if err == nil {
		prev = loadMeta(row)
		haveBaseline = true
	} else if err != database.ErrNotFound {
		logf("fim", "failed to load baseline for %s: %v", path, err)
		return
	}

	if !haveBaseline {
		// First time this exact path has ever been seen. On the
		// category's very first scan ever, silently establish the
		// baseline (no incident for pre-existing files -- otherwise
		// every fresh VANGUARD install would instantly "detect" every
		// watched file as newly created). On any LATER scan, a
		// brand-new baseline row means the path genuinely appeared
		// for the first time since VANGUARD started watching it.
		if !firstScan && curr.Exists {
			w.report(path, "created", fileMeta{}, curr)
		}
		if err := saveMeta(w.db, database.BaselineFIM, path, curr); err != nil {
			logf("fim", "failed to save baseline for %s: %v", path, err)
		}
		return
	}

	change, changed := compareMeta(prev, curr)
	if changed {
		w.report(path, change, prev, curr)
	}
	if err := saveMeta(w.db, database.BaselineFIM, path, curr); err != nil {
		logf("fim", "failed to update baseline for %s: %v", path, err)
	}
}

func (w *FIMWatcher) report(path, change string, prev, curr fileMeta) {
	critical := criticalFIMPaths[path]
	note := ""
	if critical {
		note = "change to a highest-value credential/access-control target (" + path + ")"
	}
	w.reporter.ReportHostFinding(Finding{
		Type:           database.IncidentFIMChange,
		Change:         change,
		Subject:        path,
		Critical:       critical,
		EscalationNote: note,
		Details: map[string]any{
			"path":            path,
			"change":          change,
			"previous":        prev,
			"current":         curr,
			"watched_targets": "sensitive system files/dirs (passwd, shadow, sudoers, sshd_config, authorized_keys, crontab, systemd units)",
		},
	})
}
