package hostsec

// path_watcher.go: the generic path-diffing engine shared by File
// Integrity Monitoring (feature 1, fim.go) and System Binary Integrity
// (feature 8, binary_integrity.go). Per the mega-prompt's "do not create
// duplicate detection engines" rule, both features are configurations of
// this single engine -- a target-list, a baseline category, an incident
// type, and an optional critical-path set -- not two independent
// implementations of "hash a file and diff it against a baseline".

import (
	"context"
	"os"
	"path/filepath"

	"vanguard/core/internal/database"
)

// pathBaselineWatcher periodically snapshots (statFile/fileMeta) every
// path in paths (expanding one-level-deep directories to their direct
// children), diffs each against database.HostFileBaseline, and reports a
// Finding for every real change -- created/deleted/modified/perm_changed/
// owner_changed/group_changed, per compareMeta's priority order.
type pathBaselineWatcher struct {
	db       *database.DB
	reporter Reporter
	paths    []string

	category     database.HostBaselineCategory
	incidentType database.IncidentType
	scannerName  string // log prefix, e.g. "fim" or "binary_integrity"

	// criticalPaths, when non-nil, escalates ANY change to a listed path
	// to Critical=true regardless of which attribute changed.
	criticalPaths map[string]bool
	criticalNote  string // EscalationNote suffix used when criticalPaths matches
	watchedNote   string // Details["watched_targets"] description
}

// Scan performs one full pass: expand every configured path, diff each
// against its baseline, report a Finding for every real change, and
// persist the new baseline regardless of whether a change was found (so
// a legitimate, expected modification doesn't re-fire on the next tick).
func (w *pathBaselineWatcher) Scan(ctx context.Context) {
	first, err := isFirstScan(w.db, w.category)
	if err != nil {
		logf(w.scannerName, "failed to check first-scan marker: %v", err)
		return
	}

	targets := w.expandTargets()
	for _, path := range targets {
		if ctx.Err() != nil {
			logf(w.scannerName, "scan cancelled/timed out, stopping early")
			return
		}
		w.scanOne(path, first)
	}

	if first {
		if err := markSeeded(w.db, w.category); err != nil {
			logf(w.scannerName, "failed to mark category seeded: %v", err)
		}
	}
}

// expandTargets turns w.paths (a mix of files and directories) into a
// flat list of concrete file paths to snapshot. Directories are read one
// level deep only, deliberately avoiding an unbounded recursive walk.
func (w *pathBaselineWatcher) expandTargets() []string {
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
			logf(w.scannerName, "failed to read directory %s: %v", p, err)
			continue
		}
		for _, e := range entries {
			add(filepath.Join(p, e.Name()))
		}
	}
	return out
}

func (w *pathBaselineWatcher) scanOne(path string, firstScan bool) {
	curr, err := statFile(path)
	if err != nil {
		logf(w.scannerName, "failed to stat %s: %v", path, err)
		return
	}

	row, err := w.db.GetHostBaseline(w.category, path)
	var prev fileMeta
	haveBaseline := false
	if err == nil {
		prev = loadMeta(row)
		haveBaseline = true
	} else if err != database.ErrNotFound {
		logf(w.scannerName, "failed to load baseline for %s: %v", path, err)
		return
	}

	if !haveBaseline {
		// First time this exact path has ever been seen. On the
		// category's very first scan ever, silently establish the
		// baseline (no incident for pre-existing files). On any LATER
		// scan, a brand-new baseline row means the path genuinely
		// appeared for the first time since VANGUARD started watching it.
		if !firstScan && curr.Exists {
			w.report(path, "created", fileMeta{}, curr)
		}
		if err := saveMeta(w.db, w.category, path, curr); err != nil {
			logf(w.scannerName, "failed to save baseline for %s: %v", path, err)
		}
		return
	}

	change, changed := compareMeta(prev, curr)
	if changed {
		w.report(path, change, prev, curr)
	}
	if err := saveMeta(w.db, w.category, path, curr); err != nil {
		logf(w.scannerName, "failed to update baseline for %s: %v", path, err)
	}
}

func (w *pathBaselineWatcher) report(path, change string, prev, curr fileMeta) {
	critical := w.criticalPaths != nil && w.criticalPaths[path]
	note := ""
	if critical {
		note = w.criticalNote + " (" + path + ")"
	}
	w.reporter.ReportHostFinding(Finding{
		Type:           w.incidentType,
		Change:         change,
		Subject:        path,
		Critical:       critical,
		EscalationNote: note,
		Details: map[string]any{
			"path":            path,
			"change":          change,
			"previous":        prev,
			"current":         curr,
			"watched_targets": w.watchedNote,
		},
	})
}
