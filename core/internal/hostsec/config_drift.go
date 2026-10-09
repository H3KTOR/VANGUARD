package hostsec

// ---------------------------------------------------------------------------
// Phase 4, Detector B: Configuration Drift
//
// Detection:   a bounded allowlist of configuration resources is
//              snapshotted (existence, type, mode, uid, gid, size, and a
//              SHA-256 content hash for regular files up to a size
//              limit) and compared against a SQLite-persisted baseline.
// Evidence:    resource, previous state, current state, changed fields,
//              baseline age, whether content was hashed, created/deleted.
//              File CONTENT is never read into evidence or logs.
// Risk:        IncidentConfigurationDrift; Critical-escalated for
//              thresholds.CriticalConfigDriftPaths.
// Semantics:
//   - first observation of a resource silently establishes its baseline
//     (unless ReportFirstObservation is set);
//   - a resource recorded as absent that later appears is "created";
//   - a baselined resource that is gone is "deleted";
//   - mtime is NEVER compared (a touch with unchanged content is not
//     drift); content is compared by hash when both sides were hashed,
//     otherwise by size (HashSkipped is recorded explicitly);
//   - after a drift is reported the baseline advances to the new state,
//     so the same unchanged drift is reported exactly once, while a
//     later revert (or further change) is a new, separately reported
//     drift;
//   - an unreadable/unstat-able resource is a scan failure, not a
//     deletion: the baseline is preserved untouched.
// ---------------------------------------------------------------------------

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"vanguard/core/internal/database"
	"vanguard/core/internal/thresholds"
)

// ConfigDriftConfig controls the Configuration Drift detector.
type ConfigDriftConfig struct {
	// Paths is the explicit allowlist of monitored resources.
	Paths []string
	// MaxHashBytes: regular files larger than this are compared by
	// metadata only (HashSkipped=true). <=0 selects the default.
	MaxHashBytes int64
	// ReportFirstObservation, when true, reports a pre-existing resource
	// seen for the first time as drift ("first_observed") instead of
	// silently baselining it. Default false.
	ReportFirstObservation bool
	// CriticalPaths overrides thresholds.CriticalConfigDriftPaths.
	CriticalPaths map[string]bool
}

// DefaultConfigDriftConfig returns the out-of-the-box configuration.
func DefaultConfigDriftConfig() ConfigDriftConfig {
	return ConfigDriftConfig{
		Paths:         thresholds.DefaultConfigDriftPaths,
		MaxHashBytes:  thresholds.ConfigDriftMaxHashBytes,
		CriticalPaths: thresholds.CriticalConfigDriftPaths,
	}
}

// driftState is one resource's comparable snapshot (the persisted
// baseline row shape).
type driftState struct {
	Exists      bool      `json:"exists"`
	IsRegular   bool      `json:"is_regular"`
	IsDir       bool      `json:"is_dir"`
	Mode        string    `json:"mode,omitempty"`
	UID         uint32    `json:"uid"`
	GID         uint32    `json:"gid"`
	Size        int64     `json:"size"`
	Hash        string    `json:"hash,omitempty"`
	HashSkipped bool      `json:"hash_skipped"`
	BaselineAt  time.Time `json:"baseline_at"`
}

// ConfigDriftDetector implements Configuration Drift (Phase 4,
// Detector B).
type ConfigDriftDetector struct {
	db       *database.DB
	reporter Reporter
	cfg      ConfigDriftConfig
	paths    []string
	root     string // test-only filesystem prefix
	rep      scanReporter
}

// NewConfigDriftDetector constructs the detector, validating cfg: paths
// are sanitized and bounded, a non-positive hash limit falls back to the
// default.
func NewConfigDriftDetector(db *database.DB, reporter Reporter, cfg ConfigDriftConfig) *ConfigDriftDetector {
	if cfg.MaxHashBytes <= 0 {
		cfg.MaxHashBytes = thresholds.ConfigDriftMaxHashBytes
	}
	if cfg.CriticalPaths == nil {
		cfg.CriticalPaths = thresholds.CriticalConfigDriftPaths
	}
	return &ConfigDriftDetector{
		db: db, reporter: reporter, cfg: cfg,
		paths: sanitizeMonitoredPaths("config_drift", cfg.Paths, thresholds.MaxConfigDriftResources),
	}
}

// WithRoot returns a copy rooted at root, for tests only.
func (d *ConfigDriftDetector) WithRoot(root string) *ConfigDriftDetector {
	d2 := *d
	d2.root = root
	return &d2
}

// Scan performs one full Configuration Drift pass.
func (d *ConfigDriftDetector) Scan(ctx context.Context) {
	for _, p := range d.paths {
		if ctx.Err() != nil {
			logf("config_drift", "scan cancelled/timed out, stopping early")
			return
		}
		d.scanOne(p)
	}
}

func (d *ConfigDriftDetector) scanOne(p string) {
	curr, err := d.snapshot(p)
	if err != nil {
		// Unreadable != deleted: keep the baseline, record the failure.
		logf("config_drift", "scan failure for %s: %v (baseline preserved)", p, err)
		d.rep.fail("cannot stat " + p + ": " + err.Error())
		return
	}

	var prev driftState
	have, err := loadSnapshot(d.db, database.BaselineConfigDrift, p, &prev)
	if err != nil {
		logf("config_drift", "baseline unavailable for %s: %v (not replacing it)", p, err)
		d.rep.fail("baseline store unavailable: " + err.Error())
		return
	}

	if !have {
		curr.BaselineAt = time.Now().UTC()
		if err := saveJSON(d.db, database.BaselineConfigDrift, p, curr); err != nil {
			logf("config_drift", "failed to store baseline for %s: %v", p, err)
			return
		}
		logf("config_drift", "baseline created for %s (exists=%v hashed=%v)", p, curr.Exists, curr.Hash != "")
		if d.cfg.ReportFirstObservation && curr.Exists {
			d.report(p, []string{"first_observed"}, "first_observed", driftState{}, curr, time.Time{})
		}
		return
	}

	fields := diffDrift(prev, curr)
	if len(fields) == 0 {
		return // unchanged (mtime-only changes land here)
	}

	change := fields[0]
	switch {
	case !prev.Exists && curr.Exists:
		change = "created"
	case prev.Exists && !curr.Exists:
		change = "deleted"
	case contains(fields, "content"):
		change = "modified"
	case contains(fields, "mode"):
		change = "perm_changed"
	case contains(fields, "uid"):
		change = "owner_changed"
	case contains(fields, "gid"):
		change = "group_changed"
	}

	d.report(p, fields, change, prev, curr, prev.BaselineAt)

	// Advance the baseline to the reported state (dedup: the same
	// unchanged drift is not re-reported on the next tick).
	curr.BaselineAt = time.Now().UTC()
	if err := saveJSON(d.db, database.BaselineConfigDrift, p, curr); err != nil {
		logf("config_drift", "failed to advance baseline for %s: %v", p, err)
	} else {
		logf("config_drift", "baseline changed for %s (%s)", p, strings.Join(fields, ","))
	}
}

// diffDrift returns the sorted list of meaningful changed fields between
// two snapshots; empty means no drift. Pure function.
func diffDrift(prev, curr driftState) []string {
	if prev.Exists != curr.Exists {
		return []string{"existence"}
	}
	if !curr.Exists {
		return nil
	}
	var f []string
	if prev.Mode != curr.Mode {
		f = append(f, "mode")
	}
	if prev.UID != curr.UID {
		f = append(f, "uid")
	}
	if prev.GID != curr.GID {
		f = append(f, "gid")
	}
	if prev.IsDir != curr.IsDir || prev.IsRegular != curr.IsRegular {
		f = append(f, "file_type")
	}
	if curr.IsRegular {
		if prev.Hash != "" && curr.Hash != "" && !prev.HashSkipped && !curr.HashSkipped {
			if prev.Hash != curr.Hash {
				f = append(f, "content")
			}
		} else if prev.Size != curr.Size {
			// Hashing skipped on either side: metadata fallback.
			f = append(f, "content")
		}
	}
	sort.Strings(f)
	return f
}

func (d *ConfigDriftDetector) report(p string, fields []string, change string, prev, curr driftState, baselineAt time.Time) {
	critical := d.cfg.CriticalPaths[p]
	note := ""
	if critical {
		note = "configuration drift on a highest-value authentication/access-control resource (" + p + ")"
	}
	d.reporter.ReportHostFinding(Finding{
		Type:           database.IncidentConfigurationDrift,
		Change:         change,
		Subject:        "config_drift:" + p + ":" + strings.Join(fields, "+") + ":" + stateFingerprint(curr),
		Critical:       critical,
		EscalationNote: note,
		Details: map[string]any{
			"resource":         p,
			"changed_fields":   fields,
			"previous_state":   publicState(prev),
			"current_state":    publicState(curr),
			"baseline_age_sec": ageSeconds(baselineAt),
			"content_hashed":   curr.Hash != "" && !curr.HashSkipped,
			"hash_skipped":     curr.HashSkipped,
			"created":          !prev.Exists && curr.Exists,
			"deleted":          prev.Exists && !curr.Exists,
			"detected_at":      time.Now().UTC(),
		},
	})
}

// publicState is the evidence-safe view of a snapshot (metadata + hash;
// never content).
func publicState(s driftState) map[string]any {
	return map[string]any{
		"exists": s.Exists, "mode": s.Mode, "uid": s.UID, "gid": s.GID,
		"size": s.Size, "sha256": s.Hash, "hash_skipped": s.HashSkipped,
	}
}

// stateFingerprint is a short stable digest of the resulting state, so
// the engine's (Subject, Type) dedupe distinguishes two different drifts
// of the same resource and field set.
func stateFingerprint(s driftState) string {
	raw := s.Mode + "|" + s.Hash + "|" + strconv.FormatInt(s.Size, 10) + "|" +
		strconv.FormatUint(uint64(s.UID), 10) + "|" + strconv.FormatUint(uint64(s.GID), 10) + "|" +
		strconv.FormatBool(s.Exists)
	h := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(h[:6])
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// snapshot Lstat()s p and, for a regular file within the size limit,
// hashes it with a hard read bound. A missing path is not an error
// (Exists=false); any other stat error is returned.
func (d *ConfigDriftDetector) snapshot(p string) (driftState, error) {
	info, err := os.Lstat(d.root + p)
	if err != nil {
		if os.IsNotExist(err) {
			return driftState{Exists: false}, nil
		}
		return driftState{}, err
	}
	s := driftState{
		Exists:    true,
		IsRegular: info.Mode().IsRegular(),
		IsDir:     info.IsDir(),
		Mode:      info.Mode().Perm().String(),
		Size:      info.Size(),
	}
	if uid, gid, ok := ownerOf(info); ok {
		s.UID, s.GID = uid, gid
	}
	if !s.IsRegular {
		return s, nil
	}
	if info.Size() > d.cfg.MaxHashBytes {
		s.HashSkipped = true
		return s, nil
	}
	h, ok := d.hashBounded(d.root + p)
	if !ok {
		s.HashSkipped = true // unreadable or grew past the limit mid-read
		return s, nil
	}
	s.Hash = h
	return s, nil
}

// hashBounded SHA-256s the file reading at most MaxHashBytes+1 bytes, so
// a file that grows between stat and read can never be read unbounded.
func (d *ConfigDriftDetector) hashBounded(path string) (string, bool) {
	f, err := os.Open(path)
	if err != nil {
		return "", false
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(f, d.cfg.MaxHashBytes+1))
	if err != nil || n > d.cfg.MaxHashBytes {
		return "", false
	}
	return hex.EncodeToString(h.Sum(nil)), true
}
