package hostsec

// Shared helpers for the Phase 4 System Posture detectors (Configuration
// Drift, Listening Service Drift, Package Drift).

import (
	"path/filepath"
	"strings"
	"time"

	"vanguard/core/internal/database"
)

// sanitizeMonitoredPaths validates an operator-supplied path list: each
// entry must be absolute, NUL-free and is cleaned (so "/etc/../etc/x"
// and "/etc//x" collapse to one identity). Invalid entries are dropped
// with a log line rather than silently trusted; duplicates are removed;
// the result is capped at max entries (extras dropped, logged).
func sanitizeMonitoredPaths(scanner string, in []string, max int) []string {
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, raw := range in {
		p := strings.TrimSpace(raw)
		if p == "" {
			continue
		}
		if strings.ContainsRune(p, 0) || !strings.HasPrefix(p, "/") {
			logf(scanner, "ignoring invalid monitored path %q (must be absolute)", raw)
			continue
		}
		p = filepath.ToSlash(filepath.Clean(p))
		if seen[p] {
			continue
		}
		if len(out) >= max {
			logf(scanner, "monitored path limit (%d) reached, ignoring %q and any further entries", max, p)
			break
		}
		seen[p] = true
		out = append(out, p)
	}
	return out
}

// loadSnapshot reads a single-row JSON snapshot baseline. found=false
// with a nil error means no snapshot exists yet (cold start); a non-nil
// error means the baseline store is unreadable and the caller MUST NOT
// treat that as "empty baseline" (fail-safe: never silently replace a
// baseline with the current state).
func loadSnapshot(db *database.DB, category database.HostBaselineCategory, key string, v any) (found bool, err error) {
	row, err := db.GetHostBaseline(category, key)
	if err != nil {
		if err == database.ErrNotFound {
			return false, nil
		}
		return false, err
	}
	if err := row.GetContent(v); err != nil {
		return false, err // corrupt baseline: surface, never overwrite silently
	}
	return true, nil
}

// ageSeconds returns whole seconds since t, or 0 for a zero time.
func ageSeconds(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return int64(time.Since(t).Seconds())
}
