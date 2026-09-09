package hostsec

import (
	"context"
	"testing"

	"vanguard/core/internal/database"
)

// fakeReporter collects every Finding reported during a test instead of
// routing it through internal/detection (which would create an import
// cycle: detection already imports hostsec). It gives tests a simple,
// dependency-free way to assert on exactly what a scanner reported.
type fakeReporter struct {
	findings []Finding
}

func (r *fakeReporter) ReportHostFinding(f Finding) {
	r.findings = append(r.findings, f)
}

func (r *fakeReporter) reset() { r.findings = nil }

// byChange returns every collected finding whose Change label matches.
func (r *fakeReporter) byChange(change string) []Finding {
	var out []Finding
	for _, f := range r.findings {
		if f.Change == change {
			out = append(out, f)
		}
	}
	return out
}

// testDB opens a fresh in-memory SQLite database with every model
// migrated, mirroring internal/detection's own testEngine helper.
func testDB(t *testing.T) *database.DB {
	t.Helper()
	db, err := database.Open(database.Config{Path: ":memory:"})
	if err != nil {
		t.Fatalf("failed to open in-memory db: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

// bg returns a background context, matching the ctx type every Scan
// method expects.
func bg() context.Context { return context.Background() }
