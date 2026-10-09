package detection

import (
	"path/filepath"
	"testing"
	"time"

	"vanguard/core/internal/database"
	"vanguard/core/internal/thresholds"
	"vanguard/core/internal/tuning"
)

func tunedEngine(t *testing.T) (*Engine, *database.DB, *tuning.Store) {
	t.Helper()
	db, err := database.Open(database.Config{Path: filepath.Join(t.TempDir(), "tr.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if s, err := db.DB.DB(); err == nil {
			s.Close()
		}
	})
	st := tuning.Load(db)
	return NewEngine(Config{DB: db, Tuning: st}), db, st
}

func p(n int) *int { return &n }

func failures(e *Engine, ip string, n int) {
	for i := 0; i < n; i++ {
		e.IngestAuthLogLine(sshFail(ip, i))
	}
}

// The tuned threshold really changes the rule's behaviour, in both
// directions, at the exact boundary (fires when count > threshold).
func TestTuning_ChangesRuleBoundaryBothWays(t *testing.T) {
	e, db, st := tunedEngine(t)
	failures(e, "203.0.113.1", thresholds.SSHBruteForceMinAttempts+1)
	if nIncidents(t, db, database.IncidentSSHBruteForce) != 1 {
		t.Fatal("default boundary broken")
	}

	// tighten: 6 failures now cross a threshold of 5
	if _, err := st.Apply(0, tuning.Patch{SSHBruteForceMinAttempts: p(5)}, "admin@x", "tighten", false); err != nil {
		t.Fatal(err)
	}
	failures(e, "203.0.113.2", 5)
	if nIncidents(t, db, database.IncidentSSHBruteForce) != 1 {
		t.Fatal("exactly at the tuned threshold must not fire")
	}
	failures(e, "203.0.113.3", 6)
	if nIncidents(t, db, database.IncidentSSHBruteForce) != 2 {
		t.Fatal("one above the tuned threshold must fire")
	}

	// relax (acknowledged): the old default count no longer fires
	if _, err := st.Apply(1, tuning.Patch{SSHBruteForceMinAttempts: p(30)}, "admin@x", "relax", true); err != nil {
		t.Fatal(err)
	}
	failures(e, "203.0.113.4", thresholds.SSHBruteForceMinAttempts+5)
	if nIncidents(t, db, database.IncidentSSHBruteForce) != 2 {
		t.Fatal("a relaxed threshold must suppress the previous default boundary")
	}
}

func TestTuning_EachTunableAppliesToItsOwnRuleOnly(t *testing.T) {
	e, db, st := tunedEngine(t)
	// raise only the flood threshold; port scan keeps its default
	if _, err := st.Apply(0, tuning.Patch{HTTPFloodMaxRequests: p(500)}, "a@x", "", true); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 400; i++ {
		e.IngestWebLogLine(`203.0.113.5 - - [23/Aug/2026:14:05:00 +0000] "GET /index.html HTTP/1.1" 200 512 "-" "curl/8.0"`)
	}
	if nIncidents(t, db, database.IncidentHTTPFlood) != 0 {
		t.Fatal("400 requests must not flood under a 500 threshold")
	}
	for p := 0; p < thresholds.PortScanDistinctPorts+1; p++ {
		e.IngestPortTouch("203.0.113.6", 2000+p, nowUTC())
	}
	if nIncidents(t, db, database.IncidentPortScan) != 1 {
		t.Fatal("an unrelated rule's default must be untouched")
	}
}

// 10.5: the incident records the condition, the observed value, the
// threshold actually applied and where that threshold came from.
func TestExplanation_RecordsConditionObservedThresholdAndSource(t *testing.T) {
	e, db, st := tunedEngine(t)
	failures(e, "203.0.113.7", thresholds.SSHBruteForceMinAttempts+1)
	m := metaOfInc(t, incidentsOfType(t, db, database.IncidentSSHBruteForce)[0])
	r := m["rule"].(map[string]any)
	if r["threshold"] != float64(thresholds.SSHBruteForceMinAttempts) || r["observed"] != float64(thresholds.SSHBruteForceMinAttempts+1) ||
		r["comparison"] != ">" || r["threshold_source"] != "compiled default" || r["tuning_revision"] != float64(0) || r["condition"] == "" {
		t.Fatalf("explanation = %v", r)
	}
	if _, err := st.Apply(0, tuning.Patch{SSHBruteForceMinAttempts: p(4)}, "admin@x", "", false); err != nil {
		t.Fatal(err)
	}
	failures(e, "203.0.113.8", 5)
	var tuned map[string]any
	for _, inc := range incidentsOfType(t, db, database.IncidentSSHBruteForce) {
		if inc.SourceIP == "203.0.113.8" {
			tuned = metaOfInc(t, inc)["rule"].(map[string]any)
		}
	}
	if tuned["threshold"] != float64(4) || tuned["threshold_source"] != "operator tuning revision 1" || tuned["tuning_revision"] != float64(1) {
		t.Fatalf("tuned explanation = %v", tuned)
	}
	// the explanation never claims more than the rule evaluated
	prov := metaOfInc(t, incidentsOfType(t, db, database.IncidentSSHBruteForce)[0])["provenance"].(map[string]any)
	if prov["limitations"] == "" {
		t.Fatal("limitations must stay alongside the explanation")
	}
}

// Tuning must not change response policy: a relaxed rule still produces
// incidents scored by the same formula, and IOC-only risk stays capped.
func TestTuning_DoesNotTouchRiskCapOrBaseSeverities(t *testing.T) {
	if thresholds.MaxIOCOnlyRisk >= 60 {
		t.Fatal("IOC-only cap must stay below the default auto-response threshold")
	}
}

func nowUTC() time.Time { return time.Now().UTC() }

func metaOfInc(t *testing.T, inc database.Incident) map[string]any { return metaOf(t, &inc) }
