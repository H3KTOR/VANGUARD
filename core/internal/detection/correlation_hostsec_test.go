package detection

import (
	"testing"
	"time"

	"vanguard/core/internal/database"
	"vanguard/core/internal/hostsec"
	"vanguard/core/internal/thresholds"
)

// fakeThreatIntel treats every IP in bad as malicious, everything else as
// clean.
type fakeThreatIntel struct {
	bad map[string]bool
}

func (f *fakeThreatIntel) IsMalicious(ip string) bool { return f.bad[ip] }

func testEngineWithIntel(t *testing.T, bad ...string) (*Engine, *database.DB) {
	t.Helper()
	db, err := database.Open(database.Config{Path: ":memory:"})
	if err != nil {
		t.Fatalf("failed to open in-memory db: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	set := make(map[string]bool, len(bad))
	for _, ip := range bad {
		set[ip] = true
	}
	return NewEngine(Config{DB: db, ThreatIntel: &fakeThreatIntel{bad: set}}), db
}

func countIncidentsOfType(t *testing.T, db *database.DB, itype database.IncidentType) int {
	t.Helper()
	incidents, err := db.ListIncidents(database.IncidentFilter{Limit: 500})
	if err != nil {
		t.Fatalf("ListIncidents failed: %v", err)
	}
	n := 0
	for _, inc := range incidents {
		if inc.Type == itype {
			n++
		}
	}
	return n
}

// incidentOfType returns the first stored incident matching itype.
// Deliberately queried by type rather than by "most recent" (lastIncident)
// -- these tests create multiple incidents in the same test, often with
// identical DetectedAt timestamps (same synthetic "now"), which makes
// ORDER BY detected_at DESC non-deterministic between rows that tie.
func incidentOfType(t *testing.T, db *database.DB, itype database.IncidentType) *database.Incident {
	t.Helper()
	incidents, err := db.ListIncidents(database.IncidentFilter{Type: itype, Limit: 500})
	if err != nil {
		t.Fatalf("ListIncidents failed: %v", err)
	}
	if len(incidents) == 0 {
		t.Fatalf("expected at least one %s incident, got none", itype)
	}
	return &incidents[0]
}

// TestCorrelateHostFinding_NoCorroboratingEvidenceStaysStandalone verifies
// a Suspicious Process finding with neither recent file activity nor a
// malicious-reputation outbound connection raises ONLY the standalone
// IncidentSuspiciousProcess -- no HIGH_CONFIDENCE_COMPROMISE.
func TestCorrelateHostFinding_NoCorroboratingEvidenceStaysStandalone(t *testing.T) {
	e, db := testEngineWithIntel(t)

	e.ReportHostFinding(hostsec.Finding{
		Type:    database.IncidentSuspiciousProcess,
		Change:  "process_from_unusual_directory",
		Subject: "/tmp/x",
	})

	if got := countIncidentsOfType(t, db, database.IncidentSuspiciousProcess); got != 1 {
		t.Errorf("expected 1 standalone suspicious-process incident, got %d", got)
	}
	if got := countIncidentsOfType(t, db, database.IncidentHighConfidenceCompromise); got != 0 {
		t.Errorf("expected 0 high-confidence-compromise incidents without corroborating evidence, got %d", got)
	}
}

// TestCorrelateHostFinding_RecentFIMActivityTriggersCompromise verifies a
// Suspicious Process finding that arrives shortly after a FIM (Feature 1)
// finding -- within thresholds.HostCorrelationWindow -- raises both the
// standalone incident AND a correlated HIGH_CONFIDENCE_COMPROMISE.
func TestCorrelateHostFinding_RecentFIMActivityTriggersCompromise(t *testing.T) {
	e, db := testEngineWithIntel(t)

	e.ReportHostFinding(hostsec.Finding{
		Type:    database.IncidentFIMChange,
		Change:  "modified",
		Subject: "/etc/shadow",
	})
	e.ReportHostFinding(hostsec.Finding{
		Type:    database.IncidentSuspiciousProcess,
		Change:  "deleted_exe_running",
		Subject: "/tmp/x",
	})

	if got := countIncidentsOfType(t, db, database.IncidentHighConfidenceCompromise); got != 1 {
		t.Fatalf("expected 1 high-confidence-compromise incident after recent FIM activity + suspicious process, got %d", got)
	}
	inc := incidentOfType(t, db, database.IncidentHighConfidenceCompromise)
	if inc.Severity != database.SeverityCritical {
		t.Errorf("expected CRITICAL severity for a correlated compromise, got %s (score %d)", inc.Severity, inc.RiskScore)
	}
}

// TestCorrelateHostFinding_BinaryIntegrityActivityTriggersCompromise is
// the same scenario as above but sourced from Feature 8 (System Binary
// Integrity) instead of Feature 1 (FIM) -- both are "Sensitive File
// Activity" for correlation purposes.
func TestCorrelateHostFinding_BinaryIntegrityActivityTriggersCompromise(t *testing.T) {
	e, db := testEngineWithIntel(t)

	e.ReportHostFinding(hostsec.Finding{
		Type:    database.IncidentSystemBinaryIntegrity,
		Change:  "modified",
		Subject: "/bin/bash",
	})
	e.ReportHostFinding(hostsec.Finding{
		Type:    database.IncidentSuspiciousProcess,
		Change:  "suspicious_parent_child",
		Subject: "/bin/sh",
	})

	if got := countIncidentsOfType(t, db, database.IncidentHighConfidenceCompromise); got != 1 {
		t.Errorf("expected 1 high-confidence-compromise incident after recent binary-integrity activity + suspicious process, got %d", got)
	}
}

// TestCorrelateHostFinding_MaliciousOutboundConnectionTriggersCompromise
// verifies a Suspicious Process finding whose RemoteAddrs includes an IP
// on the threat-intel feed raises HIGH_CONFIDENCE_COMPROMISE even with NO
// recent file activity at all -- the mega-prompt's example chain's final
// two links ("network connection -> malicious reputation") are alone
// sufficient corroboration.
func TestCorrelateHostFinding_MaliciousOutboundConnectionTriggersCompromise(t *testing.T) {
	e, db := testEngineWithIntel(t, "203.0.113.66")

	e.ReportHostFinding(hostsec.Finding{
		Type:        database.IncidentSuspiciousProcess,
		Change:      "deleted_exe_running",
		Subject:     "/tmp/x",
		RemoteAddrs: []string{"203.0.113.66:4444"},
	})

	if got := countIncidentsOfType(t, db, database.IncidentHighConfidenceCompromise); got != 1 {
		t.Errorf("expected 1 high-confidence-compromise incident from a malicious outbound connection alone, got %d", got)
	}
	inc := incidentOfType(t, db, database.IncidentHighConfidenceCompromise)
	var meta map[string]any
	if err := inc.GetMetadata(&meta); err != nil {
		t.Fatalf("GetMetadata: %v", err)
	}
	if got, _ := meta["malicious_remote_addr"].(string); got != "203.0.113.66:4444" {
		t.Errorf("expected malicious_remote_addr to be recorded, got %+v", meta["malicious_remote_addr"])
	}
}

// TestCorrelateHostFinding_CleanOutboundConnectionDoesNotTrigger verifies
// a RemoteAddrs entry that is NOT on the threat-intel feed contributes no
// corroboration by itself.
func TestCorrelateHostFinding_CleanOutboundConnectionDoesNotTrigger(t *testing.T) {
	e, db := testEngineWithIntel(t) // no malicious IPs configured

	e.ReportHostFinding(hostsec.Finding{
		Type:        database.IncidentSuspiciousProcess,
		Change:      "deleted_exe_running",
		Subject:     "/tmp/x",
		RemoteAddrs: []string{"93.184.216.34:443"}, // ordinary, clean destination
	})

	if got := countIncidentsOfType(t, db, database.IncidentHighConfidenceCompromise); got != 0 {
		t.Errorf("expected 0 high-confidence-compromise incidents for a clean outbound connection, got %d", got)
	}
}

// TestCorrelateHostFinding_FileActivityOutsideWindowDoesNotTrigger
// verifies file activity older than thresholds.HostCorrelationWindow no
// longer counts as corroborating evidence.
func TestCorrelateHostFinding_FileActivityOutsideWindowDoesNotTrigger(t *testing.T) {
	e, db := testEngineWithIntel(t)

	// Directly seed correlator state as "stale" by recording it far in
	// the past relative to now, bypassing ReportHostFinding's own
	// now := time.Now() so the test doesn't need to sleep for real.
	e.hostCor.RecordFileFinding(time.Now().UTC().Add(-2*thresholds.HostCorrelationWindow), thresholds.HostCorrelationWindow)

	e.ReportHostFinding(hostsec.Finding{
		Type:    database.IncidentSuspiciousProcess,
		Change:  "deleted_exe_running",
		Subject: "/tmp/x",
	})

	if got := countIncidentsOfType(t, db, database.IncidentHighConfidenceCompromise); got != 0 {
		t.Errorf("expected 0 high-confidence-compromise incidents for out-of-window file activity, got %d", got)
	}
}

// TestCorrelateHostFinding_DedupeSuppressesRepeats verifies an identical
// repeated Suspicious Process finding (same Subject) doesn't flood a
// second HIGH_CONFIDENCE_COMPROMISE within the dedupe window.
func TestCorrelateHostFinding_DedupeSuppressesRepeats(t *testing.T) {
	e, db := testEngineWithIntel(t, "203.0.113.66")

	finding := hostsec.Finding{
		Type:        database.IncidentSuspiciousProcess,
		Change:      "deleted_exe_running",
		Subject:     "/tmp/x",
		RemoteAddrs: []string{"203.0.113.66:4444"},
	}
	e.ReportHostFinding(finding)
	e.ReportHostFinding(finding)

	if got := countIncidentsOfType(t, db, database.IncidentHighConfidenceCompromise); got != 1 {
		t.Errorf("expected repeated identical findings within the dedupe window to be suppressed, got %d high-confidence-compromise incidents", got)
	}
}
