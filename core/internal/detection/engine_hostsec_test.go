package detection

import (
	"testing"

	"vanguard/core/internal/database"
	"vanguard/core/internal/hostsec"
)

func TestReportHostFinding_CreatesIncidentWithHostLocalIP(t *testing.T) {
	e, db := testEngine(t)

	e.ReportHostFinding(hostsec.Finding{
		Type:    database.IncidentFIMChange,
		Change:  "modified",
		Subject: "/etc/shadow",
		Details: map[string]any{"path": "/etc/shadow"},
	})

	if got := countIncidents(t, db); got != 1 {
		t.Fatalf("expected 1 incident, got %d", got)
	}
	inc := lastIncident(t, db)
	if inc.Type != database.IncidentFIMChange {
		t.Errorf("expected type %s, got %s", database.IncidentFIMChange, inc.Type)
	}
	if inc.SourceIP != database.HostLocalIP {
		t.Errorf("expected SourceIP %s, got %s", database.HostLocalIP, inc.SourceIP)
	}
}

func TestReportHostFinding_CriticalEscalatesRiskScore(t *testing.T) {
	e, db := testEngine(t)

	e.ReportHostFinding(hostsec.Finding{
		Type:    database.IncidentAccountChange,
		Change:  "user_created",
		Subject: "unrelated-normal-account",
	})
	normal := lastIncident(t, db)

	e2, db2 := testEngine(t)
	e2.ReportHostFinding(hostsec.Finding{
		Type:           database.IncidentPrivilegeEscalation,
		Change:         "uid0_account",
		Subject:        "backdoor",
		Critical:       true,
		EscalationNote: "non-root account with UID 0 (root-equivalent)",
	})
	critical := lastIncident(t, db2)

	if critical.RiskScore <= normal.RiskScore {
		t.Errorf("expected a Critical=true finding to score higher than a normal finding: critical=%d normal=%d", critical.RiskScore, normal.RiskScore)
	}
}

func TestReportHostFinding_DedupeSuppressesRepeats(t *testing.T) {
	e, db := testEngine(t)

	finding := hostsec.Finding{
		Type:    database.IncidentSUIDSGIDAnomaly,
		Change:  "created",
		Subject: "/tmp/evil-suid",
	}
	e.ReportHostFinding(finding)
	e.ReportHostFinding(finding) // immediate repeat within the dedupe window

	if got := countIncidents(t, db); got != 1 {
		t.Fatalf("expected repeated identical findings within the dedupe window to be suppressed, got %d incidents", got)
	}
}

func TestReportHostFinding_BestEffortSurfacedInDetails(t *testing.T) {
	e, db := testEngine(t)

	e.ReportHostFinding(hostsec.Finding{
		Type:       database.IncidentPrivilegeEscalation,
		Change:     "unexpected_root_process",
		Subject:    "/tmp/.hidden/backdoor",
		BestEffort: true,
	})

	inc := lastIncident(t, db)
	var meta map[string]any
	if err := inc.GetMetadata(&meta); err != nil {
		t.Fatalf("GetMetadata: %v", err)
	}
	if bf, _ := meta["best_effort"].(bool); !bf {
		t.Errorf("expected metadata.best_effort=true, got %+v", meta["best_effort"])
	}
}
