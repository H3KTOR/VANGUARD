package detection

import (
	"testing"
	"time"

	"vanguard/core/internal/database"
	"vanguard/core/internal/hostsec"
)

// ---------------------------------------------------------------------------
// Web Shell Indicators: engine-level integration tests (through the real
// Engine/IngestWebLogLine, not just the pure classifyWebShellRequest
// helper), including the cross-detector correlation with Phase 1/2
// host-security findings via the real ReportHostFinding/HostCorrelator.
// ---------------------------------------------------------------------------

func TestWebShellIndicator_UploadPathScriptRequest_CreatesUnescalatedIncident(t *testing.T) {
	e, db := testEngine(t)
	ip := "203.0.113.80"
	line := formatWebLine(ip, time.Now().UTC(), "/wp-content/uploads/shell.php?cmd=whoami", 200, "curl/8.0")
	e.IngestWebLogLine(line)

	incidents, _ := db.ListIncidents(database.IncidentFilter{SourceIP: ip})
	var found *database.Incident
	for i, inc := range incidents {
		if inc.Type == database.IncidentWebShellIndicator {
			found = &incidents[i]
		}
	}
	if found == nil {
		t.Fatalf("expected a %s incident, got types: %+v", database.IncidentWebShellIndicator, incidentTypes(incidents))
	}
	if found.Severity == database.SeverityCritical || found.Severity == database.SeverityHigh {
		t.Errorf("expected an UNCORROBORATED web-shell-shaped request (even with all 3 signals) to stay LOW/MEDIUM, got %s", found.Severity)
	}
}

func TestWebShellIndicator_OrdinaryRequest_NoIncident(t *testing.T) {
	e, db := testEngine(t)
	ip := "203.0.113.81"
	line := formatWebLine(ip, time.Now().UTC(), "/index.html", 200, "Mozilla/5.0")
	e.IngestWebLogLine(line)

	incidents, _ := db.ListIncidents(database.IncidentFilter{SourceIP: ip})
	for _, inc := range incidents {
		if inc.Type == database.IncidentWebShellIndicator {
			t.Fatalf("expected NO %s incident for an ordinary request", database.IncidentWebShellIndicator)
		}
	}
}

func TestWebShellIndicator_OrdinaryPHPAppRequest_SingleExtensionSignal_NotCritical(t *testing.T) {
	e, db := testEngine(t)
	ip := "203.0.113.82"
	// A completely ordinary PHP application request -- extension signal
	// only, no upload path, no suspicious query param. Must never reach
	// HIGH/CRITICAL on its own.
	line := formatWebLine(ip, time.Now().UTC(), "/index.php?page=about", 200, "Mozilla/5.0")
	e.IngestWebLogLine(line)

	incidents, _ := db.ListIncidents(database.IncidentFilter{SourceIP: ip})
	for _, inc := range incidents {
		if inc.Type == database.IncidentWebShellIndicator {
			if inc.Severity == database.SeverityCritical || inc.Severity == database.SeverityHigh {
				t.Errorf("expected a single ordinary .php request to stay LOW/MEDIUM, got %s", inc.Severity)
			}
		}
	}
}

func TestWebShellIndicator_CorroboratedByRecentFIMFinding_Escalates(t *testing.T) {
	e, db := testEngine(t)
	ip := "203.0.113.83"

	// A Phase 1 FIM finding on the host shortly before the web-shell-
	// shaped request arrives -- this is the corroborating evidence that
	// should escalate the Web Shell Indicator via the shared
	// HostCorrelator (the same mechanism feature 7 already uses).
	e.ReportHostFinding(hostsec.Finding{
		Type:    database.IncidentFIMChange,
		Change:  "created",
		Subject: "/var/www/html/uploads/shell.php",
	})

	line := formatWebLine(ip, time.Now().UTC(), "/uploads/shell.php?cmd=whoami", 200, "curl/8.0")
	e.IngestWebLogLine(line)

	incidents, _ := db.ListIncidents(database.IncidentFilter{SourceIP: ip})
	var found *database.Incident
	for i, inc := range incidents {
		if inc.Type == database.IncidentWebShellIndicator {
			found = &incidents[i]
		}
	}
	if found == nil {
		t.Fatalf("expected a %s incident, got types: %+v", database.IncidentWebShellIndicator, incidentTypes(incidents))
	}
	if found.RiskScore < 55 {
		t.Errorf("expected FIM-corroborated web-shell request to escalate materially above the un-escalated base (~35), got %d", found.RiskScore)
	}
}

func TestWebShellIndicator_CorroboratedBySuspiciousProcessFinding_Escalates(t *testing.T) {
	e, db := testEngine(t)
	ip := "203.0.113.84"

	e.ReportHostFinding(hostsec.Finding{
		Type:    database.IncidentSuspiciousProcess,
		Change:  "suspicious_parent_child",
		Subject: "/bin/sh",
	})

	line := formatWebLine(ip, time.Now().UTC(), "/uploads/shell.php", 200, "curl/8.0")
	e.IngestWebLogLine(line)

	incidents, _ := db.ListIncidents(database.IncidentFilter{SourceIP: ip})
	found := false
	escalated := false
	for _, inc := range incidents {
		if inc.Type == database.IncidentWebShellIndicator {
			found = true
			if inc.RiskScore >= 55 {
				escalated = true
			}
		}
	}
	if !found {
		t.Fatalf("expected a %s incident", database.IncidentWebShellIndicator)
	}
	if !escalated {
		t.Errorf("expected a recent Suspicious Process finding to also corroborate/escalate the Web Shell Indicator")
	}
}

func TestWebShellIndicator_NoCorroboration_StaysUnescalated(t *testing.T) {
	e, db := testEngine(t)
	ip := "203.0.113.85"

	// No prior host-security finding at all -- the web-shell-shaped
	// request must stay at its ordinary, un-escalated base score.
	line := formatWebLine(ip, time.Now().UTC(), "/uploads/shell.php?cmd=whoami", 200, "curl/8.0")
	e.IngestWebLogLine(line)

	incidents, _ := db.ListIncidents(database.IncidentFilter{SourceIP: ip})
	for _, inc := range incidents {
		if inc.Type == database.IncidentWebShellIndicator {
			if inc.RiskScore >= 55 {
				t.Errorf("expected an uncorroborated request to NOT reach escalated territory, got score %d", inc.RiskScore)
			}
		}
	}
}

func TestWebShellIndicator_DedupeSuppressesRepeatIncidents(t *testing.T) {
	e, db := testEngine(t)
	ip := "203.0.113.86"
	base := time.Now().UTC()

	e.IngestWebLogLine(formatWebLine(ip, base, "/uploads/shell.php?cmd=whoami", 200, "curl/8.0"))
	e.IngestWebLogLine(formatWebLine(ip, base.Add(1*time.Second), "/uploads/shell2.php?cmd=id", 200, "curl/8.0"))

	incidents, _ := db.ListIncidents(database.IncidentFilter{SourceIP: ip})
	count := 0
	for _, inc := range incidents {
		if inc.Type == database.IncidentWebShellIndicator {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("expected dedupe to suppress a rapid repeat web-shell incident from the same IP, got %d", count)
	}
}
