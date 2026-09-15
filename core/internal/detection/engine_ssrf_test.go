package detection

import (
	"testing"
	"time"

	"vanguard/core/internal/database"
)

// ---------------------------------------------------------------------------
// SSRF Indicators: engine-level integration tests (through the real
// Engine/IngestWebLogLine, not just the pure isSSRFIndicator helper).
// ---------------------------------------------------------------------------

func TestSSRFIndicator_PrivateTarget_CreatesIncident(t *testing.T) {
	e, db := testEngine(t)
	ip := "203.0.113.60"
	line := formatWebLine(ip, time.Now().UTC(), "/fetch?url=http://10.0.0.5/admin", 200, "curl/8.0")
	e.IngestWebLogLine(line)

	incidents, _ := db.ListIncidents(database.IncidentFilter{SourceIP: ip})
	found := false
	for _, inc := range incidents {
		if inc.Type == database.IncidentSSRFIndicator {
			found = true
			if inc.Severity == database.SeverityCritical {
				t.Errorf("expected an ordinary RFC1918 hit to NOT reach CRITICAL, got %s", inc.Severity)
			}
		}
	}
	if !found {
		t.Fatalf("expected a %s incident, got types: %+v", database.IncidentSSRFIndicator, incidentTypes(incidents))
	}
}

func TestSSRFIndicator_MetadataEndpoint_Escalates(t *testing.T) {
	e, db := testEngine(t)
	ip := "203.0.113.61"
	line := formatWebLine(ip, time.Now().UTC(), "/fetch?url=http://169.254.169.254/latest/meta-data/", 200, "curl/8.0")
	e.IngestWebLogLine(line)

	incidents, _ := db.ListIncidents(database.IncidentFilter{SourceIP: ip})
	var found *database.Incident
	for i, inc := range incidents {
		if inc.Type == database.IncidentSSRFIndicator {
			found = &incidents[i]
		}
	}
	if found == nil {
		t.Fatalf("expected a %s incident from a metadata-endpoint hit", database.IncidentSSRFIndicator)
	}
	if found.RiskScore < 60 {
		t.Errorf("expected metadata-endpoint hit to escalate risk score materially above the un-escalated base (35), got %d", found.RiskScore)
	}
}

func TestSSRFIndicator_OrdinaryRequest_NoIncident(t *testing.T) {
	e, db := testEngine(t)
	ip := "203.0.113.62"
	line := formatWebLine(ip, time.Now().UTC(), "/products?price=19.99&id=42", 200, "Mozilla/5.0")
	e.IngestWebLogLine(line)

	incidents, _ := db.ListIncidents(database.IncidentFilter{SourceIP: ip})
	for _, inc := range incidents {
		if inc.Type == database.IncidentSSRFIndicator {
			t.Fatalf("expected NO %s incident for an ordinary request with decimal-shaped query values", database.IncidentSSRFIndicator)
		}
	}
}

func TestSSRFIndicator_PublicIPTarget_NoIncident(t *testing.T) {
	e, db := testEngine(t)
	ip := "203.0.113.63"
	line := formatWebLine(ip, time.Now().UTC(), "/fetch?url=http://8.8.8.8/", 200, "curl/8.0")
	e.IngestWebLogLine(line)

	incidents, _ := db.ListIncidents(database.IncidentFilter{SourceIP: ip})
	for _, inc := range incidents {
		if inc.Type == database.IncidentSSRFIndicator {
			t.Fatalf("expected NO %s incident for a public-IP target", database.IncidentSSRFIndicator)
		}
	}
}

func TestSSRFIndicator_DedupeSuppressesRepeatIncidents(t *testing.T) {
	e, db := testEngine(t)
	ip := "203.0.113.64"
	base := time.Now().UTC()

	e.IngestWebLogLine(formatWebLine(ip, base, "/fetch?url=http://10.0.0.5/admin", 200, "curl/8.0"))
	e.IngestWebLogLine(formatWebLine(ip, base.Add(1*time.Second), "/fetch?url=http://10.0.0.6/admin", 200, "curl/8.0"))

	incidents, _ := db.ListIncidents(database.IncidentFilter{SourceIP: ip})
	count := 0
	for _, inc := range incidents {
		if inc.Type == database.IncidentSSRFIndicator {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("expected dedupe to suppress a rapid repeat SSRF incident from the same IP, got %d", count)
	}
}
