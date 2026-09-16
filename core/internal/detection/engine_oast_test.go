package detection

import (
	"testing"
	"time"

	"vanguard/core/internal/database"
	"vanguard/core/internal/thresholds"
)

// ---------------------------------------------------------------------------
// OAST / Out-of-Band Interaction Indicators: engine-level integration
// tests (through the real Engine/IngestWebLogLine, not just the pure
// isOASTIndicator helper).
// ---------------------------------------------------------------------------

func TestOASTIndicator_KnownProviderSuffix_CreatesEscalatedIncident(t *testing.T) {
	e, db := testEngine(t)
	ip := "203.0.113.70"
	line := formatWebLine(ip, time.Now().UTC(), "/fetch?url=http://a1b2c3d4e5f6g7h8.oast.fun/callback", 200, "curl/8.0")
	e.IngestWebLogLine(line)

	incidents, _ := db.ListIncidents(database.IncidentFilter{SourceIP: ip})
	var found *database.Incident
	for i, inc := range incidents {
		if inc.Type == database.IncidentOASTIndicator {
			found = &incidents[i]
		}
	}
	if found == nil {
		t.Fatalf("expected a %s incident, got types: %+v", database.IncidentOASTIndicator, incidentTypes(incidents))
	}
	if found.RiskScore < 50 {
		t.Errorf("expected known-provider-suffix hit to escalate above the un-escalated base (30), got %d", found.RiskScore)
	}
}

func TestOASTIndicator_RandomHostnameNoSuffix_CreatesUnescalatedIncident(t *testing.T) {
	e, db := testEngine(t)
	ip := "203.0.113.71"
	line := formatWebLine(ip, time.Now().UTC(), "/fetch?url=http://a1b2c3d4e5f6g7h8i9j0.attacker-controlled.example/x", 200, "curl/8.0")
	e.IngestWebLogLine(line)

	incidents, _ := db.ListIncidents(database.IncidentFilter{SourceIP: ip})
	found := false
	for _, inc := range incidents {
		if inc.Type == database.IncidentOASTIndicator {
			found = true
			if inc.Severity == database.SeverityCritical || inc.Severity == database.SeverityHigh {
				t.Errorf("expected a single unreinforced callback-shaped hostname to stay LOW/MEDIUM, got %s", inc.Severity)
			}
		}
	}
	if !found {
		t.Fatalf("expected a %s incident from a single random callback-shaped hostname", database.IncidentOASTIndicator)
	}
}

func TestOASTIndicator_OrdinaryTraffic_NoIncident(t *testing.T) {
	e, db := testEngine(t)
	ip := "203.0.113.72"
	line := formatWebLine(ip, time.Now().UTC(), "/api/v1/users/12345?ref=api.example.com", 200, "Mozilla/5.0")
	e.IngestWebLogLine(line)

	incidents, _ := db.ListIncidents(database.IncidentFilter{SourceIP: ip})
	for _, inc := range incidents {
		if inc.Type == database.IncidentOASTIndicator {
			t.Fatalf("expected NO %s incident for ordinary traffic", database.IncidentOASTIndicator)
		}
	}
}

func TestOASTIndicator_RepeatedDistinctCallbacks_Escalates(t *testing.T) {
	e, db := testEngine(t)
	ip := "203.0.113.73"
	base := time.Now().UTC()

	// Pre-seed the tracker with an earlier, DIFFERENT callback-shaped
	// hostname from this same IP, as if a prior request had already
	// been observed (using the tracker directly rather than a second
	// IngestWebLogLine call, since dedupeWindow.allow keys off real
	// wall-clock time.Now(), not the event's own Timestamp, so two
	// rapid-succession log lines in a unit test cannot otherwise
	// exercise the "second distinct callback" path without an
	// artificial real-time sleep).
	e.oastCallback.Record(ip, "a1b2c3d4e5f6g7h8.attacker.example", base.Add(-1*time.Second), thresholds.OASTCallbackWindow)

	// Now the SECOND, DIFFERENT callback-shaped hostname arrives via the
	// real ingestion path -- distinctCallbacks should be 2, triggering
	// the "repeated distinct callbacks" reinforcement/escalation.
	e.IngestWebLogLine(formatWebLine(ip, base, "/fetch?url=http://z9y8x7w6v5u4t3s2.attacker.example/y", 200, "curl/8.0"))

	incidents, _ := db.ListIncidents(database.IncidentFilter{SourceIP: ip})
	var found *database.Incident
	for i, inc := range incidents {
		if inc.Type == database.IncidentOASTIndicator {
			found = &incidents[i]
		}
	}
	if found == nil {
		t.Fatalf("expected a %s incident, got types: %+v", database.IncidentOASTIndicator, incidentTypes(incidents))
	}
	if found.RiskScore < 50 {
		t.Errorf("expected the repeated-distinct-callback incident to be escalated (score >= 50), got %d", found.RiskScore)
	}
}

func TestOASTIndicator_DedupeSuppressesRepeatIncidents(t *testing.T) {
	e, db := testEngine(t)
	ip := "203.0.113.74"
	base := time.Now().UTC()

	// Same hostname repeated rapidly -- dedupe must suppress the second.
	e.IngestWebLogLine(formatWebLine(ip, base, "/fetch?url=http://a1b2c3d4e5f6g7h8.oast.fun/x", 200, "curl/8.0"))
	e.IngestWebLogLine(formatWebLine(ip, base.Add(1*time.Second), "/fetch?url=http://a1b2c3d4e5f6g7h8.oast.fun/x", 200, "curl/8.0"))

	incidents, _ := db.ListIncidents(database.IncidentFilter{SourceIP: ip})
	count := 0
	for _, inc := range incidents {
		if inc.Type == database.IncidentOASTIndicator {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("expected dedupe to suppress a rapid repeat OAST incident from the same IP/hostname, got %d", count)
	}
}
