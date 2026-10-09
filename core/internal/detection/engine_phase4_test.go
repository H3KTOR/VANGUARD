package detection

import (
	"testing"

	"vanguard/core/internal/database"
	"vanguard/core/internal/hostsec"
)

func phase4Score(t *testing.T, f hostsec.Finding) *database.Incident {
	t.Helper()
	e, db := testEngine(t)
	e.ReportHostFinding(f)
	if got := countIncidents(t, db); got != 1 {
		t.Fatalf("expected 1 incident, got %d", got)
	}
	return lastIncident(t, db)
}

func TestPhase4_IncidentTypesRouteThroughHostPipeline(t *testing.T) {
	for _, typ := range []database.IncidentType{
		database.IncidentConfigurationPosture, database.IncidentConfigurationDrift,
		database.IncidentListeningServiceDrift, database.IncidentPackageDrift,
	} {
		inc := phase4Score(t, hostsec.Finding{Type: typ, Change: "x", Subject: "s"})
		if inc.Type != typ || inc.SourceIP != database.HostLocalIP {
			t.Errorf("%s: got type=%s ip=%s", typ, inc.Type, inc.SourceIP)
		}
	}
}

func TestPhase4_RiskAdjustGradesListenerExposure(t *testing.T) {
	loopback := phase4Score(t, hostsec.Finding{Type: database.IncidentListeningServiceDrift, Change: "new_listener", Subject: "a", RiskAdjust: -10})
	wildcard := phase4Score(t, hostsec.Finding{Type: database.IncidentListeningServiceDrift, Change: "new_listener", Subject: "b", RiskAdjust: 25})
	if loopback.RiskScore >= wildcard.RiskScore {
		t.Fatalf("loopback (%d) must score below privileged wildcard (%d)", loopback.RiskScore, wildcard.RiskScore)
	}
}

func TestPhase4_OrdinaryDriftIsNotCritical(t *testing.T) {
	routine := phase4Score(t, hostsec.Finding{Type: database.IncidentPackageDrift, Change: "upgraded", Subject: "p", RiskAdjust: -10})
	if routine.Severity == database.SeverityCritical || routine.Severity == database.SeverityHigh {
		t.Fatalf("routine package update severity = %s (score %d)", routine.Severity, routine.RiskScore)
	}
	crit := phase4Score(t, hostsec.Finding{Type: database.IncidentConfigurationDrift, Change: "modified", Subject: "sshd", Critical: true})
	if crit.RiskScore <= routine.RiskScore {
		t.Fatalf("critical config drift (%d) must outscore routine update (%d)", crit.RiskScore, routine.RiskScore)
	}
}

func TestPhase4_IdenticalFindingDeduped(t *testing.T) {
	e, db := testEngine(t)
	f := hostsec.Finding{Type: database.IncidentListeningServiceDrift, Change: "new_listener", Subject: "listening_service_drift:new_listener:tcp:0.0.0.0:9000:"}
	for i := 0; i < 10; i++ {
		e.ReportHostFinding(f)
	}
	if got := countIncidents(t, db); got != 1 {
		t.Fatalf("repeated identical finding produced %d incidents", got)
	}
}
