package detection

import (
	"fmt"
	"testing"
	"time"

	"vanguard/core/internal/database"
	"vanguard/core/internal/thresholds"
)

func testEngine(t *testing.T) (*Engine, *database.DB) {
	t.Helper()
	db, err := database.Open(database.Config{Path: ":memory:"})
	if err != nil {
		t.Fatalf("failed to open in-memory db: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return NewEngine(Config{DB: db}), db
}

func lastIncident(t *testing.T, db *database.DB) *database.Incident {
	t.Helper()
	incidents, err := db.ListIncidents(database.IncidentFilter{Limit: 1})
	if err != nil {
		t.Fatalf("ListIncidents failed: %v", err)
	}
	if len(incidents) == 0 {
		t.Fatalf("expected at least one incident, got none")
	}
	return &incidents[0]
}

func countIncidents(t *testing.T, db *database.DB) int {
	t.Helper()
	incidents, err := db.ListIncidents(database.IncidentFilter{Limit: 500})
	if err != nil {
		t.Fatalf("ListIncidents failed: %v", err)
	}
	return len(incidents)
}

func TestSSHBruteForceRule(t *testing.T) {
	e, db := testEngine(t)
	ip := "203.0.113.10"

	// Below threshold: no incident should be raised yet.
	for i := 0; i < thresholds.SSHBruteForceMinAttempts; i++ {
		line := fmt.Sprintf("Aug 23 14:00:%02d host sshd[100]: Failed password for root from %s port 4000%d ssh2", i, ip, i)
		e.IngestAuthLogLine(line)
	}
	if got := countIncidents(t, db); got != 0 {
		t.Fatalf("expected 0 incidents at exactly the threshold, got %d", got)
	}

	// One more failure crosses ">10" and should raise a brute-force incident.
	line := fmt.Sprintf("Aug 23 14:00:59 host sshd[100]: Failed password for root from %s port 40099 ssh2", ip)
	e.IngestAuthLogLine(line)

	if got := countIncidents(t, db); got != 1 {
		t.Fatalf("expected 1 incident after crossing threshold, got %d", got)
	}
	inc := lastIncident(t, db)
	if inc.Type != database.IncidentSSHBruteForce {
		t.Errorf("expected type %s, got %s", database.IncidentSSHBruteForce, inc.Type)
	}
	if inc.SourceIP != ip {
		t.Errorf("expected source_ip %s, got %s", ip, inc.SourceIP)
	}
	if inc.Severity == "" || inc.RiskScore <= 0 {
		t.Errorf("expected a populated risk score/severity, got score=%d severity=%s", inc.RiskScore, inc.Severity)
	}
}

func TestFailedThenSuccessEscalation(t *testing.T) {
	e, db := testEngine(t)
	ip := "203.0.113.20"

	for i := 0; i < thresholds.FailedThenSuccessMinFailed+2; i++ {
		line := fmt.Sprintf("Aug 23 14:01:%02d host sshd[200]: Failed password for admin from %s port 5000%d ssh2", i%60, ip, i)
		e.IngestAuthLogLine(line)
	}
	// A single successful login right after should escalate to CRITICAL.
	successLine := fmt.Sprintf("Aug 23 14:01:59 host sshd[200]: Accepted password for root from %s port 50099 ssh2", ip)
	e.IngestAuthLogLine(successLine)

	incidents, err := db.ListIncidents(database.IncidentFilter{SourceIP: ip})
	if err != nil {
		t.Fatalf("ListIncidents failed: %v", err)
	}
	found := false
	for _, inc := range incidents {
		if inc.Type == database.IncidentFailedThenSuccess {
			found = true
			if inc.Severity != database.SeverityCritical {
				t.Errorf("expected CRITICAL severity for failed->success escalation, got %s (score %d)", inc.Severity, inc.RiskScore)
			}
		}
	}
	if !found {
		t.Fatalf("expected a %s incident, got types: %+v", database.IncidentFailedThenSuccess, incidentTypes(incidents))
	}
}

func TestPortScanRule(t *testing.T) {
	e, _ := testEngine(t)
	ip := "203.0.113.30"
	now := time.Now().UTC()

	for p := 0; p < thresholds.PortScanDistinctPorts; p++ {
		e.IngestPortTouch(ip, 1000+p, now)
	}
	if got := e.State().TrackedIPCount(); got == 0 {
		t.Fatalf("expected state to be tracking at least one IP")
	}
}

func TestWebDirScanRule(t *testing.T) {
	e, db := testEngine(t)
	ip := "203.0.113.40"

	for i := 0; i < thresholds.WebDirScanMin404s; i++ {
		line := fmt.Sprintf(`%s - - [23/Aug/2026:14:02:%02d +0000] "GET /wp-admin HTTP/1.1" 404 162 "-" "curl/8.0"`, ip, i)
		e.IngestWebLogLine(line)
	}
	if got := countIncidents(t, db); got != 1 {
		t.Fatalf("expected 1 web-dir-scan incident, got %d", got)
	}
	inc := lastIncident(t, db)
	if inc.Type != database.IncidentWebDirScan {
		t.Errorf("expected type %s, got %s", database.IncidentWebDirScan, inc.Type)
	}
}

func TestPathTraversalRule(t *testing.T) {
	e, db := testEngine(t)
	ip := "203.0.113.50"

	line := fmt.Sprintf(`%s - - [23/Aug/2026:14:03:00 +0000] "GET /../../etc/passwd HTTP/1.1" 403 0 "-" "curl/8.0"`, ip)
	e.IngestWebLogLine(line)

	if got := countIncidents(t, db); got != 1 {
		t.Fatalf("expected 1 path-traversal incident, got %d", got)
	}
	inc := lastIncident(t, db)
	if inc.Type != database.IncidentPathTraversal {
		t.Errorf("expected type %s, got %s", database.IncidentPathTraversal, inc.Type)
	}
}

func TestSQLiXSSRule(t *testing.T) {
	e, db := testEngine(t)
	ip := "203.0.113.60"

	line := fmt.Sprintf(`%s - - [23/Aug/2026:14:04:00 +0000] "GET /search?q=<script>alert(1)</script> HTTP/1.1" 200 100 "-" "curl/8.0"`, ip)
	e.IngestWebLogLine(line)

	if got := countIncidents(t, db); got != 1 {
		t.Fatalf("expected 1 sqli/xss incident, got %d", got)
	}
	inc := lastIncident(t, db)
	if inc.Type != database.IncidentSQLiXSS {
		t.Errorf("expected type %s, got %s", database.IncidentSQLiXSS, inc.Type)
	}
}

func TestHTTPFloodRule(t *testing.T) {
	e, db := testEngine(t)
	ip := "203.0.113.70"

	for i := 0; i < thresholds.HTTPFloodMaxRequests+5; i++ {
		line := fmt.Sprintf(`%s - - [23/Aug/2026:14:05:00 +0000] "GET /index.html HTTP/1.1" 200 512 "-" "curl/8.0"`, ip)
		e.IngestWebLogLine(line)
	}
	if got := countIncidents(t, db); got != 1 {
		t.Fatalf("expected exactly 1 http-flood incident (dedupe should suppress repeats), got %d", got)
	}
	inc := lastIncident(t, db)
	if inc.Type != database.IncidentHTTPFlood {
		t.Errorf("expected type %s, got %s", database.IncidentHTTPFlood, inc.Type)
	}
}

func TestHoneypotTriggerIsAlwaysCritical(t *testing.T) {
	e, db := testEngine(t)
	ip := "203.0.113.80"

	e.IngestHoneypotHit(ip, 2222, "fake-ssh", time.Now().UTC(), "connection from "+ip)

	if got := countIncidents(t, db); got != 1 {
		t.Fatalf("expected 1 honeypot incident, got %d", got)
	}
	inc := lastIncident(t, db)
	if inc.Type != database.IncidentHoneypotTrigger {
		t.Errorf("expected type %s, got %s", database.IncidentHoneypotTrigger, inc.Type)
	}
	if inc.Severity != database.SeverityCritical {
		t.Errorf("honeypot trigger must always be CRITICAL, got %s (score %d)", inc.Severity, inc.RiskScore)
	}
}

func TestWhitelistedIPStillDetectedButNotBanned(t *testing.T) {
	// Detection always fires regardless of whitelist status -- only the
	// firewall/Autopilot layer (tested separately) must honor the
	// fail-safe whitelist. This test just documents/locks that boundary.
	e, db := testEngine(t)
	ip := "203.0.113.90"

	if err := db.CreateFirewallRule(&database.FirewallRule{
		IPAddress: ip, IsWhitelisted: true, IsActive: true, Reason: "test",
	}); err != nil {
		t.Fatalf("failed to seed whitelist rule: %v", err)
	}

	e.IngestHoneypotHit(ip, 2222, "fake-ssh", time.Now().UTC(), "connection from "+ip)

	if got := countIncidents(t, db); got != 1 {
		t.Fatalf("expected detection to still create an incident even for a whitelisted IP, got %d", got)
	}
}

func incidentTypes(incidents []database.Incident) []database.IncidentType {
	out := make([]database.IncidentType, len(incidents))
	for i, inc := range incidents {
		out[i] = inc.Type
	}
	return out
}
