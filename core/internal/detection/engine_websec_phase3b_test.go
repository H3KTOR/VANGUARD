package detection

import (
	"testing"
	"time"

	"vanguard/core/internal/database"
	"vanguard/core/internal/thresholds"
)

// formatWebLineFull builds a synthetic combined-format log line with an
// explicit method/protocol, for tests that need to drive malformed
// method/protocol tokens through the real parser (formatWebLine in
// chain_integration_test.go always uses "GET ... HTTP/1.1").
func formatWebLineFull(ip string, ts time.Time, method, path, protocol string, status int, ua string) string {
	return ip + ` - - [` + ts.Format("02/Jan/2006:15:04:05 -0700") + `] "` + method + ` ` + path + ` ` + protocol + `" ` +
		itoa(status) + ` 162 "-" "` + ua + `"`
}

// formatWebLineWithHost builds a synthetic combined-format log line with
// an additional trailing quoted Host field, matching parser_web.go's
// opt-in extended format.
func formatWebLineWithHost(ip string, ts time.Time, path string, status int, ua, host string) string {
	return ip + ` - - [` + ts.Format("02/Jan/2006:15:04:05 -0700") + `] "GET ` + path + ` HTTP/1.1" ` +
		itoa(status) + ` 162 "-" "` + ua + `" "` + host + `"`
}

// ---------------------------------------------------------------------------
// HTTP Protocol Anomaly Detection: engine-level integration tests
// ---------------------------------------------------------------------------

func TestHTTPProtocolAnomaly_SustainedInvalidMethod_CreatesIncident(t *testing.T) {
	e, db := testEngine(t)
	ip := "203.0.113.230"
	base := time.Now().UTC()

	for i := 0; i < thresholds.HTTPProtocolAnomalyMinCount+1; i++ {
		ts := base.Add(time.Duration(i) * time.Millisecond)
		line := formatWebLineFull(ip, ts, "FOOBAR", "/", "HTTP/1.1", 200, "curl/8.0")
		e.IngestWebLogLine(line)
	}

	incidents, _ := db.ListIncidents(database.IncidentFilter{SourceIP: ip})
	found := false
	for _, inc := range incidents {
		if inc.Type == database.IncidentHTTPProtocolAnomaly {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected a %s incident, got types: %+v", database.IncidentHTTPProtocolAnomaly, incidentTypes(incidents))
	}
}

func TestHTTPProtocolAnomaly_SingleMalformedRequest_NoIncident(t *testing.T) {
	e, db := testEngine(t)
	ip := "203.0.113.231"
	base := time.Now().UTC()

	e.IngestWebLogLine(formatWebLineFull(ip, base, "FOOBAR", "/", "HTTP/1.1", 200, "curl/8.0"))

	incidents, _ := db.ListIncidents(database.IncidentFilter{SourceIP: ip})
	for _, inc := range incidents {
		if inc.Type == database.IncidentHTTPProtocolAnomaly {
			t.Fatalf("did not expect a single malformed request to trigger an incident")
		}
	}
}

func TestHTTPProtocolAnomaly_NormalTraffic_NoIncident(t *testing.T) {
	// False-positive control: normal well-formed traffic must never
	// trigger this, no matter the volume.
	e, db := testEngine(t)
	ip := "203.0.113.232"
	base := time.Now().UTC()

	for i := 0; i < thresholds.HTTPProtocolAnomalyMinCount+10; i++ {
		ts := base.Add(time.Duration(i) * time.Millisecond)
		e.IngestWebLogLine(formatWebLine(ip, ts, "/", 200, "Mozilla/5.0"))
	}

	incidents, _ := db.ListIncidents(database.IncidentFilter{SourceIP: ip})
	for _, inc := range incidents {
		if inc.Type == database.IncidentHTTPProtocolAnomaly {
			t.Fatalf("did not expect an incident from well-formed high-volume traffic")
		}
	}
}

func TestHTTPProtocolAnomaly_SustainedBadStatusCodes_CreatesIncident(t *testing.T) {
	e, db := testEngine(t)
	ip := "203.0.113.233"
	base := time.Now().UTC()

	for i := 0; i < thresholds.HTTPProtocolAnomalyMinCount+1; i++ {
		ts := base.Add(time.Duration(i) * time.Millisecond)
		e.IngestWebLogLine(formatWebLine(ip, ts, "/", 414, "curl/8.0"))
	}

	incidents, _ := db.ListIncidents(database.IncidentFilter{SourceIP: ip})
	found := false
	for _, inc := range incidents {
		if inc.Type == database.IncidentHTTPProtocolAnomaly {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected a %s incident from sustained 414 responses", database.IncidentHTTPProtocolAnomaly)
	}
}

func TestHTTPProtocolAnomaly_OrdinaryFourOhFours_NoIncident(t *testing.T) {
	// False positive control: ordinary application-level 404s (not in
	// ProtocolAnomalyStatusCodes) must never count toward this detector.
	e, db := testEngine(t)
	ip := "203.0.113.234"
	base := time.Now().UTC()

	for i := 0; i < thresholds.HTTPProtocolAnomalyMinCount+10; i++ {
		ts := base.Add(time.Duration(i) * time.Millisecond)
		e.IngestWebLogLine(formatWebLine(ip, ts, "/page"+itoa(i), 404, "Mozilla/5.0"))
	}

	incidents, _ := db.ListIncidents(database.IncidentFilter{SourceIP: ip})
	for _, inc := range incidents {
		if inc.Type == database.IncidentHTTPProtocolAnomaly {
			t.Fatalf("did not expect ordinary 404s to trigger HTTP Protocol Anomaly")
		}
	}
}

func TestHTTPProtocolAnomaly_PerIPIsolation(t *testing.T) {
	e, db := testEngine(t)
	base := time.Now().UTC()
	ipA := "203.0.113.235"
	ipB := "203.0.113.236"

	half := thresholds.HTTPProtocolAnomalyMinCount - 1
	for i := 0; i < half; i++ {
		e.IngestWebLogLine(formatWebLineFull(ipA, base.Add(time.Duration(i)*time.Millisecond), "FOOBAR", "/", "HTTP/1.1", 200, "curl"))
	}
	for i := 0; i < half; i++ {
		e.IngestWebLogLine(formatWebLineFull(ipB, base.Add(time.Duration(i)*time.Millisecond), "FOOBAR", "/", "HTTP/1.1", 200, "curl"))
	}

	for _, ip := range []string{ipA, ipB} {
		incidents, _ := db.ListIncidents(database.IncidentFilter{SourceIP: ip})
		for _, inc := range incidents {
			if inc.Type == database.IncidentHTTPProtocolAnomaly {
				t.Fatalf("did not expect an incident on %s below its own per-IP threshold", ip)
			}
		}
	}
}

func TestHTTPProtocolAnomaly_DedupeSuppressesRepeatIncidents(t *testing.T) {
	e, db := testEngine(t)
	ip := "203.0.113.237"
	base := time.Now().UTC()

	n := thresholds.HTTPProtocolAnomalyMinCount + 1
	for i := 0; i < n; i++ {
		ts := base.Add(time.Duration(i) * time.Millisecond)
		e.IngestWebLogLine(formatWebLineFull(ip, ts, "FOOBAR", "/", "HTTP/1.1", 200, "curl"))
	}
	firstCount := countIncidentsOfType(t, db, database.IncidentHTTPProtocolAnomaly)
	if firstCount != 1 {
		t.Fatalf("expected exactly 1 incident, got %d", firstCount)
	}

	e.IngestWebLogLine(formatWebLineFull(ip, base.Add(time.Duration(n+1)*time.Millisecond), "FOOBAR", "/", "HTTP/1.1", 200, "curl"))
	secondCount := countIncidentsOfType(t, db, database.IncidentHTTPProtocolAnomaly)
	if secondCount != 1 {
		t.Fatalf("expected dedupe to suppress a duplicate incident, got %d total", secondCount)
	}
}

// ---------------------------------------------------------------------------
// Request-Smuggling Indicators: engine-level integration tests
// ---------------------------------------------------------------------------

func TestRequestSmuggling_SustainedSymptomStatusBurst_CreatesIncident(t *testing.T) {
	e, db := testEngine(t)
	ip := "203.0.113.240"
	base := time.Now().UTC()

	for i := 0; i < thresholds.RequestSmugglingMinCount+1; i++ {
		ts := base.Add(time.Duration(i) * time.Millisecond)
		e.IngestWebLogLine(formatWebLine(ip, ts, "/", 502, "curl/8.0"))
	}

	incidents, _ := db.ListIncidents(database.IncidentFilter{SourceIP: ip})
	found := false
	for _, inc := range incidents {
		if inc.Type == database.IncidentRequestSmugglingIndicator {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected a %s incident, got types: %+v", database.IncidentRequestSmugglingIndicator, incidentTypes(incidents))
	}
}

func TestRequestSmuggling_SingleFiveOhTwo_NoIncident(t *testing.T) {
	e, db := testEngine(t)
	ip := "203.0.113.241"
	base := time.Now().UTC()

	e.IngestWebLogLine(formatWebLine(ip, base, "/", 502, "curl/8.0"))

	incidents, _ := db.ListIncidents(database.IncidentFilter{SourceIP: ip})
	for _, inc := range incidents {
		if inc.Type == database.IncidentRequestSmugglingIndicator {
			t.Fatalf("did not expect a single 502 response to trigger an incident")
		}
	}
}

func TestRequestSmuggling_OrdinaryStatusCodes_NoIncident(t *testing.T) {
	// False-positive control: a burst of ORDINARY status codes (200, 404,
	// 500 -- not in RequestSmugglingSymptomStatusCodes) must never count.
	e, db := testEngine(t)
	ip := "203.0.113.242"
	base := time.Now().UTC()

	for i := 0; i < thresholds.RequestSmugglingMinCount+10; i++ {
		ts := base.Add(time.Duration(i) * time.Millisecond)
		e.IngestWebLogLine(formatWebLine(ip, ts, "/", 500, "curl/8.0"))
	}

	incidents, _ := db.ListIncidents(database.IncidentFilter{SourceIP: ip})
	for _, inc := range incidents {
		if inc.Type == database.IncidentRequestSmugglingIndicator {
			t.Fatalf("did not expect ordinary 500s to trigger a request-smuggling indicator")
		}
	}
}

func TestRequestSmuggling_PerIPIsolation(t *testing.T) {
	e, db := testEngine(t)
	base := time.Now().UTC()
	ipA := "203.0.113.243"
	ipB := "203.0.113.244"

	half := thresholds.RequestSmugglingMinCount - 1
	for i := 0; i < half; i++ {
		e.IngestWebLogLine(formatWebLine(ipA, base.Add(time.Duration(i)*time.Millisecond), "/", 408, "curl"))
	}
	for i := 0; i < half; i++ {
		e.IngestWebLogLine(formatWebLine(ipB, base.Add(time.Duration(i)*time.Millisecond), "/", 408, "curl"))
	}

	for _, ip := range []string{ipA, ipB} {
		incidents, _ := db.ListIncidents(database.IncidentFilter{SourceIP: ip})
		for _, inc := range incidents {
			if inc.Type == database.IncidentRequestSmugglingIndicator {
				t.Fatalf("did not expect an incident on %s below its own per-IP threshold", ip)
			}
		}
	}
}

func TestRequestSmuggling_DedupeSuppressesRepeatIncidents(t *testing.T) {
	e, db := testEngine(t)
	ip := "203.0.113.245"
	base := time.Now().UTC()

	n := thresholds.RequestSmugglingMinCount + 1
	for i := 0; i < n; i++ {
		ts := base.Add(time.Duration(i) * time.Millisecond)
		e.IngestWebLogLine(formatWebLine(ip, ts, "/", 400, "curl"))
	}
	firstCount := countIncidentsOfType(t, db, database.IncidentRequestSmugglingIndicator)
	if firstCount != 1 {
		t.Fatalf("expected exactly 1 incident, got %d", firstCount)
	}

	e.IngestWebLogLine(formatWebLine(ip, base.Add(time.Duration(n+1)*time.Millisecond), "/", 400, "curl"))
	secondCount := countIncidentsOfType(t, db, database.IncidentRequestSmugglingIndicator)
	if secondCount != 1 {
		t.Fatalf("expected dedupe to suppress a duplicate incident, got %d total", secondCount)
	}
}

// ---------------------------------------------------------------------------
// Host Header / Virtual Host Abuse: engine-level integration tests
// ---------------------------------------------------------------------------

func TestHostHeaderAbuse_IPLiteralHost_CreatesIncident(t *testing.T) {
	e, db := testEngine(t)
	ip := "203.0.113.250"
	base := time.Now().UTC()

	e.IngestWebLogLine(formatWebLineWithHost(ip, base, "/", 200, "curl/8.0", "10.0.0.5"))

	incidents, _ := db.ListIncidents(database.IncidentFilter{SourceIP: ip})
	found := false
	for _, inc := range incidents {
		if inc.Type == database.IncidentHostHeaderAnomaly {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected a %s incident from a single IP-literal Host (escalated signal), got types: %+v",
			database.IncidentHostHeaderAnomaly, incidentTypes(incidents))
	}
}

func TestHostHeaderAbuse_LoopbackHost_CreatesIncident(t *testing.T) {
	e, db := testEngine(t)
	ip := "203.0.113.251"
	base := time.Now().UTC()

	e.IngestWebLogLine(formatWebLineWithHost(ip, base, "/", 200, "curl/8.0", "127.0.0.1"))

	incidents, _ := db.ListIncidents(database.IncidentFilter{SourceIP: ip})
	found := false
	for _, inc := range incidents {
		if inc.Type == database.IncidentHostHeaderAnomaly {
			found = true
			// IncidentHostHeaderAnomaly deliberately has a LOW BaseSeverity
			// (25 -- see risk.go's "no overclaiming" comment: an unexpected
			// Host value alone is often just a misconfigured client or bot).
			// The Escalate mechanism adds a flat +25 on top of that base for
			// a loopback/IP-literal Host (a single occurrence worth flagging
			// harder than an ordinary unexpected-hostname mismatch), landing
			// at 50/MEDIUM -- NOT HIGH/CRITICAL. Asserting HIGH/CRITICAL here
			// would itself be the kind of overclaiming this phase forbids, so
			// this test instead asserts the escalation actually fired (score
			// materially above the un-escalated LOW-tier baseline).
			if inc.Severity != database.SeverityMedium {
				t.Errorf("expected escalated loopback-Host incident to land at MEDIUM (base 25 + escalation 25 = 50), got %s (score %d)", inc.Severity, inc.RiskScore)
			}
			if inc.RiskScore < 50 {
				t.Errorf("expected escalation bonus to be applied (score >= 50), got %d", inc.RiskScore)
			}
		}
	}
	if !found {
		t.Fatalf("expected a %s incident from a single loopback Host", database.IncidentHostHeaderAnomaly)
	}
}

func TestHostHeaderAbuse_NormalHost_NoIncident(t *testing.T) {
	e, db := testEngine(t)
	ip := "203.0.113.252"
	base := time.Now().UTC()

	e.IngestWebLogLine(formatWebLineWithHost(ip, base, "/", 200, "Mozilla/5.0", "shop.example.com"))

	incidents, _ := db.ListIncidents(database.IncidentFilter{SourceIP: ip})
	for _, inc := range incidents {
		if inc.Type == database.IncidentHostHeaderAnomaly {
			t.Fatalf("did not expect an incident from a single ordinary hostname (no allowlist configured)")
		}
	}
}

func TestHostHeaderAbuse_EmptyHost_NeverTriggered(t *testing.T) {
	// The stock combined log format (no Host field) must never trigger
	// this detector, no matter how much traffic flows.
	e, db := testEngine(t)
	ip := "203.0.113.253"
	base := time.Now().UTC()

	for i := 0; i < thresholds.HostHeaderEnumerationMinDistinctHosts+10; i++ {
		e.IngestWebLogLine(formatWebLine(ip, base.Add(time.Duration(i)*time.Millisecond), "/", 200, "Mozilla/5.0"))
	}

	incidents, _ := db.ListIncidents(database.IncidentFilter{SourceIP: ip})
	for _, inc := range incidents {
		if inc.Type == database.IncidentHostHeaderAnomaly {
			t.Fatalf("did not expect an incident when Host is never populated (stock log format)")
		}
	}
}

func TestHostHeaderAbuse_Enumeration_CreatesIncident(t *testing.T) {
	e, db := testEngine(t)
	ip := "203.0.113.254"
	base := time.Now().UTC()

	for i := 0; i < thresholds.HostHeaderEnumerationMinDistinctHosts; i++ {
		ts := base.Add(time.Duration(i) * time.Second)
		host := "vhost" + itoa(i) + ".example.com"
		e.IngestWebLogLine(formatWebLineWithHost(ip, ts, "/", 200, "curl/8.0", host))
	}

	incidents, _ := db.ListIncidents(database.IncidentFilter{SourceIP: ip})
	found := false
	for _, inc := range incidents {
		if inc.Type == database.IncidentHostHeaderAnomaly {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected a %s incident from Host enumeration, got types: %+v", database.IncidentHostHeaderAnomaly, incidentTypes(incidents))
	}
}

func TestHostHeaderAbuse_SingleHostRepeated_NoEnumerationIncident(t *testing.T) {
	e, db := testEngine(t)
	ip := "203.0.113.255"
	base := time.Now().UTC()

	for i := 0; i < thresholds.HostHeaderEnumerationMinDistinctHosts+10; i++ {
		ts := base.Add(time.Duration(i) * time.Second)
		e.IngestWebLogLine(formatWebLineWithHost(ip, ts, "/", 200, "Mozilla/5.0", "shop.example.com"))
	}

	incidents, _ := db.ListIncidents(database.IncidentFilter{SourceIP: ip})
	for _, inc := range incidents {
		if inc.Type == database.IncidentHostHeaderAnomaly {
			t.Fatalf("did not expect an incident from repeated requests to the SAME Host value")
		}
	}
}

func TestHostHeaderAbuse_ExpectedHostsConfigured_UnexpectedHostFlagged(t *testing.T) {
	restoreExpectedHosts(t, []string{"shop.example.com"})
	e, db := testEngine(t)
	ip := "198.51.100.10"
	base := time.Now().UTC()

	e.IngestWebLogLine(formatWebLineWithHost(ip, base, "/", 200, "curl/8.0", "evil.attacker.example"))

	incidents, _ := db.ListIncidents(database.IncidentFilter{SourceIP: ip})
	found := false
	for _, inc := range incidents {
		if inc.Type == database.IncidentHostHeaderAnomaly {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected a %s incident from a Host not matching the configured allowlist", database.IncidentHostHeaderAnomaly)
	}
}

func TestHostHeaderAbuse_ExpectedHostsConfigured_MatchingHostNotFlagged(t *testing.T) {
	restoreExpectedHosts(t, []string{"shop.example.com"})
	e, db := testEngine(t)
	ip := "198.51.100.11"
	base := time.Now().UTC()

	e.IngestWebLogLine(formatWebLineWithHost(ip, base, "/", 200, "Mozilla/5.0", "shop.example.com"))

	incidents, _ := db.ListIncidents(database.IncidentFilter{SourceIP: ip})
	for _, inc := range incidents {
		if inc.Type == database.IncidentHostHeaderAnomaly {
			t.Fatalf("did not expect an incident from a Host matching the configured allowlist")
		}
	}
}

func TestHostHeaderAbuse_DedupeSuppressesRepeatIncidents(t *testing.T) {
	e, db := testEngine(t)
	ip := "203.0.113.156"
	base := time.Now().UTC()

	e.IngestWebLogLine(formatWebLineWithHost(ip, base, "/", 200, "curl/8.0", "10.0.0.9"))
	firstCount := countIncidentsOfType(t, db, database.IncidentHostHeaderAnomaly)
	if firstCount != 1 {
		t.Fatalf("expected exactly 1 incident, got %d", firstCount)
	}

	e.IngestWebLogLine(formatWebLineWithHost(ip, base.Add(time.Second), "/", 200, "curl/8.0", "10.0.0.9"))
	secondCount := countIncidentsOfType(t, db, database.IncidentHostHeaderAnomaly)
	if secondCount != 1 {
		t.Fatalf("expected dedupe to suppress a duplicate incident, got %d total", secondCount)
	}
}
