package detection

import (
	"testing"
	"time"

	"vanguard/core/internal/database"
	"vanguard/core/internal/firewall"
	"vanguard/core/internal/thresholds"
)

// ---------------------------------------------------------------------------
// Full-pipeline integration tests: Engine -> createIncident -> Notifier ->
// Autopilot.OnIncident -> instant firewall ban. These exercise Task 3's
// "trigger an instant Autopilot firewall ban" requirement end-to-end,
// proving no new ban-integration code was needed -- the ATTACK_CHAIN
// incident flows through the exact same detection.Notifier interface every
// other rule already uses.
// ---------------------------------------------------------------------------

// testEngineWithAutopilot wires a real *firewall.Autopilot (backed by a
// MockExecutor, so no real OS firewall calls are made) as the Engine's
// Notifier, mirroring how cmd/vanguard/serve.go wires them together in
// production.
func testEngineWithAutopilot(t *testing.T) (*Engine, *database.DB, *firewall.Autopilot, *firewall.MockExecutor) {
	t.Helper()
	db, err := database.Open(database.Config{Path: ":memory:"})
	if err != nil {
		t.Fatalf("failed to open in-memory db: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	exec := firewall.NewMockExecutor()
	autopilot := firewall.NewAutopilot(db, exec, firewall.DefaultConfig())
	engine := NewEngine(Config{DB: db, Notifier: autopilot})
	return engine, db, autopilot, exec
}

// driveFullAttackChain feeds a complete, correctly-ordered recon -> web
// probing -> auth probing sequence for ip into e, returning the timestamp
// of the final (triggering) event.
func driveFullAttackChain(e *Engine, ip string, base time.Time) time.Time {
	for p := 0; p < thresholds.AttackChainMinDistinctPorts; p++ {
		e.IngestPortTouch(ip, 6000+p, base)
	}

	webTS := base.Add(30 * time.Second)
	for i := 0; i < thresholds.AttackChainMinWebProbes; i++ {
		ts := webTS.Add(time.Duration(i) * time.Second)
		line := formatWebLine(ip, ts, "/wp-login.php", 404, "python-requests/2.28")
		e.IngestWebLogLine(line)
	}

	authTS := webTS.Add(30 * time.Second)
	var last time.Time
	for i := 0; i < thresholds.AttackChainMinAuthFailures; i++ {
		ts := authTS.Add(time.Duration(i) * time.Second)
		line := formatAuthFailedLine(ip, ts, i)
		e.IngestAuthLogLine(line)
		last = ts
	}
	return last
}

// formatWebLine builds a synthetic Nginx/Apache combined-format log line.
func formatWebLine(ip string, ts time.Time, path string, status int, ua string) string {
	return ip + ` - - [` + ts.Format("02/Jan/2006:15:04:05 -0700") + `] "GET ` + path + ` HTTP/1.1" ` +
		itoa(status) + ` 162 "-" "` + ua + `"`
}

// formatAuthFailedLine builds a synthetic auth.log "Failed password" line.
// Uses the syslog "Mon _2 15:04:05" format the real parser expects, and a
// distinct source port per call so ordering is unambiguous in test output.
func formatAuthFailedLine(ip string, ts time.Time, i int) string {
	return ts.In(time.Local).Format("Jan _2 15:04:05") + " host sshd[100]: Failed password for root from " + ip + " port 400" + itoa(50+i) + " ssh2"
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [12]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}

func TestAttackChain_FullSequenceCreatesIncidentAndBans(t *testing.T) {
	e, db, _, exec := testEngineWithAutopilot(t)
	ip := "203.0.113.150"
	base := time.Now().UTC()

	driveFullAttackChain(e, ip, base)

	incidents, err := db.ListIncidents(database.IncidentFilter{SourceIP: ip})
	if err != nil {
		t.Fatalf("ListIncidents failed: %v", err)
	}
	var chainInc *database.Incident
	for i := range incidents {
		if incidents[i].Type == database.IncidentAttackChain {
			chainInc = &incidents[i]
		}
	}
	if chainInc == nil {
		t.Fatalf("expected an %s incident, got types: %+v", database.IncidentAttackChain, incidentTypes(incidents))
	}
	if chainInc.Severity != database.SeverityCritical {
		t.Errorf("expected ATTACK_CHAIN to be CRITICAL severity, got %s (score %d)", chainInc.Severity, chainInc.RiskScore)
	}
	if chainInc.RiskScore < 60 {
		t.Errorf("expected ATTACK_CHAIN risk score to clear the auto-ban threshold (60), got %d", chainInc.RiskScore)
	}

	// The instant Autopilot ban should have fired automatically, with zero
	// extra integration code, purely because the incident flowed through
	// the same createIncident()/OnIncident() pipeline every other rule uses.
	if !exec.Blocked[ip] {
		t.Fatalf("expected Autopilot to have instantly banned %s in response to the ATTACK_CHAIN incident", ip)
	}
	banned, err := db.IsBanned(ip)
	if err != nil || !banned {
		t.Fatalf("expected IsBanned=true for %s, got %v (err=%v)", ip, banned, err)
	}

	got, err := db.GetIncident(chainInc.ID)
	if err != nil {
		t.Fatalf("GetIncident failed: %v", err)
	}
	if got.Status != database.StatusAutoBlocked {
		t.Errorf("expected incident status auto_blocked, got %s", got.Status)
	}
}

func TestAttackChain_RiskScoreIsAggregatedThenMultiplied(t *testing.T) {
	e, db, _, _ := testEngineWithAutopilot(t)
	ip := "203.0.113.151"
	base := time.Now().UTC()

	driveFullAttackChain(e, ip, base)

	incidents, err := db.ListIncidents(database.IncidentFilter{SourceIP: ip})
	if err != nil {
		t.Fatalf("ListIncidents failed: %v", err)
	}
	var chainInc *database.Incident
	for i := range incidents {
		if incidents[i].Type == database.IncidentAttackChain {
			chainInc = &incidents[i]
		}
	}
	if chainInc == nil {
		t.Fatalf("expected an %s incident", database.IncidentAttackChain)
	}

	// PortScan(25) + WebDirScan(20) + SSHBruteForce(40) = 85, x1.5 = 127.5
	// -> int(127) before reputation, clamped to 100 overall since 127 > 100.
	if chainInc.RiskScore != 100 {
		t.Errorf("expected aggregated-then-x1.5 score to clamp to 100, got %d", chainInc.RiskScore)
	}
}

func TestAttackChain_PartialSequenceNeverCreatesIncident(t *testing.T) {
	e, db := testEngine(t)
	ip := "203.0.113.152"
	base := time.Now().UTC()

	// Only recon + web probing, no SSH auth-failure stage at all.
	for p := 0; p < thresholds.AttackChainMinDistinctPorts; p++ {
		e.IngestPortTouch(ip, 7000+p, base)
	}
	webTS := base.Add(10 * time.Second)
	for i := 0; i < thresholds.AttackChainMinWebProbes; i++ {
		ts := webTS.Add(time.Duration(i) * time.Second)
		e.IngestWebLogLine(formatWebLine(ip, ts, "/admin", 403, ""))
	}

	incidents, err := db.ListIncidents(database.IncidentFilter{SourceIP: ip})
	if err != nil {
		t.Fatalf("ListIncidents failed: %v", err)
	}
	for _, inc := range incidents {
		if inc.Type == database.IncidentAttackChain {
			t.Fatalf("did not expect an ATTACK_CHAIN incident from a 2-of-3-stage sequence")
		}
	}
}

func TestAttackChain_DedupeSuppressesRepeatIncidents(t *testing.T) {
	e, db := testEngine(t)
	ip := "203.0.113.153"
	base := time.Now().UTC()

	driveFullAttackChain(e, ip, base)
	firstCount := 0
	{
		incidents, _ := db.ListIncidents(database.IncidentFilter{SourceIP: ip})
		for _, inc := range incidents {
			if inc.Type == database.IncidentAttackChain {
				firstCount++
			}
		}
	}
	if firstCount != 1 {
		t.Fatalf("expected exactly 1 ATTACK_CHAIN incident after the first full sequence, got %d", firstCount)
	}

	// Feed one more auth failure immediately after -- the chain condition
	// still holds, but the dedupe cooldown should suppress a duplicate
	// incident from flooding the table.
	e.IngestAuthLogLine(formatAuthFailedLine(ip, base.Add(70*time.Second), 99))

	secondCount := 0
	incidents, _ := db.ListIncidents(database.IncidentFilter{SourceIP: ip})
	for _, inc := range incidents {
		if inc.Type == database.IncidentAttackChain {
			secondCount++
		}
	}
	if secondCount != 1 {
		t.Fatalf("expected dedupe to suppress a second ATTACK_CHAIN incident within the cooldown, got %d total", secondCount)
	}
}

// ---------------------------------------------------------------------------
// Web Scanner Behavior heuristic: Engine-level tests
// ---------------------------------------------------------------------------

func TestWebScannerBehavior_HighFrequencyPlusSuspiciousUA_CreatesIncident(t *testing.T) {
	e, db := testEngine(t)
	ip := "203.0.113.160"
	base := time.Now().UTC()

	for i := 0; i < thresholds.WebScannerMin4xx+1; i++ {
		ts := base.Add(time.Duration(i) * time.Millisecond)
		line := formatWebLine(ip, ts, "/probe"+itoa(i), 404, "Nikto/2.5.0")
		e.IngestWebLogLine(line)
	}

	if got := countIncidents(t, db); got == 0 {
		t.Fatalf("expected at least 1 incident")
	}
	incidents, _ := db.ListIncidents(database.IncidentFilter{SourceIP: ip})
	found := false
	for _, inc := range incidents {
		if inc.Type == database.IncidentWebScanner {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected a %s incident, got types: %+v", database.IncidentWebScanner, incidentTypes(incidents))
	}
}

func TestWebScannerBehavior_MissingUserAgent_CreatesIncident(t *testing.T) {
	e, db := testEngine(t)
	ip := "203.0.113.161"
	base := time.Now().UTC()

	for i := 0; i < thresholds.WebScannerMin4xx+1; i++ {
		ts := base.Add(time.Duration(i) * time.Millisecond)
		// Empty User-Agent field ("-") -- automated tool that never set one.
		line := formatWebLine(ip, ts, "/probe"+itoa(i), 403, "-")
		e.IngestWebLogLine(line)
	}

	incidents, _ := db.ListIncidents(database.IncidentFilter{SourceIP: ip})
	found := false
	for _, inc := range incidents {
		if inc.Type == database.IncidentWebScanner {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected a %s incident from missing-UA + high-frequency 4xx, got types: %+v", database.IncidentWebScanner, incidentTypes(incidents))
	}
}

func TestWebScannerBehavior_HighFrequencyButNormalUA_NoIncident(t *testing.T) {
	e, db := testEngine(t)
	ip := "203.0.113.162"
	base := time.Now().UTC()

	// High frequency of 4xx responses, but a perfectly normal browser UA
	// every time -- the heuristic requires BOTH signals, so this alone
	// must not raise a web-scanner incident (though ruleWebDirScan may
	// still fire independently on sensitive paths -- irrelevant here since
	// we deliberately use a non-sensitive path).
	for i := 0; i < thresholds.WebScannerMin4xx+3; i++ {
		ts := base.Add(time.Duration(i) * time.Millisecond)
		line := formatWebLine(ip, ts, "/some/normal/page", 404, "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0")
		e.IngestWebLogLine(line)
	}

	incidents, _ := db.ListIncidents(database.IncidentFilter{SourceIP: ip})
	for _, inc := range incidents {
		if inc.Type == database.IncidentWebScanner {
			t.Fatalf("did not expect a web-scanner incident when every request carried a normal browser UA")
		}
	}
}

func TestWebScannerBehavior_LowFrequencyWithSuspiciousUA_NoIncident(t *testing.T) {
	e, db := testEngine(t)
	ip := "203.0.113.163"
	base := time.Now().UTC()

	// Suspicious UA, but too few 4xx hits to cross the frequency threshold.
	for i := 0; i < thresholds.WebScannerMin4xx-2; i++ {
		ts := base.Add(time.Duration(i) * time.Millisecond)
		line := formatWebLine(ip, ts, "/probe"+itoa(i), 404, "Nikto/2.5.0")
		e.IngestWebLogLine(line)
	}

	incidents, _ := db.ListIncidents(database.IncidentFilter{SourceIP: ip})
	for _, inc := range incidents {
		if inc.Type == database.IncidentWebScanner {
			t.Fatalf("did not expect a web-scanner incident below the 4xx frequency threshold")
		}
	}
}
