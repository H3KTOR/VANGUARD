package detection

import (
	"testing"
	"time"

	"vanguard/core/internal/database"
	"vanguard/core/internal/thresholds"
)

// ---------------------------------------------------------------------------
// Web Attack Chain Correlation (Phase 3, Section 14): engine-level
// integration tests driving the real Engine via IngestWebLogLine/
// IngestAuthLogLine (not the pure ChainTracker helpers directly), mirroring
// the style of chain_integration_test.go's original ATTACK_CHAIN tests.
// ---------------------------------------------------------------------------

// driveFullWebAttackChain feeds a complete, correctly-ordered
// web-probing -> auth-probing -> exploitation sequence for ip into e,
// through the real log-ingestion entry points, returning the timestamp of
// the final (triggering) event.
func driveFullWebAttackChain(e *Engine, ip string, base time.Time) time.Time {
	webTS := base
	for i := 0; i < thresholds.WebAttackChainMinWebProbes; i++ {
		ts := webTS.Add(time.Duration(i) * time.Second)
		e.IngestWebLogLine(formatWebLine(ip, ts, "/probe"+itoa(i), 404, "python-requests/2.28"))
	}

	authTS := webTS.Add(30 * time.Second)
	for i := 0; i < thresholds.WebAttackChainMinAuthFailures; i++ {
		ts := authTS.Add(time.Duration(i) * time.Second)
		e.IngestAuthLogLine(formatAuthFailedLine(ip, ts, i))
	}

	exploitTS := authTS.Add(30 * time.Second)
	e.IngestWebLogLine(formatWebLine(ip, exploitTS, "/uploads/shell.php?cmd=whoami", 200, "curl/8.0"))
	return exploitTS
}

func findWebAttackChain(incidents []database.Incident) *database.Incident {
	for i := range incidents {
		if incidents[i].Type == database.IncidentWebAttackChain {
			return &incidents[i]
		}
	}
	return nil
}

func TestWebAttackChain_FullOrderedSequence_CreatesIncident(t *testing.T) {
	e, db := testEngine(t)
	ip := "203.0.113.170"
	base := time.Now().UTC()

	driveFullWebAttackChain(e, ip, base)

	incidents, err := db.ListIncidents(database.IncidentFilter{SourceIP: ip})
	if err != nil {
		t.Fatalf("ListIncidents failed: %v", err)
	}
	found := findWebAttackChain(incidents)
	if found == nil {
		t.Fatalf("expected a %s incident, got types: %+v", database.IncidentWebAttackChain, incidentTypes(incidents))
	}
	if found.RiskScore < 50 {
		t.Errorf("expected the aggregated+1.5x chain score to be substantial, got %d", found.RiskScore)
	}
}

func TestWebAttackChain_RiskScoreReflectsChainAggregation(t *testing.T) {
	e, db := testEngine(t)
	ip := "203.0.113.171"
	base := time.Now().UTC()

	driveFullWebAttackChain(e, ip, base)

	incidents, _ := db.ListIncidents(database.IncidentFilter{SourceIP: ip})
	found := findWebAttackChain(incidents)
	if found == nil {
		t.Fatalf("expected a %s incident", database.IncidentWebAttackChain)
	}

	// WebDirScan(20) + SSHBruteForce(40) + WebShellIndicator(base
	// severity, low) aggregated then x1.5 (thresholds.AttackChainRiskMultiplier)
	// should land materially above any single constituent's own base
	// score and should never silently fall back to a plain single-event
	// score -- i.e. it must be scored via ScoreChain, not risk.Score.
	if found.RiskScore <= 40 {
		t.Errorf("expected chain-aggregated score to exceed a lone SSHBruteForce base score (40), got %d", found.RiskScore)
	}
}

func TestWebAttackChain_MissingWebProbingStage_NoIncident(t *testing.T) {
	e, db := testEngine(t)
	ip := "203.0.113.172"
	base := time.Now().UTC()

	// Only auth-failures + an exploit-shaped request -- no 403/404
	// web-probing stage at all.
	authTS := base
	for i := 0; i < thresholds.WebAttackChainMinAuthFailures; i++ {
		e.IngestAuthLogLine(formatAuthFailedLine(ip, authTS.Add(time.Duration(i)*time.Second), i))
	}
	e.IngestWebLogLine(formatWebLine(ip, authTS.Add(30*time.Second), "/uploads/shell.php?cmd=whoami", 200, "curl/8.0"))

	incidents, _ := db.ListIncidents(database.IncidentFilter{SourceIP: ip})
	if found := findWebAttackChain(incidents); found != nil {
		t.Fatalf("did not expect a %s incident without a web-probing stage", database.IncidentWebAttackChain)
	}
}

func TestWebAttackChain_MissingAuthProbingStage_NoIncident(t *testing.T) {
	e, db := testEngine(t)
	ip := "203.0.113.173"
	base := time.Now().UTC()

	// Only web-probing + an exploit-shaped request -- no SSH auth
	// failures at all.
	webTS := base
	for i := 0; i < thresholds.WebAttackChainMinWebProbes; i++ {
		e.IngestWebLogLine(formatWebLine(ip, webTS.Add(time.Duration(i)*time.Second), "/probe"+itoa(i), 404, "python-requests/2.28"))
	}
	e.IngestWebLogLine(formatWebLine(ip, webTS.Add(30*time.Second), "/uploads/shell.php?cmd=whoami", 200, "curl/8.0"))

	incidents, _ := db.ListIncidents(database.IncidentFilter{SourceIP: ip})
	if found := findWebAttackChain(incidents); found != nil {
		t.Fatalf("did not expect a %s incident without an auth-probing stage", database.IncidentWebAttackChain)
	}
}

func TestWebAttackChain_MissingExploitationStage_NoIncident(t *testing.T) {
	e, db := testEngine(t)
	ip := "203.0.113.174"
	base := time.Now().UTC()

	// Web-probing + auth-probing, but no web-shell/SSRF-shaped request
	// ever arrives -- this is exactly the pre-existing (non-web)
	// ATTACK_CHAIN's territory if a recon stage were present, but here
	// with no recon stage AND no exploitation stage, WEB_ATTACK_CHAIN
	// must not fire either.
	webTS := base
	for i := 0; i < thresholds.WebAttackChainMinWebProbes; i++ {
		e.IngestWebLogLine(formatWebLine(ip, webTS.Add(time.Duration(i)*time.Second), "/probe"+itoa(i), 404, "python-requests/2.28"))
	}
	authTS := webTS.Add(30 * time.Second)
	for i := 0; i < thresholds.WebAttackChainMinAuthFailures; i++ {
		e.IngestAuthLogLine(formatAuthFailedLine(ip, authTS.Add(time.Duration(i)*time.Second), i))
	}

	incidents, _ := db.ListIncidents(database.IncidentFilter{SourceIP: ip})
	if found := findWebAttackChain(incidents); found != nil {
		t.Fatalf("did not expect a %s incident without an exploitation stage", database.IncidentWebAttackChain)
	}
}

func TestWebAttackChain_WrongOrder_ExploitBeforeWebProbing_NoIncident(t *testing.T) {
	e, db := testEngine(t)
	ip := "203.0.113.175"
	base := time.Now().UTC()

	// Exploitation-shaped request arrives FIRST, then web-probing, then
	// auth-probing -- the required order is web -> auth -> exploit, so
	// this must not match.
	e.IngestWebLogLine(formatWebLine(ip, base, "/uploads/shell.php?cmd=whoami", 200, "curl/8.0"))

	webTS := base.Add(10 * time.Second)
	for i := 0; i < thresholds.WebAttackChainMinWebProbes; i++ {
		e.IngestWebLogLine(formatWebLine(ip, webTS.Add(time.Duration(i)*time.Second), "/probe"+itoa(i), 404, "python-requests/2.28"))
	}
	authTS := webTS.Add(30 * time.Second)
	for i := 0; i < thresholds.WebAttackChainMinAuthFailures; i++ {
		e.IngestAuthLogLine(formatAuthFailedLine(ip, authTS.Add(time.Duration(i)*time.Second), i))
	}

	incidents, _ := db.ListIncidents(database.IncidentFilter{SourceIP: ip})
	if found := findWebAttackChain(incidents); found != nil {
		t.Fatalf("did not expect a %s incident when exploitation precedes web-probing", database.IncidentWebAttackChain)
	}
}

func TestWebAttackChain_SSRFIndicatorAsExploitationStage_CreatesIncident(t *testing.T) {
	e, db := testEngine(t)
	ip := "203.0.113.176"
	base := time.Now().UTC()

	webTS := base
	for i := 0; i < thresholds.WebAttackChainMinWebProbes; i++ {
		e.IngestWebLogLine(formatWebLine(ip, webTS.Add(time.Duration(i)*time.Second), "/probe"+itoa(i), 404, "python-requests/2.28"))
	}
	authTS := webTS.Add(30 * time.Second)
	for i := 0; i < thresholds.WebAttackChainMinAuthFailures; i++ {
		e.IngestAuthLogLine(formatAuthFailedLine(ip, authTS.Add(time.Duration(i)*time.Second), i))
	}
	// Exploitation stage this time is an SSRF-Indicator-shaped request
	// (not a web-shell one), proving RecordExploitSignal is genuinely
	// shared between both feed-in points.
	e.IngestWebLogLine(formatWebLine(ip, authTS.Add(30*time.Second), "/fetch?url=http://169.254.169.254/latest/meta-data/", 200, "curl/8.0"))

	incidents, _ := db.ListIncidents(database.IncidentFilter{SourceIP: ip})
	if found := findWebAttackChain(incidents); found == nil {
		t.Fatalf("expected a %s incident when the exploitation stage is an SSRF-Indicator-shaped request, got types: %+v", database.IncidentWebAttackChain, incidentTypes(incidents))
	}
}

func TestWebAttackChain_DedupeSuppressesRepeatIncidents(t *testing.T) {
	e, db := testEngine(t)
	ip := "203.0.113.177"
	base := time.Now().UTC()

	driveFullWebAttackChain(e, ip, base)

	firstCount := 0
	{
		incidents, _ := db.ListIncidents(database.IncidentFilter{SourceIP: ip})
		for _, inc := range incidents {
			if inc.Type == database.IncidentWebAttackChain {
				firstCount++
			}
		}
	}
	if firstCount != 1 {
		t.Fatalf("expected exactly 1 %s incident after the first full sequence, got %d", database.IncidentWebAttackChain, firstCount)
	}

	// One more exploitation-shaped request immediately after -- the
	// chain condition still holds, but dedupe should suppress a
	// duplicate incident from flooding the table.
	e.IngestWebLogLine(formatWebLine(ip, base.Add(90*time.Second), "/uploads/shell2.php?cmd=id", 200, "curl/8.0"))

	secondCount := 0
	incidents, _ := db.ListIncidents(database.IncidentFilter{SourceIP: ip})
	for _, inc := range incidents {
		if inc.Type == database.IncidentWebAttackChain {
			secondCount++
		}
	}
	if secondCount != 1 {
		t.Fatalf("expected dedupe to suppress a second %s incident within the cooldown, got %d total", database.IncidentWebAttackChain, secondCount)
	}
}

func TestWebAttackChain_PerIPIsolation(t *testing.T) {
	e, db := testEngine(t)
	ipA := "203.0.113.178"
	ipB := "203.0.113.179"
	base := time.Now().UTC()

	// Full sequence for ipA only.
	driveFullWebAttackChain(e, ipA, base)

	// ipB gets only the web-probing stage.
	for i := 0; i < thresholds.WebAttackChainMinWebProbes; i++ {
		e.IngestWebLogLine(formatWebLine(ipB, base.Add(time.Duration(i)*time.Second), "/probe"+itoa(i), 404, "python-requests/2.28"))
	}

	incidentsA, _ := db.ListIncidents(database.IncidentFilter{SourceIP: ipA})
	if findWebAttackChain(incidentsA) == nil {
		t.Fatalf("expected ipA to have a %s incident", database.IncidentWebAttackChain)
	}
	incidentsB, _ := db.ListIncidents(database.IncidentFilter{SourceIP: ipB})
	if found := findWebAttackChain(incidentsB); found != nil {
		t.Fatalf("did not expect ipB (only web-probing stage) to have a %s incident -- per-IP state must be isolated", database.IncidentWebAttackChain)
	}
}

func TestWebAttackChain_DoesNotRequireRegularAttackChainToAlsoFire(t *testing.T) {
	// A pure web-application attacker who never touches multiple TCP
	// ports (no recon/port-scan stage at all) must still be able to
	// trigger WEB_ATTACK_CHAIN, even though the original (Task 3)
	// ATTACK_CHAIN -- which DOES require a recon stage -- never fires.
	e, db := testEngine(t)
	ip := "203.0.113.180"
	base := time.Now().UTC()

	driveFullWebAttackChain(e, ip, base)

	incidents, _ := db.ListIncidents(database.IncidentFilter{SourceIP: ip})
	if findWebAttackChain(incidents) == nil {
		t.Fatalf("expected a %s incident even with no recon/port-scan stage", database.IncidentWebAttackChain)
	}
	for _, inc := range incidents {
		if inc.Type == database.IncidentAttackChain {
			t.Fatalf("did not expect the original recon-requiring %s to also fire with zero port touches", database.IncidentAttackChain)
		}
	}
}

// TestWebAttackChain_SingleWeakSignalWebShellPath_DuringWebProbing_DoesNotPrematurelyFeedExploitStage
// is a regression test for a real bug found by the Docker lab's end-to-end
// run (lab/run-tests.sh Scenario A's own web-probing stage legitimately
// requests "/phpmyadmin/index.php" as one of its ordinary 404 recon
// probes -- an entirely unremarkable path that happens to end in ".php",
// classifyWebShellRequest's WEAKEST single signal). Before the fix,
// ruleWebShellIndicator fed ANY sig.any()-shaped match into
// RecordExploitSignal, so this single ordinary web-probing request was
// wrongly recorded as Exploitation-stage evidence BEFORE the auth-probing
// stage even happened, permanently corrupting the required
// web -> auth -> exploit sequence for that attack window and causing the
// Web Attack Chain scenario to never fire even after a genuine
// multi-signal web-shell request arrived later. The fix requires >= 2 of
// the 3 independent signals (see ruleWebShellIndicator's doc comment) to
// count as Exploitation-stage evidence, while leaving the standalone Web
// Shell Indicator incident's own single-signal-triggers-a-LOW/MEDIUM-
// finding behavior completely unchanged.
func TestWebAttackChain_SingleWeakSignalWebShellPath_DuringWebProbing_DoesNotPrematurelyFeedExploitStage(t *testing.T) {
	e, db := testEngine(t)
	ip := "203.0.113.181"
	base := time.Now().UTC()

	// Web-probing stage: one of the requests is "/phpmyadmin/index.php"
	// -- a single-signal (extension-only) web-shell-shaped path, exactly
	// like the real lab scenario that exposed this bug.
	webTS := base
	paths := []string{"/wp-login.php", "/phpmyadmin/index.php", "/.env"}
	for i, p := range paths {
		e.IngestWebLogLine(formatWebLine(ip, webTS.Add(time.Duration(i)*time.Second), p, 404, "curl/8.0"))
	}

	// Auth-probing stage, well after the web-probing stage.
	authTS := webTS.Add(30 * time.Second)
	for i := 0; i < thresholds.WebAttackChainMinAuthFailures; i++ {
		e.IngestAuthLogLine(formatAuthFailedLine(ip, authTS.Add(time.Duration(i)*time.Second), i))
	}

	// At this point NO genuine multi-signal exploitation-stage request
	// has occurred yet -- only the incidental single-signal ".php" hit
	// during web-probing. The chain must NOT have matched from that
	// alone.
	incidentsBeforeExploit, _ := db.ListIncidents(database.IncidentFilter{SourceIP: ip})
	if found := findWebAttackChain(incidentsBeforeExploit); found != nil {
		t.Fatalf("did not expect a %s incident from a single-signal web-probing-stage \".php\" path alone (before any real exploitation-stage request)", database.IncidentWebAttackChain)
	}

	// NOW a genuine multi-signal (upload-path + suspicious query param +
	// extension) exploitation-stage request arrives, strictly after the
	// auth-probing stage -- the chain should complete correctly.
	exploitTS := authTS.Add(30 * time.Second)
	e.IngestWebLogLine(formatWebLine(ip, exploitTS, "/uploads/shell.php?cmd=whoami", 200, "curl/8.0"))

	incidentsAfterExploit, _ := db.ListIncidents(database.IncidentFilter{SourceIP: ip})
	if found := findWebAttackChain(incidentsAfterExploit); found == nil {
		t.Fatalf("expected a %s incident once a genuine multi-signal exploitation-stage request arrived in correct order, got types: %+v", database.IncidentWebAttackChain, incidentTypes(incidentsAfterExploit))
	}
}
