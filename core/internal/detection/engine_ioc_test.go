package detection

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"vanguard/core/internal/database"
	"vanguard/core/internal/firewall"
	"vanguard/core/internal/hostsec"
	"vanguard/core/internal/intel"
	"vanguard/core/internal/thresholds"
)

func iocFeed(source string, recs ...string) string {
	return fmt.Sprintf(`{"format":"vanguard-ioc","version":1,"source":%q,"indicators":[%s]}`, source, strings.Join(recs, ","))
}

func iocRec(typ, val string, extra ...string) string {
	s := fmt.Sprintf(`{"type":%q,"value":%q`, typ, val)
	for _, e := range extra {
		s += "," + e
	}
	return s + "}"
}

func iocEngineAt(t *testing.T, path string, feeds ...string) (*Engine, *database.DB, *intel.Matcher) {
	t.Helper()
	db, err := database.Open(database.Config{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if s, err := db.DB.DB(); err == nil {
			s.Close()
		}
	})
	for _, f := range feeds {
		if _, err := intel.Import(db, strings.NewReader(f), intel.ImportOptions{}); err != nil {
			t.Fatal(err)
		}
	}
	m := intel.NewMatcher(db)
	return NewEngine(Config{DB: db, IOC: m, ThreatIntel: m}), db, m
}

func iocEngine(t *testing.T, feeds ...string) (*Engine, *database.DB, *intel.Matcher) {
	return iocEngineAt(t, filepath.Join(t.TempDir(), "e.db"), feeds...)
}

func httpEv(ip, host, path string) *Event {
	return &Event{Kind: EventHTTPRequest, SourceIP: ip, Host: host, Path: path, Method: "GET", StatusCode: 200, Timestamp: time.Now().UTC()}
}

func incidentsOfType(t *testing.T, db *database.DB, typ database.IncidentType) []database.Incident {
	t.Helper()
	all, err := db.ListIncidents(database.IncidentFilter{Type: typ, Limit: 500})
	if err != nil {
		t.Fatal(err)
	}
	return all
}

func metaMap(t *testing.T, inc database.Incident) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(inc.Metadata), &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func TestIOC_IPMatchCreatesExplainableIncident(t *testing.T) {
	e, db, _ := iocEngine(t, iocFeed("feed-a", iocRec("ip", "203.0.113.7", `"confidence":"high"`, `"description":"known scanner"`)))
	e.handleEvent(httpEv("203.0.113.7", "", "/login?password=hunter2&token=abc"))

	incs := incidentsOfType(t, db, database.IncidentIOCMatch)
	if len(incs) != 1 {
		t.Fatalf("want 1 ioc_match incident, got %d", len(incs))
	}
	inc := incs[0]
	if inc.SourceIP != "203.0.113.7" {
		t.Errorf("source ip %s", inc.SourceIP)
	}
	m := metaMap(t, inc)
	ioc := m["ioc"].(map[string]any)
	if ioc["source"] != "feed-a" || ioc["confidence_from_source"] != "high" || ioc["description"] != "known scanner" {
		t.Errorf("indicator provenance missing: %v", ioc)
	}
	if m["match_kind"] != "direct" || m["matched_field"] != "source_ip" || m["matched_value"] != "203.0.113.7" {
		t.Errorf("match context wrong: %v", m)
	}
	prov := m["provenance"].(map[string]any)
	if prov["evidence_kind"] != "observed" || !strings.Contains(prov["limitations"].(string), "not that the host is compromised") {
		t.Errorf("provenance must state what a match does not prove: %v", prov)
	}
	if strings.Contains(inc.Metadata, "hunter2") || strings.Contains(inc.Metadata, "token=abc") || strings.Contains(inc.Metadata, "password") {
		t.Errorf("request secrets leaked into IOC evidence: %s", inc.Metadata)
	}
	// hunting history row
	rows, _ := db.HuntMatches(database.HuntFilter{SourceIP: "203.0.113.7"})
	if len(rows) != 1 || rows[0].Kind != "direct" || rows[0].IncidentID != inc.ID || rows[0].IncidentType != database.IncidentIOCMatch {
		t.Fatalf("hunt row wrong: %+v", rows)
	}
}

func TestIOC_RiskGradedByConfidenceAndCapped(t *testing.T) {
	score := func(conf string) int {
		extra := []string{}
		if conf != "" {
			extra = append(extra, `"confidence":"`+conf+`"`)
		}
		e, db, _ := iocEngine(t, iocFeed("f", iocRec("ip", "203.0.113.9", extra...)))
		e.handleEvent(httpEv("203.0.113.9", "", "/"))
		return incidentsOfType(t, db, database.IncidentIOCMatch)[0].RiskScore
	}
	high, med, none, low := score("high"), score("medium"), score(""), score("low")
	if !(high > med && med > none && none > low) {
		t.Fatalf("confidence must grade risk: high=%d medium=%d unrated=%d low=%d", high, med, none, low)
	}
	if high > thresholds.MaxIOCOnlyRisk {
		t.Fatalf("IOC-only risk %d exceeds the cap %d", high, thresholds.MaxIOCOnlyRisk)
	}
	if high >= firewall.DefaultConfig().MinRiskScoreToBan {
		t.Fatalf("IOC-only incident (%d) must stay below the auto-ban threshold", high)
	}
}

func TestIOC_NeverTriggersAutopilotBan(t *testing.T) {
	db, err := database.Open(database.Config{Path: filepath.Join(t.TempDir(), "ap.db")})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { s, _ := db.DB.DB(); s.Close() }()
	exec := firewall.NewMockExecutor()
	ap := firewall.NewAutopilot(db, exec, firewall.DefaultConfig())
	_, _ = intel.Import(db, strings.NewReader(iocFeed("f", iocRec("ip", "203.0.113.10", `"confidence":"high"`))), intel.ImportOptions{})
	m := intel.NewMatcher(db)
	e := NewEngine(Config{DB: db, IOC: m, ThreatIntel: m, Notifier: ap})
	for i := 0; i < 5; i++ {
		e.handleEvent(httpEv("203.0.113.10", "", "/"))
	}
	if len(exec.Calls) != 0 {
		t.Fatalf("an IOC match alone must not touch the firewall: %v", exec.Calls)
	}
}

func TestIOC_BenignNearMatchesDoNotTrigger(t *testing.T) {
	e, db, _ := iocEngine(t, iocFeed("f", iocRec("ip", "203.0.113.20"), iocRec("url", "http://evil.example.com/a?b=1")))
	for _, ev := range []*Event{
		httpEv("203.0.113.200", "good.example.com", "/"),
		httpEv("203.0.113.2", "", "/"),
		httpEv("198.51.100.20", "", "/"),
		httpEv("203.0.113.21", "notevil.example.com", "/a?b=1"),
		httpEv("203.0.113.22", "a.evil.example.com", "/a?b=1"),
		httpEv("203.0.113.23", "evil.example.com.attacker.net", "/a?b=1"),
		httpEv("203.0.113.24", "evil.example.com", "/a?b=2"),
		httpEv("203.0.113.25", "evil.example.com", "/a"),
		httpEv("203.0.113.26", "", "/evil.example.com/a?b=1"), // Host unobserved
	} {
		e.handleEvent(ev)
	}
	if n := len(incidentsOfType(t, db, database.IncidentIOCMatch)); n != 0 {
		t.Fatalf("near-misses produced %d ioc_match incident(s)", n)
	}
}

func TestIOC_DomainNearMatchesDoNotTrigger(t *testing.T) {
	e, db, _ := iocEngine(t, iocFeed("f", iocRec("domain", "evil.example.com")))
	for i, h := range []string{"notevil.example.com", "a.evil.example.com", "evil.example.com.attacker.net", "evil.example.co", "example.com", ""} {
		e.handleEvent(httpEv(fmt.Sprintf("203.0.113.%d", 150+i), h, "/"))
	}
	if n := len(incidentsOfType(t, db, database.IncidentIOCMatch)); n != 0 {
		t.Fatalf("domain near-misses produced %d incident(s)", n)
	}
	e.handleEvent(httpEv("203.0.113.160", "EVIL.example.com:8080", "/"))
	if n := len(incidentsOfType(t, db, database.IncidentIOCMatch)); n != 1 {
		t.Fatalf("exact host (case/port-insensitive) should match once, got %d", n)
	}
}

func TestIOC_DomainAndURLMatchNeedLoggedHost(t *testing.T) {
	e, db, _ := iocEngine(t, iocFeed("f", iocRec("domain", "evil.example.com"), iocRec("url", "https://evil.example.com/dl/x.bin")))
	e.handleEvent(httpEv("203.0.113.30", "", "/dl/x.bin")) // Host not logged => not observable
	if n := len(incidentsOfType(t, db, database.IncidentIOCMatch)); n != 0 {
		t.Fatalf("unobservable Host must not match, got %d", n)
	}
	e.handleEvent(httpEv("203.0.113.30", "Evil.Example.com:443", "/dl/x.bin"))
	incs := incidentsOfType(t, db, database.IncidentIOCMatch)
	if len(incs) != 2 {
		t.Fatalf("domain + url should both match once Host is logged, got %d", len(incs))
	}
	fields := map[string]bool{}
	for _, i := range incs {
		fields[metaMap(t, i)["matched_field"].(string)] = true
	}
	if !fields["host"] || !fields["url"] {
		t.Fatalf("fields: %v", fields)
	}
}

func TestIOC_ExpiredAndDisabledNeverMatch(t *testing.T) {
	e, db, m := iocEngine(t, iocFeed("f",
		iocRec("ip", "203.0.113.41", `"expires_at":"2099-01-01T00:00:00Z"`),
		iocRec("ip", "203.0.113.42")))
	// expire the first by moving the matcher clock past its expiry (snapshot is stale on purpose)
	m.SetClock(func() time.Time { return time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC) })
	e.handleEvent(httpEv("203.0.113.41", "", "/"))
	if n := len(incidentsOfType(t, db, database.IncidentIOCMatch)); n != 0 {
		t.Fatalf("expired indicator matched: %d", n)
	}
	// operator disables the other
	rows, _ := db.ListIOCs(database.IOCFilter{Value: "203.0.113.42"})
	_, _ = db.SetIOCEnabled(rows[0].ID, false)
	_ = m.Reload()
	e.handleEvent(httpEv("203.0.113.42", "", "/"))
	if n := len(incidentsOfType(t, db, database.IncidentIOCMatch)); n != 0 {
		t.Fatalf("disabled indicator matched: %d", n)
	}
}

func TestIOC_DedupeAndRecurrence(t *testing.T) {
	e, db, _ := iocEngine(t, iocFeed("f", iocRec("ip", "203.0.113.50")))
	e.iocDedupe = newDedupeWindow(60 * time.Millisecond)
	for i := 0; i < 25; i++ {
		e.handleEvent(httpEv("203.0.113.50", "", "/"))
	}
	if n := len(incidentsOfType(t, db, database.IncidentIOCMatch)); n != 1 {
		t.Fatalf("sustained matches must dedupe to 1, got %d", n)
	}
	time.Sleep(90 * time.Millisecond)
	e.handleEvent(httpEv("203.0.113.50", "", "/"))
	if n := len(incidentsOfType(t, db, database.IncidentIOCMatch)); n != 2 {
		t.Fatalf("recurrence after the cooldown must be reported again, got %d", n)
	}
}

func TestIOC_MultipleIndicatorsOneEventAndMultipleActors(t *testing.T) {
	e, db, _ := iocEngine(t,
		iocFeed("a", iocRec("ip", "203.0.113.60")),
		iocFeed("b", iocRec("ip", "203.0.113.60"), iocRec("domain", "evil.example.com")))
	e.handleEvent(httpEv("203.0.113.60", "evil.example.com", "/"))
	e.handleEvent(httpEv("203.0.113.61", "ok.example.com", "/")) // unrelated actor
	incs := incidentsOfType(t, db, database.IncidentIOCMatch)
	if len(incs) != 3 { // ip@a, ip@b, domain@b
		t.Fatalf("want 3 distinct indicator matches, got %d", len(incs))
	}
	for _, i := range incs {
		if i.SourceIP != "203.0.113.60" {
			t.Fatalf("unrelated actor got an incident: %s", i.SourceIP)
		}
	}
}

func TestIOC_IPv6AndMappedForms(t *testing.T) {
	e, db, _ := iocEngine(t, iocFeed("f", iocRec("ip", "2001:db8::bad"), iocRec("ip", "203.0.113.70")))
	e.handleEvent(httpEv("2001:DB8::BAD", "", "/"))
	e.handleEvent(httpEv("::ffff:203.0.113.70", "", "/"))
	e.handleEvent(httpEv("2001:db8::bae", "", "/"))
	if n := len(incidentsOfType(t, db, database.IncidentIOCMatch)); n != 2 {
		t.Fatalf("want 2 matches (v6 + mapped v4), got %d", n)
	}
}

func TestIOC_EnrichesUnrelatedIncidentAndRaisesReputationOnlyForTrustedIOC(t *testing.T) {
	e, db, _ := iocEngine(t, iocFeed("f",
		iocRec("ip", "203.0.113.80", `"confidence":"high"`),
		iocRec("ip", "203.0.113.81", `"confidence":"low"`)))
	trav := "/../../etc/passwd"
	e.handleEvent(httpEv("203.0.113.80", "", trav))
	e.handleEvent(httpEv("203.0.113.81", "", trav))
	e.handleEvent(httpEv("203.0.113.82", "", trav)) // clean control

	risk := map[string]int{}
	for _, inc := range incidentsOfType(t, db, database.IncidentPathTraversal) {
		risk[inc.SourceIP] = inc.RiskScore
		m := metaMap(t, inc)
		_, enriched := m["ioc_matches"]
		if wantEnriched := inc.SourceIP != "203.0.113.82"; enriched != wantEnriched {
			t.Errorf("%s: enrichment=%v want %v", inc.SourceIP, enriched, wantEnriched)
		}
	}
	if risk["203.0.113.80"] <= risk["203.0.113.82"] {
		t.Errorf("high-confidence IOC should raise the behavioral incident's reputation component: %v", risk)
	}
	if risk["203.0.113.81"] != risk["203.0.113.82"] {
		t.Errorf("low-confidence IOC must not change unrelated risk: %v", risk)
	}
	rows, _ := db.HuntMatches(database.HuntFilter{SourceIP: "203.0.113.80", Kind: "enrichment"})
	if len(rows) != 1 || rows[0].IncidentType != database.IncidentPathTraversal {
		t.Fatalf("enrichment hunt row wrong: %+v", rows)
	}
}

func TestIOC_HostFindingHashAndRemoteAddr(t *testing.T) {
	hash := strings.Repeat("ab", 32)
	e, db, _ := iocEngine(t, iocFeed("f", iocRec("sha256", hash), iocRec("ip", "198.51.100.99")))
	e.ReportHostFinding(hostsec.Finding{Type: database.IncidentFIMChange, Change: "modified", Subject: "/usr/bin/x", SHA256: []string{strings.ToUpper(hash)}})
	e.ReportHostFinding(hostsec.Finding{Type: database.IncidentSuspiciousProcess, Change: "p", Subject: "pid:1", RemoteAddrs: []string{"198.51.100.99:4444"}})
	e.ReportHostFinding(hostsec.Finding{Type: database.IncidentFIMChange, Change: "modified", Subject: "/usr/bin/y", SHA256: []string{strings.Repeat("cd", 32)}})
	incs := incidentsOfType(t, db, database.IncidentIOCMatch)
	if len(incs) != 2 {
		t.Fatalf("want sha256 + remote_addr matches, got %d", len(incs))
	}
	for _, i := range incs {
		if i.SourceIP != database.HostLocalIP {
			t.Errorf("host-derived match must be host-local, got %s", i.SourceIP)
		}
	}
}

func TestIOC_MalformedAndMissingTelemetryDoNotCrashOrMatch(t *testing.T) {
	e, db, _ := iocEngine(t, iocFeed("f", iocRec("ip", "203.0.113.90")))
	for _, ev := range []*Event{
		{Kind: EventHTTPRequest, SourceIP: "not-an-ip"},
		{Kind: EventHTTPRequest, SourceIP: "203.0.113.90/32"},
		{Kind: EventHTTPRequest, SourceIP: "", Host: "x"},
		httpEv("203.0.113.91", strings.Repeat("a", 5000), "/"),
		httpEv("203.0.113.91", "[::1", "/%zz"),
	} {
		e.handleEvent(ev)
	}
	if n := len(incidentsOfType(t, db, database.IncidentIOCMatch)); n != 0 {
		t.Fatalf("got %d", n)
	}
}

func TestIOC_NilMatcherEngineUnaffected(t *testing.T) {
	e, db := testEngine(t)
	e.handleEvent(httpEv("203.0.113.100", "", "/../../etc/passwd"))
	if len(incidentsOfType(t, db, database.IncidentPathTraversal)) != 1 || len(incidentsOfType(t, db, database.IncidentIOCMatch)) != 0 {
		t.Fatal("engine without intelligence must behave exactly as before")
	}
}

func TestIOC_RestartPersistence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "r.db")
	_, db, _ := iocEngineAt(t, path, iocFeed("f", iocRec("ip", "203.0.113.110")))
	s, _ := db.DB.DB()
	s.Close()
	e2, db2, _ := iocEngineAt(t, path) // fresh process over the same file
	e2.handleEvent(httpEv("203.0.113.110", "", "/"))
	if n := len(incidentsOfType(t, db2, database.IncidentIOCMatch)); n != 1 {
		t.Fatalf("indicator must survive restart, got %d incidents", n)
	}
}

func TestIOC_AnalystLifecycleStillApplies(t *testing.T) {
	e, db, _ := iocEngine(t, iocFeed("f", iocRec("ip", "203.0.113.120")))
	e.handleEvent(httpEv("203.0.113.120", "", "/"))
	inc := incidentsOfType(t, db, database.IncidentIOCMatch)[0]
	if _, err := db.TransitionIncident(inc.ID, database.StatusFalsePositive, "analyst", "shared proxy"); err != nil {
		t.Fatal(err)
	}
	cur, _ := db.GetIncident(inc.ID)
	if cur.Status != database.StatusFalsePositive {
		t.Fatal("ioc incidents use the normal lifecycle")
	}
}
