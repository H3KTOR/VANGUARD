package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"vanguard/core/internal/database"
)

func seedIncident(t *testing.T, db *database.DB, typ database.IncidentType, ip string) *database.Incident {
	t.Helper()
	inc := &database.Incident{Type: typ, SourceIP: ip, RiskScore: 50, DetectedAt: time.Now().UTC().Add(-time.Minute),
		Metadata: `{"provenance":{"rule_id":"port_scan","evidence_kind":"observed","limitations":"decoy only"},"password":"hunter2"}`}
	if err := db.CreateIncident(inc); err != nil {
		t.Fatal(err)
	}
	return inc
}

func TestInvestigationAPI_TimelineGraphNotesExport(t *testing.T) {
	ts, db, _, tok := newIntelServer(t)
	inc := seedIncident(t, db, database.IncidentPortScan, "203.0.113.5")
	_ = db.RecordIOCMatch(&database.IOCMatch{IOCID: 3, IncidentID: inc.ID, IOCType: database.IOCIP, Source: "s", Field: "source_ip", Context: "203.0.113.5", SourceIP: "203.0.113.5", Kind: "direct"})
	base := fmt.Sprintf("%s/api/incidents/%d", ts.URL, inc.ID)

	// notes: author comes from the session, text is bounded
	code, n := call(t, "POST", base+"/notes", tok, []byte(`{"text":"checked with network team; password=Sup3rSecret"}`))
	if code != http.StatusCreated || n["author"] != "lab-admin@vanguard.local" && n["author"] == "" {
		t.Fatalf("add note: %d %v", code, n)
	}
	if code, _ := call(t, "POST", base+"/notes", tok, []byte(`{"text":"  "}`)); code != 400 {
		t.Errorf("empty note: %d", code)
	}
	if code, _ := call(t, "POST", base+"/notes", tok, []byte(`{"text":"`+strings.Repeat("x", 2001)+`"}`)); code != 400 {
		t.Errorf("long note: %d", code)
	}
	noteID := int(n["id"].(float64))
	if code, _ := call(t, "PUT", fmt.Sprintf("%s/notes/%d", base, noteID), tok, []byte(`{"text":"updated"}`)); code != 200 {
		t.Errorf("edit: %d", code)
	}
	if code, _ := call(t, "PUT", base+"/notes/9999", tok, []byte(`{"text":"x"}`)); code != 404 {
		t.Errorf("edit missing: %d", code)
	}

	// timeline
	code, tl := call(t, "GET", base+"/timeline?limit=50", tok, nil)
	if code != 200 || tl["total"].(float64) < 3 || len(tl["data_gaps"].([]any)) == 0 {
		t.Fatalf("timeline: %d %v", code, tl)
	}
	entries := tl["entries"].([]any)
	prev := ""
	for _, e := range entries {
		at := e.(map[string]any)["at"].(string)
		if !strings.HasSuffix(at, "Z") {
			t.Errorf("timestamps must be UTC (Z): %s", at)
		}
		if at < prev {
			t.Errorf("entries out of order: %s after %s", at, prev)
		}
		prev = at
	}
	for _, q := range []string{"limit=0", "limit=201", "offset=-1", "offset=zz"} {
		if code, _ := call(t, "GET", base+"/timeline?"+q, tok, nil); code != 400 {
			t.Errorf("timeline %q: %d", q, code)
		}
	}
	if code, _ := call(t, "GET", ts.URL+"/api/incidents/99999/timeline", tok, nil); code != 404 {
		t.Errorf("missing incident: %d", code)
	}

	// graph
	code, g := call(t, "GET", base+"/graph", tok, nil)
	if code != 200 || len(g["edges"].([]any)) != 1 || g["edges"].([]any)[0].(map[string]any)["relation"] != "matched" {
		t.Fatalf("graph: %d %v", code, g)
	}

	// export: redacted, no unrelated incident, attachment
	other := seedIncident(t, db, database.IncidentSQLiXSS, "198.51.100.77")
	req, _ := http.NewRequest("GET", base+"/export", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var buf strings.Builder
	_, _ = fmt.Fprint(&buf, "")
	var ex map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&ex); err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(ex)
	for _, leak := range []string{"hunter2", "Sup3rSecret"} {
		if strings.Contains(string(raw), leak) {
			t.Errorf("export leaked %q", leak)
		}
	}
	if strings.Contains(string(raw), "198.51.100.77") || other.ID == inc.ID {
		t.Error("export must contain only the requested incident")
	}
	if !strings.Contains(resp.Header.Get("Content-Disposition"), "attachment") || ex["format"] != "vanguard-investigation" {
		t.Errorf("export envelope wrong: %v %v", resp.Header, ex["format"])
	}

	// delete
	if code, _ := call(t, "DELETE", fmt.Sprintf("%s/notes/%d", base, noteID), tok, nil); code != 200 {
		t.Errorf("delete: %d", code)
	}
	_, list := call(t, "GET", base+"/notes", tok, nil)
	if list["count"] != float64(0) {
		t.Errorf("deleted note still listed: %v", list)
	}
}

func TestInvestigationAPI_QueryValidationAndResults(t *testing.T) {
	ts, db, _, tok := newIntelServer(t)
	a := seedIncident(t, db, database.IncidentPortScan, "203.0.113.20")
	seedIncident(t, db, database.IncidentAttackChain, "203.0.113.21")
	_ = db.AddIncidentEvent(database.IncidentEvent{IncidentID: a.ID, Kind: database.EventVerification, Outcome: "failed", Actor: "autopilot"})

	_, all := call(t, "GET", ts.URL+"/api/investigate/incidents", tok, nil)
	if all["count"] != float64(2) || all["window_defaulted"] != true || len(all["retention_notes"].([]any)) == 0 {
		t.Fatalf("default query: %v", all)
	}
	_, vf := call(t, "GET", ts.URL+"/api/investigate/incidents?verification_outcome=failed", tok, nil)
	if vf["count"] != float64(1) {
		t.Fatalf("verification filter: %v", vf)
	}
	_, ck := call(t, "GET", ts.URL+"/api/investigate/incidents?evidence_kind=correlated", tok, nil)
	if ck["count"] != float64(1) {
		t.Fatalf("evidence_kind filter: %v", ck)
	}
	// Injection-shaped values are rejected by validation (400); the query
	// layer additionally binds every value as a parameter (see
	// investigate.TestQuery_FiltersBoundsAndWindow).
	_, unknownRule := call(t, "GET", ts.URL+"/api/investigate/incidents?rule=no_such_rule", tok, nil)
	if unknownRule["count"] != float64(0) {
		t.Fatalf("unknown rule must simply match nothing: %v", unknownRule)
	}
	bad := []string{
		"status=zzz", "severity=URGENT", "evidence_kind=maybe", "response_outcome=ok", "verification_outcome=ok",
		"id=abc", "id=0", "ioc_id=-1", "ip=nope", "risk_min=-1", "risk_max=101", "risk_min=60&risk_max=10",
		"has_ioc_match=maybe", "since=yesterday", "until=1", "since=2026-10-02T00:00:00Z&until=2026-10-01T00:00:00Z",
		"limit=0", "limit=201", "offset=10001", "rule=a%20b", "rule=" + strings.Repeat("a", 70),
	}
	for _, q := range bad {
		if code, _ := call(t, "GET", ts.URL+"/api/investigate/incidents?"+q, tok, nil); code != 400 {
			t.Errorf("%q should be 400, got %d", q, code)
		}
	}
	for _, p := range []string{"/api/investigate/incidents", fmt.Sprintf("/api/incidents/%d/timeline", a.ID), fmt.Sprintf("/api/incidents/%d/export", a.ID)} {
		resp, _ := http.Get(ts.URL + p)
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("%s must require auth: %d", p, resp.StatusCode)
		}
	}
}
