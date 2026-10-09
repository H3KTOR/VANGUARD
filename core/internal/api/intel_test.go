package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"vanguard/core/internal/auth"
	"vanguard/core/internal/database"
	"vanguard/core/internal/firewall"
	"vanguard/core/internal/intel"
	"vanguard/core/internal/simulator"
)

func newIntelServer(t *testing.T) (*httptest.Server, *database.DB, *intel.Matcher, string) {
	t.Helper()
	db, err := database.Open(database.Config{Path: t.TempDir() + "/api.db"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s, _ := db.DB.DB(); s.Close() })
	mgr, _ := auth.NewManager("test-secret-key-not-for-prod", time.Hour)
	ap := firewall.NewAutopilot(db, firewall.NewMockExecutor(), firewall.DefaultConfig())
	m := intel.NewMatcher(db)
	srv := &Server{DB: db, Autopilot: ap, Auth: mgr, Registry: simulator.NewRegistry(), StartedAt: time.Now(), Intel: m}
	ts := httptest.NewServer(srv.NewEcho())
	t.Cleanup(ts.Close)
	return ts, db, m, bootstrapAdminToken(t, ts)
}

func call(t *testing.T, method, url, token string, body []byte) (int, map[string]any) {
	t.Helper()
	req, _ := http.NewRequest(method, url, bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

func feedJSON(source string, recs ...string) []byte {
	return []byte(fmt.Sprintf(`{"format":"vanguard-ioc","version":1,"source":%q,"indicators":[%s]}`, source, strings.Join(recs, ",")))
}

func TestIntelAPI_ImportListDisableDelete(t *testing.T) {
	ts, _, m, tok := newIntelServer(t)
	code, rep := call(t, "POST", ts.URL+"/api/intel/import", tok, feedJSON("api-feed",
		`{"type":"ip","value":"203.0.113.7","confidence":"high"}`,
		`{"type":"domain","value":"evil.example.com"}`,
		`{"type":"ip","value":"bad"}`,
		`{"type":"ip","value":"203.0.113.8","expires_at":"2020-01-01T00:00:00Z"}`))
	if code != 200 || rep["status"] != "applied" || rep["accepted"] != float64(2) || rep["rejected"] != float64(1) || rep["expired"] != float64(1) {
		t.Fatalf("import: %d %v", code, rep)
	}
	if len(m.MatchIP("203.0.113.7")) != 1 {
		t.Fatal("import must reload the matcher immediately")
	}

	code, list := call(t, "GET", ts.URL+"/api/intel/iocs?type=ip", tok, nil)
	items := list["indicators"].([]any)
	if code != 200 || len(items) != 1 || items[0].(map[string]any)["state"] != "active" {
		t.Fatalf("list: %d %v", code, list)
	}
	id := int(items[0].(map[string]any)["id"].(float64))

	code, one := call(t, "PUT", fmt.Sprintf("%s/api/intel/iocs/%d", ts.URL, id), tok, []byte(`{"enabled":false}`))
	if code != 200 || one["state"] != "disabled" {
		t.Fatalf("disable: %d %v", code, one)
	}
	if len(m.MatchIP("203.0.113.7")) != 0 {
		t.Fatal("disable must stop matching immediately")
	}
	if code, _ = call(t, "PUT", fmt.Sprintf("%s/api/intel/iocs/%d", ts.URL, id), tok, []byte(`{}`)); code != 400 {
		t.Fatalf("missing field must be 400, got %d", code)
	}
	if code, _ = call(t, "DELETE", fmt.Sprintf("%s/api/intel/iocs/%d", ts.URL, id), tok, nil); code != 200 {
		t.Fatalf("delete: %d", code)
	}
	if code, _ = call(t, "GET", fmt.Sprintf("%s/api/intel/iocs/%d", ts.URL, id), tok, nil); code != 404 {
		t.Fatalf("deleted indicator must 404, got %d", code)
	}
}

func TestIntelAPI_FailedImportKeepsExistingIntelAndIsReported(t *testing.T) {
	ts, db, m, tok := newIntelServer(t)
	call(t, "POST", ts.URL+"/api/intel/import", tok, feedJSON("keep", `{"type":"ip","value":"203.0.113.20"}`))
	for name, body := range map[string][]byte{
		"malformed": []byte(`{"format":"vanguard-ioc","version":1,"source":"x","indicators":[`),
		"empty":     feedJSON("x"),
		"wrong ver": []byte(`{"format":"vanguard-ioc","version":9,"source":"x","indicators":[{"type":"ip","value":"203.0.113.21"}]}`),
		"oversize":  bytes.Repeat([]byte("A"), intel.MaxImportBytes+10),
	} {
		code, rep := call(t, "POST", ts.URL+"/api/intel/import", tok, body)
		if code != http.StatusUnprocessableEntity || rep["status"] != "rejected" {
			t.Errorf("%s: want 422 rejected, got %d %v", name, code, rep)
		}
	}
	if len(m.MatchIP("203.0.113.20")) != 1 {
		t.Fatal("failed imports destroyed healthy intelligence")
	}
	if n, _, _ := db.CountIOCs(time.Now()); n != 1 {
		t.Fatalf("rows changed: %d", n)
	}
	_, st := call(t, "GET", ts.URL+"/api/intel/status", tok, nil)
	if st["last_import"].(map[string]any)["status"] != "rejected" {
		t.Fatalf("status must surface the failed import: %v", st["last_import"])
	}
}

func TestIntelAPI_ListStatesAndFilterValidation(t *testing.T) {
	ts, db, _, tok := newIntelServer(t)
	past, future := time.Now().Add(-time.Hour), time.Now().Add(time.Hour)
	db.Create(&database.IOC{Type: database.IOCIP, Value: "203.0.113.30", Source: "s", Enabled: true, ExpiresAt: &past})
	db.Create(&database.IOC{Type: database.IOCIP, Value: "203.0.113.31", Source: "s", Enabled: true, ExpiresAt: &future})
	db.Create(&database.IOC{Type: database.IOCIP, Value: "203.0.113.32", Source: "s", Enabled: false})
	_, list := call(t, "GET", ts.URL+"/api/intel/iocs", tok, nil)
	states := map[string]string{}
	for _, it := range list["indicators"].([]any) {
		m := it.(map[string]any)
		states[m["value"].(string)] = m["state"].(string)
	}
	if states["203.0.113.30"] != "expired" || states["203.0.113.31"] != "active" || states["203.0.113.32"] != "disabled" {
		t.Fatalf("states must be honest: %v", states)
	}
	for _, q := range []string{"type=file_path", "value=1.2.3.4", "type=ip&value=nope", "state=weird", "limit=0", "limit=9999", "offset=-1", "offset=abc"} {
		if code, _ := call(t, "GET", ts.URL+"/api/intel/iocs?"+q, tok, nil); code != 400 {
			t.Errorf("%q should be 400, got %d", q, code)
		}
	}
	if _, l := call(t, "GET", ts.URL+"/api/intel/iocs?type=ip&value=::ffff:203.0.113.31", tok, nil); len(l["indicators"].([]any)) != 1 {
		t.Error("value filter must normalize")
	}
	if _, l := call(t, "GET", ts.URL+"/api/intel/iocs?state=active", tok, nil); len(l["indicators"].([]any)) != 1 {
		t.Error("state=active must exclude expired and disabled")
	}
}

func TestHuntAPI_FiltersPaginationAndValidation(t *testing.T) {
	ts, db, _, tok := newIntelServer(t)
	inc := &database.Incident{Type: database.IncidentIOCMatch, SourceIP: "203.0.113.40", RiskScore: 40}
	_ = db.CreateIncident(inc)
	base := time.Now().UTC().Add(-time.Hour)
	for i := 0; i < 5; i++ {
		_ = db.RecordIOCMatch(&database.IOCMatch{IOCID: 1, IncidentID: inc.ID, MatchedAt: base.Add(time.Duration(i) * time.Minute),
			IOCType: database.IOCIP, Source: "s", Field: "source_ip", Context: "203.0.113.40", SourceIP: "203.0.113.40", Kind: "direct"})
	}
	_ = db.RecordIOCMatch(&database.IOCMatch{IOCID: 2, MatchedAt: base, IOCType: database.IOCDomain, Source: "t", Field: "host", Context: "evil.example.com", SourceIP: "203.0.113.41", Kind: "enrichment"})

	_, all := call(t, "GET", ts.URL+"/api/hunt/matches", tok, nil)
	if all["count"] != float64(6) {
		t.Fatalf("%v", all)
	}
	_, p1 := call(t, "GET", ts.URL+"/api/hunt/matches?limit=2&ip=203.0.113.40", tok, nil)
	_, p2 := call(t, "GET", ts.URL+"/api/hunt/matches?limit=2&offset=2&ip=203.0.113.40", tok, nil)
	a, b := p1["matches"].([]any), p2["matches"].([]any)
	if len(a) != 2 || len(b) != 2 || a[0].(map[string]any)["id"] == b[0].(map[string]any)["id"] {
		t.Fatalf("pagination: %v %v", a, b)
	}
	first := a[0].(map[string]any)
	if first["incident_type"] != "ioc_match" || first["incident_status"] != "open" {
		t.Fatalf("incident join missing: %v", first)
	}
	if ts1, ts2 := first["matched_at"].(string), a[1].(map[string]any)["matched_at"].(string); ts1 < ts2 {
		t.Fatalf("not sorted newest first: %s < %s", ts1, ts2)
	}
	_, byType := call(t, "GET", ts.URL+"/api/hunt/matches?ioc_type=domain&kind=enrichment&context=evil.example.com", tok, nil)
	if byType["count"] != float64(1) {
		t.Fatalf("%v", byType)
	}
	_, empty := call(t, "GET", ts.URL+"/api/hunt/matches?ioc_id=999", tok, nil)
	if empty["count"] != float64(0) || empty["matches"] == nil {
		t.Fatalf("empty result must be [] not null: %v", empty)
	}
	// SQL metacharacters in exact-match filters are inert parameters.
	_, inj := call(t, "GET", ts.URL+"/api/hunt/matches?context="+"x%27%20OR%201%3D1--", tok, nil)
	if inj["count"] != float64(0) {
		t.Fatalf("injection-shaped filter returned rows: %v", inj)
	}
	for _, q := range []string{"ioc_type=bogus", "kind=maybe", "incident_status=zzz", "ip=nope", "ioc_id=abc", "since=yesterday", "until=1", "since_hours=0", "since_hours=99999", "limit=201", "limit=0", "offset=10001"} {
		if code, _ := call(t, "GET", ts.URL+"/api/hunt/matches?"+q, tok, nil); code != 400 {
			t.Errorf("%q should be 400, got %d", q, code)
		}
	}
}

func TestIntelAPI_RequiresAuth(t *testing.T) {
	ts, _, _, _ := newIntelServer(t)
	for _, p := range []string{"/api/intel/status", "/api/intel/iocs", "/api/hunt/matches"} {
		resp, _ := http.Get(ts.URL + p)
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("%s: %d", p, resp.StatusCode)
		}
	}
}
