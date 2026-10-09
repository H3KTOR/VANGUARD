package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"vanguard/core/internal/database"
)

func putStatus(t *testing.T, base, token string, id uint, body string) (int, map[string]any) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPut, fmt.Sprintf("%s/api/incidents/%d/status", base, id), strings.NewReader(body))
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

func TestIncidentLifecycleViaAPI(t *testing.T) {
	ts, db := testServer(t)
	token := bootstrapAdminToken(t, ts)
	inc := &database.Incident{Type: database.IncidentPortScan, SourceIP: "203.0.113.9", RiskScore: 40}
	if err := db.CreateIncident(inc); err != nil {
		t.Fatal(err)
	}

	if code, _ := putStatus(t, ts.URL, token, inc.ID, `{"status":"resolved","reason":"patched"}`); code != http.StatusOK {
		t.Fatalf("open->resolved: %d", code)
	}
	// resolved -> auto_blocked is not a legal analyst/system move
	if code, _ := putStatus(t, ts.URL, token, inc.ID, `{"status":"auto_blocked"}`); code != http.StatusConflict {
		t.Fatalf("resolved->auto_blocked must be 409, got %d", code)
	}
	if code, _ := putStatus(t, ts.URL, token, inc.ID, `{"status":"nonsense"}`); code != http.StatusBadRequest {
		t.Fatalf("unknown status must be 400, got %d", code)
	}
	if code, _ := putStatus(t, ts.URL, token, 99999, `{"status":"open"}`); code != http.StatusNotFound {
		t.Fatalf("missing incident must be 404, got %d", code)
	}
	if code, _ := putStatus(t, ts.URL, token, inc.ID, `{"status":"open","reason":"recurred"}`); code != http.StatusOK {
		t.Fatalf("reopen: %d", code)
	}

	req, _ := http.NewRequest(http.MethodGet, fmt.Sprintf("%s/api/incidents/%d/events", ts.URL, inc.ID), nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out struct {
		Events []database.IncidentEvent `json:"events"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&out)
	if len(out.Events) != 2 || out.Events[0].Detail != "patched" || out.Events[0].Actor == "" || out.Events[1].ToStatus != "open" {
		t.Fatalf("audit trail wrong: %+v", out.Events)
	}
}

func TestResponsePlanEndpointIsReadOnly(t *testing.T) {
	ts, db := testServer(t)
	token := bootstrapAdminToken(t, ts)
	inc := &database.Incident{Type: database.IncidentSSHBruteForce, SourceIP: "203.0.113.77", RiskScore: 80}
	if err := db.CreateIncident(inc); err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequest(http.MethodGet, fmt.Sprintf("%s/api/incidents/%d/response-plan", ts.URL, inc.ID), nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var d map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&d)
	if resp.StatusCode != http.StatusOK || d["would_ban"] != true || d["executed"] != false {
		t.Fatalf("plan = %d %v", resp.StatusCode, d)
	}
	if banned, _ := db.IsBanned(inc.SourceIP); banned {
		t.Fatal("plan endpoint must not ban")
	}
	if evs, _ := db.ListIncidentEvents(inc.ID); len(evs) != 0 {
		t.Fatalf("plan endpoint must not write audit events: %v", evs)
	}
	if cur, _ := db.GetIncident(inc.ID); cur.Status != database.StatusOpen {
		t.Fatalf("plan endpoint changed status: %s", cur.Status)
	}
}
