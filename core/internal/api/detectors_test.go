package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"vanguard/core/internal/auth"
	"vanguard/core/internal/database"
	"vanguard/core/internal/firewall"
	"vanguard/core/internal/hostsec"
	"vanguard/core/internal/simulator"
)

type fakeDetectors struct{ list []hostsec.ScanStatus }

func (f fakeDetectors) Status() []hostsec.ScanStatus { return f.list }

func getDetectors(t *testing.T, base, token string) map[string]any {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, base+"/api/detectors/status", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d", resp.StatusCode)
	}
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return out
}

func TestDetectorStatusDisabledIsNotReportedAsHealthy(t *testing.T) {
	ts, _ := testServer(t)
	token := bootstrapAdminToken(t, ts)
	out := getDetectors(t, ts.URL, token)
	if out["enabled"] != false {
		t.Fatalf("no detector source must report enabled=false: %v", out)
	}
	if l, _ := out["detectors"].([]any); l == nil || len(l) != 0 {
		t.Fatalf("detectors must be an empty list, got %v", out["detectors"])
	}
}

func newDetectorServer(t *testing.T, d DetectorStatusSource) *httptest.Server {
	t.Helper()
	db, err := database.Open(database.Config{Path: ":memory:"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	mgr, err := auth.NewManager("test-secret-key-not-for-prod", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	ap := firewall.NewAutopilot(db, firewall.NewMockExecutor(), firewall.DefaultConfig())
	srv := &Server{DB: db, Autopilot: ap, Auth: mgr, Registry: simulator.NewRegistry(), StartedAt: time.Now(), Detectors: d}
	ts := httptest.NewServer(srv.NewEcho())
	t.Cleanup(ts.Close)
	return ts
}

func TestDetectorStatusEndpointSurfacesFailureAndSkip(t *testing.T) {
	ts := newDetectorServer(t, fakeDetectors{list: []hostsec.ScanStatus{
		{Name: "listening", LastResult: hostsec.ResultFailed, LastNote: "could not read /proc/net"},
		{Name: "package_drift", LastResult: hostsec.ResultSkipped, LastNote: "package database unavailable"},
	}})
	token := bootstrapAdminToken(t, ts)
	out := getDetectors(t, ts.URL, token)
	if out["enabled"] != true {
		t.Fatalf("%v", out)
	}
	list, _ := out["detectors"].([]any)
	if len(list) != 2 {
		t.Fatalf("%v", out)
	}
	first := list[0].(map[string]any)
	if first["last_result"] != "failed" || first["last_clean_scan"] != nil {
		t.Fatalf("failure must be visible and not clean: %v", first)
	}
}
