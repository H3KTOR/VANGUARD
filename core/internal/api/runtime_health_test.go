package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"vanguard/core/internal/auth"
	"vanguard/core/internal/database"
	"vanguard/core/internal/firewall"
	"vanguard/core/internal/health"
	"vanguard/core/internal/honeypot"
	"vanguard/core/internal/hostsec"
	"vanguard/core/internal/intel"
	"vanguard/core/internal/simulator"
)

func runtimeServer(t *testing.T, mutate func(*Server)) (*httptest.Server, *database.DB, string) {
	t.Helper()
	db, err := database.Open(database.Config{Path: t.TempDir() + "/rt.db"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if s, err := db.DB.DB(); err == nil {
			s.Close()
		}
	})
	mgr, _ := auth.NewManager("test-secret-key-not-for-prod", time.Hour)
	ap := firewall.NewAutopilot(db, firewall.NewMockExecutor(), firewall.DefaultConfig())
	srv := &Server{DB: db, Autopilot: ap, Auth: mgr, Registry: simulator.NewRegistry(), StartedAt: time.Now()}
	if mutate != nil {
		mutate(srv)
	}
	ts := httptest.NewServer(srv.NewEcho())
	t.Cleanup(ts.Close)
	return ts, db, bootstrapAdminToken(t, ts)
}

func comps(t *testing.T, body map[string]any) map[string]map[string]any {
	t.Helper()
	out := map[string]map[string]any{}
	for _, c := range body["components"].([]any) {
		m := c.(map[string]any)
		out[m["name"].(string)] = m
	}
	return out
}

func TestRuntimeHealth_RequiresAuth(t *testing.T) {
	ts, _, _ := runtimeServer(t, nil)
	resp, _ := http.Get(ts.URL + "/api/health/runtime")
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("runtime health must be authenticated, got %d", resp.StatusCode)
	}
}

func TestRuntimeHealth_DisabledIsNotHealthy_AndStatesMapHonestly(t *testing.T) {
	fin := time.Now().UTC()
	old := fin.Add(-time.Hour)
	ts, _, tok := runtimeServer(t, func(s *Server) {
		s.Detectors = fakeDetectors{list: []hostsec.ScanStatus{
			{Name: "ok_fresh", IntervalSeconds: 600, LastResult: hostsec.ResultOK, LastFinished: &fin, LastCleanScan: &fin},
			{Name: "ok_stale", IntervalSeconds: 60, LastResult: hostsec.ResultOK, LastFinished: &old, LastCleanScan: &old},
			{Name: "skipped", IntervalSeconds: 60, LastResult: hostsec.ResultSkipped, LastNote: "package database unavailable"},
			{Name: "failed", IntervalSeconds: 60, LastResult: hostsec.ResultFailed, LastNote: "open /proc/net/tcp: permission denied"},
			{Name: "timeout", IntervalSeconds: 60, LastResult: hostsec.ResultTimeout},
			{Name: "never", IntervalSeconds: 60, LastResult: hostsec.ResultNever},
		}}
		s.Runtime.HoneypotStats = nil // honeypot disabled
	})
	code, body := call(t, "GET", ts.URL+"/api/health/runtime", tok, nil)
	if code != 200 {
		t.Fatalf("%d %v", code, body)
	}
	c := comps(t, body)
	want := map[string]string{
		"database": "healthy", "detector:ok_fresh": "healthy", "detector:ok_stale": "unknown",
		"detector:skipped": "degraded", "detector:failed": "failed", "detector:timeout": "timed_out",
		"detector:never": "not_yet_observed", "intel_matcher": "disabled", "honeypot": "disabled",
		"metrics_collector": "not_yet_observed",
	}
	for name, st := range want {
		if c[name]["state"] != st {
			t.Errorf("%s = %v, want %s", name, c[name]["state"], st)
		}
	}
	if body["overall"] != "failed" {
		t.Errorf("overall must be the worst state, got %v", body["overall"])
	}
	// stale ok must explain it is missing telemetry, not a clean result
	if d, _ := c["detector:ok_stale"]["detail"].(string); !strings.Contains(d, "not a clean result") {
		t.Errorf("stale detail: %q", d)
	}
	// error text from the OS must not leak filesystem paths
	if d, _ := c["detector:failed"]["detail"].(string); strings.Contains(d, "/proc/net") {
		t.Errorf("path leaked: %q", d)
	}
	res := body["resources"].(map[string]any)
	if res["goroutines"].(float64) < 1 {
		t.Error("resources missing")
	}
	b := body["bounds"].(map[string]any)
	if b["honeypot_max_concurrent_connections"] != float64(honeypot.MaxConcurrentConns) {
		t.Errorf("bounds not reported: %v", b)
	}
}

func TestRuntimeHealth_AllGoodIsHealthyOnlyWithRealSuccesses(t *testing.T) {
	fin := time.Now().UTC()
	ts, db, tok := runtimeServer(t, func(s *Server) {
		s.Detectors = fakeDetectors{list: []hostsec.ScanStatus{{Name: "fim", IntervalSeconds: 600, LastResult: hostsec.ResultOK, LastFinished: &fin, LastCleanScan: &fin}}}
		s.Intel = intel.NewMatcher(s.DB)
		s.Runtime.HoneypotStats = func() honeypot.Stats { return honeypot.Stats{BoundPorts: 8, Accepted: 3} }
		reg := health.New()
		reg.Register("maintenance", time.Minute)
		reg.Success("maintenance")
		s.Runtime.Registry = reg
		s.Runtime.MetricsInterval = time.Minute
	})
	_ = db.RecordMetric(&database.SystemMetric{Timestamp: time.Now().UTC()})
	_, body := call(t, "GET", ts.URL+"/api/health/runtime", tok, nil)
	if body["overall"] != "healthy" {
		t.Fatalf("expected healthy with real successes: %v", comps(t, body))
	}
	// honeypot: a decoy that could not bind, or shed load, is degraded
	for name, st := range map[string]honeypot.Stats{
		"bind failure": {BoundPorts: 7, BindFailures: 1},
		"shed":         {BoundPorts: 8, Shed: 5},
		"none bound":   {BoundPorts: 0, BindFailures: 8},
	} {
		st := st
		ts2, _, tok2 := runtimeServer(t, func(s *Server) { s.Runtime.HoneypotStats = func() honeypot.Stats { return st } })
		_, b2 := call(t, "GET", ts2.URL+"/api/health/runtime", tok2, nil)
		got := comps(t, b2)["honeypot"]["state"]
		want := "degraded"
		if name == "none bound" {
			want = "failed"
		}
		if got != want {
			t.Errorf("honeypot %s = %v, want %s", name, got, want)
		}
	}
}

func TestRuntimeHealth_DatabaseFailureIsVisibleNotHidden(t *testing.T) {
	ts, db, tok := runtimeServer(t, nil)
	if s, err := db.DB.DB(); err == nil {
		s.Close() // the database goes away underneath a running server
	}
	code, body := call(t, "GET", ts.URL+"/api/health/runtime", tok, nil)
	if code != 200 {
		t.Fatalf("the health endpoint itself must keep answering, got %d", code)
	}
	if comps(t, body)["database"]["state"] != "failed" || body["overall"] != "failed" {
		t.Fatalf("a dead database must be reported failed: %v", comps(t, body)["database"])
	}
}

func TestRuntimeHealth_IntelFailureStates(t *testing.T) {
	ts, _, tok := runtimeServer(t, func(s *Server) { s.Intel = intel.NewMatcher(s.DB) })
	_, body := call(t, "GET", ts.URL+"/api/health/runtime", tok, nil)
	if comps(t, body)["intel_matcher"]["state"] != "healthy" {
		t.Fatalf("%v", comps(t, body)["intel_matcher"])
	}
}

func TestRuntimeHealth_RegistryStalenessSurfaces(t *testing.T) {
	now := time.Now().UTC()
	reg := health.New()
	reg.SetClock(func() time.Time { return now })
	reg.Register("maintenance", time.Minute)
	reg.Success("maintenance")
	now = now.Add(10 * time.Minute) // silent far longer than 3x the interval
	ts, _, tok := runtimeServer(t, func(s *Server) { s.Runtime.Registry = reg })
	_, body := call(t, "GET", ts.URL+"/api/health/runtime", tok, nil)
	if comps(t, body)["maintenance"]["state"] != "unknown" {
		t.Fatalf("a component that stopped reporting must be unknown: %v", comps(t, body)["maintenance"])
	}
}
