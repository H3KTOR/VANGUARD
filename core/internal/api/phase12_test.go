package api

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"vanguard/core/internal/database"
	"vanguard/core/internal/detection"
	"vanguard/core/internal/pipeline"
)

func TestQueueComponent_StatesAreHonest(t *testing.T) {
	now := time.Now().UTC()
	base := pipeline.Stats{Name: "auth", Capacity: 100, Running: true}

	if c := queueComponent(base, now); c.State != "healthy" {
		t.Fatalf("idle running queue should be healthy: %+v", c)
	}
	notRunning := base
	notRunning.Running = false
	if c := queueComponent(notRunning, now); c.State != "failed" {
		t.Fatalf("a queue with no worker must be failed, got %s", c.State)
	}
	lossy := base
	lossy.Oversize, lossy.LastLoss, lossy.LastLossKind = 3, now.Add(-time.Minute), "oversize_line"
	c := queueComponent(lossy, now)
	if c.State != "degraded" || !strings.Contains(c.Detail, "NOT analysed") || c.Counters["oversize_dropped"] != 3 {
		t.Fatalf("recent loss must degrade and be named: %+v", c)
	}
	old := lossy
	old.LastLoss = now.Add(-2 * time.Hour)
	c = queueComponent(old, now)
	if c.State != "healthy" || c.Counters["oversize_dropped"] != 3 {
		t.Fatalf("old loss recovers the state but the counter must remain: %+v", c)
	}
	full := base
	full.Depth = 95
	if c := queueComponent(full, now); c.State != "degraded" || !strings.Contains(c.Detail, "falling behind") {
		t.Fatalf("saturated queue must be degraded: %+v", c)
	}
}

func TestEngineComponent_LostIncidentsAreNeverHealthy(t *testing.T) {
	now := time.Now().UTC()
	if c := engineComponent(detection.PersistStats{Created: 5}, 2, now); c.State != "healthy" {
		t.Fatalf("%+v", c)
	}
	c := engineComponent(detection.PersistStats{Created: 5, Failed: 2, LastFailureAt: now, LastError: "disk I/O error"}, 0, now)
	if c.State != "failed" || c.Counters["incidents_lost"] != 2 || !strings.Contains(c.Detail, "not sent to response") {
		t.Fatalf("%+v", c)
	}
	c = engineComponent(detection.PersistStats{Failed: 2, LastFailureAt: now.Add(-time.Hour)}, 0, now)
	if c.State != "degraded" {
		t.Fatalf("an old loss must stay visible as degraded, got %s", c.State)
	}
}

func TestGuardComponent(t *testing.T) {
	if c := guardComponent(database.GuardStats{Limit: 4}); c.State != "healthy" {
		t.Fatal(c)
	}
	if c := guardComponent(database.GuardStats{Limit: 4, InFlight: 4}); c.State != "degraded" {
		t.Fatal(c)
	}
	if c := guardComponent(database.GuardStats{Limit: 4, InFlight: 1, Abandoned: 1}); c.State != "degraded" || !strings.Contains(c.Detail, "cannot be interrupted") {
		t.Fatal(c)
	}
}

func TestRuntimeHealth_ExposesQueuesEngineAndGuard(t *testing.T) {
	ts, _, tok := runtimeServer(t, func(s *Server) {
		s.Engine = detection.NewEngine(detection.Config{DB: s.DB})
		s.Guard = database.NewQueryGuard(2, time.Millisecond, time.Second)
		s.QueueStats = func() []pipeline.Stats {
			return []pipeline.Stats{{Name: "auth", Capacity: 10, Running: true, Oversize: 1, LastLoss: time.Now().UTC(), LastLossKind: "oversize_line"}}
		}
	})
	_, body := call(t, "GET", ts.URL+"/api/health/runtime", tok, nil)
	c := comps(t, body)
	if c["ingest_queue:auth"]["state"] != "degraded" {
		t.Fatalf("queue loss missing from health: %v", c["ingest_queue:auth"])
	}
	if c["detection_engine"]["state"] != "healthy" || c["query_guard"]["state"] != "healthy" {
		t.Fatalf("engine/guard: %v %v", c["detection_engine"], c["query_guard"])
	}
	if body["overall"] == "healthy" {
		t.Fatalf("overall must not be healthy while a queue reports loss: %v", body["overall"])
	}
}

// With every guard slot held, expensive reads fail fast with 503 + Retry-After
// and nothing is changed; once the slot is free they succeed again.
func TestExpensiveReads_BusyGuardReturns503_ThenRecovers(t *testing.T) {
	g := database.NewQueryGuard(1, 5*time.Millisecond, 5*time.Second)
	ts, db, tok := runtimeServer(t, func(s *Server) { s.Guard = g })
	if err := db.CreateIncident(&database.Incident{Type: database.IncidentPortScan, SourceIP: "203.0.113.5", Severity: database.SeverityLow, Status: database.StatusOpen, DetectedAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}

	release := make(chan struct{})
	held := make(chan struct{})
	go func() {
		_ = g.Do(context.Background(), func() error { close(held); <-release; return nil })
	}()
	<-held

	for _, path := range []string{
		"/api/incidents", "/api/dashboard/summary", "/api/investigate/incidents",
		"/api/hunt/matches", "/api/incidents/1/timeline", "/api/incidents/1/graph", "/api/incidents/1/export",
	} {
		req, _ := http.NewRequest("GET", ts.URL+path, nil)
		req.Header.Set("Authorization", "Bearer "+tok)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusServiceUnavailable || resp.Header.Get("Retry-After") == "" {
			t.Errorf("%s: want 503 with Retry-After while the guard is full, got %d", path, resp.StatusCode)
		}
	}
	if st := g.Stats(); st.Rejected < 7 {
		t.Errorf("rejections not counted: %+v", st)
	}

	close(release)
	deadline := time.Now().Add(2 * time.Second)
	for g.Stats().InFlight != 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if code, _ := call(t, "GET", ts.URL+"/api/incidents", tok, nil); code != 200 {
		t.Fatalf("after the slot is free the read must succeed, got %d", code)
	}
}

// With one of two guard slots held by a stuck operation, the other slot still
// serves requests normally.
func TestExpensiveRead_OneStuckSlotDoesNotBlockOthers(t *testing.T) {
	g := database.NewQueryGuard(2, time.Millisecond, 50*time.Millisecond)
	ts, _, tok := runtimeServer(t, func(s *Server) { s.Guard = g })
	release := make(chan struct{})
	defer close(release)
	go func() { _ = g.Do(context.Background(), func() error { <-release; return nil }) }()
	time.Sleep(20 * time.Millisecond)
	// One slot is held by the stuck operation; the other works normally.
	if code, _ := call(t, "GET", ts.URL+"/api/incidents", tok, nil); code != 200 {
		t.Fatalf("a free slot must still serve requests, got %d", code)
	}
}

func TestRetentionAPI_AdminOnly_ReadOnly_NoMutationRoutes(t *testing.T) {
	ts, db, admin, viewer, _ := backupServer(t, false)
	if code, _ := call(t, "GET", ts.URL+"/api/retention", "", nil); code != http.StatusUnauthorized {
		t.Fatalf("anonymous: %d", code)
	}
	if code, _ := call(t, "GET", ts.URL+"/api/retention", viewer, nil); code != http.StatusForbidden {
		t.Fatalf("viewer: %d", code)
	}
	code, body := call(t, "GET", ts.URL+"/api/retention", admin, nil)
	if code != 200 || body["enabled"] != false {
		t.Fatalf("%d %v", code, body)
	}
	pol := body["policy"].(map[string]any)
	if pol["incident_retention_days"] != float64(0) {
		t.Fatalf("default must be keep-forever: %v", pol)
	}
	// There is no way to change or run retention over HTTP, and an attempt
	// must not change anything.
	before, _ := db.GetRetentionPolicy()
	for _, m := range []string{"PUT", "POST", "DELETE", "PATCH"} {
		if c, _ := call(t, m, ts.URL+"/api/retention", admin, []byte(`{"incident_retention_days":30}`)); c != http.StatusNotFound && c != http.StatusMethodNotAllowed {
			t.Errorf("%s /api/retention must not exist, got %d", m, c)
		}
	}
	after, _ := db.GetRetentionPolicy()
	if after != before && after.Revision != before.Revision {
		t.Fatalf("policy changed through HTTP: %+v -> %+v", before, after)
	}
}
