package api

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"vanguard/core/internal/database"
)

func TestLatestMetricReturnsNullWhenNoSamplesYet(t *testing.T) {
	ts, _ := testServer(t)
	token := bootstrapAdminToken(t, ts)

	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/metrics/latest", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	var body struct {
		Metric *database.SystemMetric `json:"metric"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if body.Metric != nil {
		t.Fatalf("expected nil metric with an empty table, got %+v", body.Metric)
	}
}

// TestLatestMetricIncludesSelfTelemetryFields is the key Task 2 API-contract
// test: it asserts the daemon's own CPU/RAM/goroutine footprint rides along
// in the SAME /api/metrics/latest response as the host-wide fields, so the
// frontend's existing 5s poll cycle (see CommandCenter.jsx's
// usePolling(getLatestMetric, 5000)) needs no second endpoint or poll to
// power the "Daemon Footprint" widget.
func TestLatestMetricIncludesSelfTelemetryFields(t *testing.T) {
	ts, db := testServer(t)
	token := bootstrapAdminToken(t, ts)

	if err := db.RecordMetric(&database.SystemMetric{
		CPUPercent:        12.5,
		MemoryPercent:     40.0,
		MemoryUsedMB:      1024,
		DiskPercent:       55.0,
		ActiveConnections: 3,
		Timestamp:         time.Now().UTC(),
		SelfCPUPercent:    0.8,
		SelfMemoryAllocMB: 14,
		SelfMemorySysMB:   26,
		SelfGoroutines:    9,
	}); err != nil {
		t.Fatalf("failed to seed a metric row: %v", err)
	}

	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/metrics/latest", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	var body struct {
		Metric *database.SystemMetric `json:"metric"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if body.Metric == nil {
		t.Fatal("expected a non-nil metric")
	}
	if body.Metric.SelfCPUPercent != 0.8 {
		t.Errorf("SelfCPUPercent = %v, want 0.8", body.Metric.SelfCPUPercent)
	}
	if body.Metric.SelfMemoryAllocMB != 14 {
		t.Errorf("SelfMemoryAllocMB = %v, want 14", body.Metric.SelfMemoryAllocMB)
	}
	if body.Metric.SelfMemorySysMB != 26 {
		t.Errorf("SelfMemorySysMB = %v, want 26", body.Metric.SelfMemorySysMB)
	}
	if body.Metric.SelfGoroutines != 9 {
		t.Errorf("SelfGoroutines = %v, want 9", body.Metric.SelfGoroutines)
	}
}
