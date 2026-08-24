package metrics

import (
	"context"
	"testing"
	"time"

	"vanguard/core/internal/database"
)

func TestSampleReturnsPlausibleValues(t *testing.T) {
	s, err := Sample("/")
	if err != nil {
		t.Fatalf("Sample failed: %v", err)
	}
	if s.CPUPercent < 0 || s.CPUPercent > 100 {
		t.Errorf("CPUPercent out of range: %v", s.CPUPercent)
	}
	if s.MemoryPercent < 0 || s.MemoryPercent > 100 {
		t.Errorf("MemoryPercent out of range: %v", s.MemoryPercent)
	}
	if s.DiskPercent < 0 || s.DiskPercent > 100 {
		t.Errorf("DiskPercent out of range: %v", s.DiskPercent)
	}
	if s.Timestamp.IsZero() {
		t.Errorf("expected a non-zero timestamp")
	}
	t.Logf("sample: cpu=%.2f%% mem=%.2f%% (%dMB) disk=%.2f%% conns=%d",
		s.CPUPercent, s.MemoryPercent, s.MemoryUsedMB, s.DiskPercent, s.ActiveConnections)
}

func TestCollectorPersistsSamples(t *testing.T) {
	db, err := database.Open(database.Config{Path: ":memory:"})
	if err != nil {
		t.Fatalf("failed to open db: %v", err)
	}
	defer db.Close()

	c := NewCollector(db, 20*time.Millisecond, "/", time.Hour)
	ctx, cancel := context.WithTimeout(context.Background(), 70*time.Millisecond)
	defer cancel()
	c.Run(ctx)

	metrics, err := db.GetMetricsSince(time.Now().UTC().Add(-time.Hour))
	if err != nil {
		t.Fatalf("GetMetricsSince failed: %v", err)
	}
	if len(metrics) < 2 {
		t.Fatalf("expected at least 2 samples (immediate + at least one tick), got %d", len(metrics))
	}
}
