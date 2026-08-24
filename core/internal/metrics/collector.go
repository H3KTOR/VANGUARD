// Package metrics implements VANGUARD's system resource monitor: a
// lightweight periodic sampler for CPU, RAM, disk, and active connection
// counts, persisted to SystemMetric rows for the dashboard's real-time
// charts. Uses gopsutil (pure syscalls/procfs reads, no external process
// spawning) to keep the "~25MB binary, near-zero overhead" promise intact.
package metrics

import (
	"context"
	"log"
	"time"

	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/disk"
	"github.com/shirou/gopsutil/v3/mem"
	gnet "github.com/shirou/gopsutil/v3/net"

	"vanguard/core/internal/database"
)

// Collector periodically samples host resource usage and writes it to the
// database.
type Collector struct {
	db       *database.DB
	interval time.Duration
	diskPath string
	// retention bounds how long historical samples are kept; older rows
	// are pruned on each tick to keep the SQLite file from growing
	// unbounded on a long-running host.
	retention time.Duration
}

// NewCollector constructs a Collector. interval controls sample frequency
// (e.g. 15-30s); diskPath is the filesystem mount to report disk usage for
// (typically "/"); retention controls how long historical samples are kept
// before being pruned.
func NewCollector(db *database.DB, interval time.Duration, diskPath string, retention time.Duration) *Collector {
	if interval <= 0 {
		interval = 30 * time.Second
	}
	if diskPath == "" {
		diskPath = "/"
	}
	if retention <= 0 {
		retention = 7 * 24 * time.Hour
	}
	return &Collector{db: db, interval: interval, diskPath: diskPath, retention: retention}
}

// Run samples metrics on a fixed interval until ctx is cancelled. Intended
// to be launched in its own goroutine by cmd/vanguard.
func (c *Collector) Run(ctx context.Context) {
	ticker := time.NewTicker(c.interval)
	defer ticker.Stop()

	// Sample once immediately so the dashboard has data without waiting a
	// full interval after a fresh start.
	c.sampleOnce()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			c.sampleOnce()
		}
	}
}

func (c *Collector) sampleOnce() {
	sample, err := Sample(c.diskPath)
	if err != nil {
		log.Printf("[metrics] failed to sample system metrics: %v", err)
		return
	}
	if err := c.db.RecordMetric(sample); err != nil {
		log.Printf("[metrics] failed to persist sample: %v", err)
		return
	}

	if n, err := c.db.PruneMetricsOlderThan(time.Now().UTC().Add(-c.retention)); err == nil && n > 0 {
		log.Printf("[metrics] pruned %d metric rows older than %s", n, c.retention)
	}
}

// Sample takes a single point-in-time reading of CPU/RAM/disk/connection
// usage. Exposed standalone (not just via Collector.Run) so the REST API
// can serve an on-demand "live" reading without waiting for the next tick.
func Sample(diskPath string) (*database.SystemMetric, error) {
	cpuPercents, err := cpu.Percent(200*time.Millisecond, false)
	cpuPct := 0.0
	if err == nil && len(cpuPercents) > 0 {
		cpuPct = cpuPercents[0]
	}

	vm, err := mem.VirtualMemory()
	memPct, memUsedMB := 0.0, uint64(0)
	if err == nil {
		memPct = vm.UsedPercent
		memUsedMB = vm.Used / (1024 * 1024)
	}

	du, err := disk.Usage(diskPath)
	diskPct := 0.0
	if err == nil {
		diskPct = du.UsedPercent
	}

	connections := 0
	if conns, err := gnet.Connections("tcp"); err == nil {
		for _, cn := range conns {
			if cn.Status == "ESTABLISHED" {
				connections++
			}
		}
	}

	return &database.SystemMetric{
		CPUPercent:        round2(cpuPct),
		MemoryPercent:     round2(memPct),
		MemoryUsedMB:      memUsedMB,
		DiskPercent:       round2(diskPct),
		ActiveConnections: connections,
		Timestamp:         time.Now().UTC(),
	}, nil
}

func round2(v float64) float64 {
	return float64(int(v*100)) / 100
}
