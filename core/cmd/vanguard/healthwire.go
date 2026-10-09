package main

import (
	"sync/atomic"
	"time"

	"vanguard/core/internal/health"
)

// newRuntimeRegistry registers the components that report themselves.
// (Database, detectors, threat intel, honeypot and the metrics collector
// are derived at request time by the API; see handlers_runtime_health.go.)
func newRuntimeRegistry(cfg serveConfig) *health.Registry {
	reg := health.New()
	// Maintenance runs every ReapInterval; silence beyond 3x is "unknown".
	reg.Register("maintenance", cfg.ReapInterval)
	reg.Register(retentionComponent, 2*retentionInterval)
	reg.Register("log:auth", 0)
	if cfg.AuthLogPath == "" {
		reg.Disable("log:auth", "auth log tailing disabled by configuration")
	}
	for i := range cfg.WebLogPaths {
		reg.Register(webLogName(i), 0)
	}
	return reg
}

func webLogName(i int) string { return "log:web" + itoa(i+1) }

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [12]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

// tailHealth adapts a detection.TailObserver to the health registry. Line
// and Started can be called once per log line, so registry writes are
// throttled to one per second; the line count is kept in an atomic.
type tailHealth struct {
	reg      *health.Registry
	name     string
	lines    atomic.Uint64
	lastPush atomic.Int64 // unix seconds
	open     atomic.Bool
}

func newTailHealth(reg *health.Registry, name string) *tailHealth {
	return &tailHealth{reg: reg, name: name}
}

func (t *tailHealth) Waiting() {
	t.open.Store(false)
	t.reg.Degrade(t.name, "log file does not exist yet; waiting for it (no events are being read)")
}

func (t *tailHealth) Started() {
	if t.open.Swap(true) {
		return
	}
	t.reg.Success(t.name)
}

func (t *tailHealth) StartFailed(err error) {
	t.open.Store(false)
	t.reg.Failure(t.name, health.Failed, "tailer could not start: "+err.Error())
}

func (t *tailHealth) Line() {
	n := t.lines.Add(1)
	now := time.Now().Unix()
	if last := t.lastPush.Load(); now > last && t.lastPush.CompareAndSwap(last, now) {
		t.reg.SetCounter(t.name, "lines_read", n)
	}
}

func (t *tailHealth) Error(err error) {
	t.reg.Failure(t.name, health.Degraded, "tail error: "+err.Error())
	t.open.Store(false) // next delivered line re-asserts health
}

func (t *tailHealth) Stopped() {
	t.open.Store(false)
	t.reg.Degrade(t.name, "tailer stopped")
}
