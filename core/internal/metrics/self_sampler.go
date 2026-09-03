// self_sampler.go implements VANGUARD's daemon self-telemetry: a sampler
// scoped to VANGUARD's OWN process (not the host), so the dashboard can
// show exactly how much CPU/RAM the daemon itself is consuming. This is a
// "prove it's lightweight" feature, not a general host-monitoring one --
// see Collector/Sample in collector.go for the host-wide equivalent.
package metrics

import (
	"os"
	"runtime"
	"sync"

	"github.com/shirou/gopsutil/v3/process"
)

// SelfMetrics is a single point-in-time reading of VANGUARD's own resource
// footprint.
type SelfMetrics struct {
	// CPUPercent is VANGUARD's own CPU usage, as a percentage of one core,
	// measured as the delta since the previous sample (not an all-time
	// average) so it reflects current load rather than smoothing over the
	// whole process uptime.
	CPUPercent float64
	// AllocMB is the Go runtime's current heap allocation (bytes still
	// reachable/in-use), from runtime.MemStats.Alloc, converted to MB.
	AllocMB uint64
	// SysMB is the total memory obtained from the OS by the Go runtime
	// (runtime.MemStats.Sys), converted to MB -- this is the closer
	// analogue to "how much RAM does this process actually hold", vs.
	// Alloc which only covers live heap objects.
	SysMB uint64
	// Goroutines is the current goroutine count (runtime.NumGoroutine()),
	// a cheap proxy for internal concurrency/load that's useful context
	// alongside CPU/RAM on the same widget.
	Goroutines int
}

// SelfSampler samples VANGUARD's own process resource usage on repeated
// calls. It must be reused across samples (not reconstructed each time)
// because CPU% is computed as a delta against the previous reading --
// gopsutil's process.Process.Percent(0) returns 0 on its very first call
// for exactly this reason.
type SelfSampler struct {
	mu   sync.Mutex
	proc *process.Process
	// initErr is sticky: if we couldn't obtain a handle on our own PID
	// (extremely unlikely, but gopsutil's procfs read can theoretically
	// fail), every subsequent Sample() call cheaply returns the zero value
	// instead of retrying a syscall that's already failed once.
	initErr error
}

// NewSelfSampler constructs a sampler bound to the current process (os.Getpid()).
func NewSelfSampler() *SelfSampler {
	s := &SelfSampler{}
	p, err := process.NewProcess(int32(currentPID()))
	if err != nil {
		s.initErr = err
		return s
	}
	s.proc = p
	return s
}

// Sample takes one self-telemetry reading. Safe for concurrent use, though
// in practice it's only ever called from the single metrics-collector tick
// goroutine. Never returns an error: any underlying gopsutil failure just
// yields zeroed fields for that one field, exactly like the host-wide
// Sample() function's error-tolerant style in collector.go, since a
// self-telemetry hiccup must never block the rest of the metrics tick.
func (s *SelfSampler) Sample() SelfMetrics {
	s.mu.Lock()
	defer s.mu.Unlock()

	var m SelfMetrics

	if s.proc != nil && s.initErr == nil {
		// interval=0 => gopsutil computes CPU% as the delta since the
		// last call on this *same* Process handle (0 on the very first
		// call). This is the "live load" reading the daemon-footprint
		// widget wants, as opposed to Process.CPUPercent()'s all-time
		// average since process start.
		if pct, err := s.proc.Percent(0); err == nil {
			m.CPUPercent = round2(pct)
		}
	}

	// RAM comes from the Go runtime's own accounting, per the explicit
	// design requirement (runtime.ReadMemStats), not from gopsutil's
	// process.MemoryInfo() RSS reading -- ReadMemStats is free (no
	// syscall), always available regardless of platform/procfs quirks,
	// and gives a heap-level breakdown (Alloc vs Sys) that's more
	// actionable for a Go daemon than a single RSS number.
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	m.AllocMB = ms.Alloc / (1024 * 1024)
	m.SysMB = ms.Sys / (1024 * 1024)
	m.Goroutines = runtime.NumGoroutine()

	return m
}

// currentPID is a tiny indirection around os.Getpid so tests could
// theoretically override it; kept as a named function (rather than an
// inline os.Getpid() call) purely for readability at the NewSelfSampler
// call site.
func currentPID() int {
	return os.Getpid()
}
