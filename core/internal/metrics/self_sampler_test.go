package metrics

import "testing"

func TestNewSelfSamplerBindsToCurrentProcessWithoutError(t *testing.T) {
	s := NewSelfSampler()
	if s.initErr != nil {
		t.Fatalf("expected NewSelfSampler to bind to the current PID without error, got: %v", s.initErr)
	}
	if s.proc == nil {
		t.Fatal("expected a non-nil process handle")
	}
}

func TestSelfSamplerSampleReturnsPlausibleValues(t *testing.T) {
	s := NewSelfSampler()

	// First call: gopsutil's Percent(0) always returns 0 on the very first
	// invocation for a given Process handle (no prior CPU-time delta to
	// compare against) -- this is documented/expected, not a bug, so we
	// only assert non-negative here rather than requiring CPUPercent > 0.
	first := s.Sample()
	if first.CPUPercent < 0 {
		t.Errorf("CPUPercent should never be negative, got %v", first.CPUPercent)
	}
	if first.AllocMB == 0 {
		t.Errorf("expected a non-zero AllocMB reading for a running Go process, got 0")
	}
	if first.SysMB == 0 {
		t.Errorf("expected a non-zero SysMB reading for a running Go process, got 0")
	}
	if first.SysMB < first.AllocMB {
		t.Errorf("expected SysMB (%d) >= AllocMB (%d): Sys is total OS-obtained memory, Alloc is the live subset",
			first.SysMB, first.AllocMB)
	}
	if first.Goroutines <= 0 {
		t.Errorf("expected at least 1 goroutine (the test itself), got %d", first.Goroutines)
	}
}

func TestSelfSamplerSampleIsSafeAcrossRepeatedCalls(t *testing.T) {
	s := NewSelfSampler()

	for i := 0; i < 3; i++ {
		m := s.Sample()
		if m.CPUPercent < 0 {
			t.Fatalf("iteration %d: CPUPercent should never be negative, got %v", i, m.CPUPercent)
		}
	}
}

func TestSelfSamplerWithInitErrorReturnsZeroCPUButStillReportsRuntimeStats(t *testing.T) {
	// Simulate the (extremely unlikely) case where binding to our own PID
	// failed: CPU should degrade to 0 gracefully, but the runtime.MemStats
	// -derived fields (which don't depend on the gopsutil process handle)
	// must still be populated normally.
	s := &SelfSampler{initErr: errSimulatedInit}

	m := s.Sample()
	if m.CPUPercent != 0 {
		t.Errorf("expected CPUPercent=0 when proc handle is unavailable, got %v", m.CPUPercent)
	}
	if m.AllocMB == 0 || m.SysMB == 0 {
		t.Errorf("expected runtime.MemStats fields to still be populated regardless of proc handle state")
	}
}

var errSimulatedInit = &simulatedInitError{}

type simulatedInitError struct{}

func (e *simulatedInitError) Error() string { return "simulated init failure" }
