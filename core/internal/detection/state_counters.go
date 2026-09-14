package detection

import (
	"sync"
	"time"
)

// ---------------------------------------------------------------------------
// Generic bounded per-IP sliding-window trackers shared by multiple Phase 3
// detectors that all need the SAME shape of state (a plain event count, or
// a distinct-value count) but with independent window/threshold tuning and
// independent memory. Factored out here specifically to satisfy the
// mega-prompt's "avoid duplicated logic" code-quality rule: HTTP Protocol
// Anomaly Detection and Request-Smuggling Indicators both just need "how
// many anomalous events in the last N seconds from this IP", and Host
// Header Enumeration needs "how many DISTINCT values in the last N minutes
// from this IP" -- rather than hand-rolling the same map+mutex+prune
// machinery three more times (as state.go, correlation.go, and
// state_auth_abuse.go/state_api_abuse.go each already do for their own
// specific shapes), every detector needing one of these two generic shapes
// gets its own independently-configured instance of ONE of the two types
// below.
// ---------------------------------------------------------------------------

// windowCounterIPState holds a single sliding-window timestamp list for
// one source IP.
type windowCounterIPState struct {
	mu       sync.Mutex
	events   []time.Time // sorted oldest-first
	lastSeen time.Time
}

// WindowCounterTracker is a generic bounded per-IP sliding-window event
// counter: "how many qualifying events has this IP produced in the last
// window". Used by HTTP Protocol Anomaly Detection and Request-Smuggling
// Indicators, each with their own instance/window/threshold.
type WindowCounterTracker struct {
	mu      sync.Mutex
	byIP    map[string]*windowCounterIPState
	maxIdle time.Duration
}

// NewWindowCounterTracker constructs an empty WindowCounterTracker.
// maxIdle defaults to 30 minutes if <= 0.
func NewWindowCounterTracker(maxIdle time.Duration) *WindowCounterTracker {
	if maxIdle <= 0 {
		maxIdle = 30 * time.Minute
	}
	return &WindowCounterTracker{byIP: make(map[string]*windowCounterIPState), maxIdle: maxIdle}
}

func (w *WindowCounterTracker) get(ip string) *windowCounterIPState {
	w.mu.Lock()
	defer w.mu.Unlock()
	st, ok := w.byIP[ip]
	if !ok {
		st = &windowCounterIPState{}
		w.byIP[ip] = st
	}
	return st
}

// Record registers one qualifying event for ip at ts, prunes to window,
// and returns the resulting count still within window.
func (w *WindowCounterTracker) Record(ip string, ts time.Time, window time.Duration) int {
	st := w.get(ip)
	st.mu.Lock()
	defer st.mu.Unlock()
	st.lastSeen = ts
	st.events = append(pruneOlderThan(st.events, ts.Add(-window)), ts)
	return len(st.events)
}

// Reap removes state for IPs idle longer than maxIdle.
func (w *WindowCounterTracker) Reap(now time.Time) int {
	w.mu.Lock()
	defer w.mu.Unlock()
	removed := 0
	for ip, st := range w.byIP {
		st.mu.Lock()
		idle := now.Sub(st.lastSeen)
		st.mu.Unlock()
		if idle > w.maxIdle {
			delete(w.byIP, ip)
			removed++
		}
	}
	return removed
}

// TrackedIPCount returns how many IPs currently have counter state,
// exposed for diagnostics/tests.
func (w *WindowCounterTracker) TrackedIPCount() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return len(w.byIP)
}

// ---------------------------------------------------------------------------
// DistinctValueTracker: generic bounded per-IP sliding-window DISTINCT
// string-value counter. Used by Host Header / Virtual Host Abuse
// (distinct Host header values) with its own instance/window/threshold.
// ---------------------------------------------------------------------------

type distinctValueHit struct {
	ts    time.Time
	value string
}

type distinctValueIPState struct {
	mu       sync.Mutex
	hits     []distinctValueHit // sorted oldest-first
	lastSeen time.Time
}

// DistinctValueTracker tracks, per source IP, how many DISTINCT string
// values have been observed within a sliding window.
type DistinctValueTracker struct {
	mu      sync.Mutex
	byIP    map[string]*distinctValueIPState
	maxIdle time.Duration
}

// NewDistinctValueTracker constructs an empty DistinctValueTracker.
// maxIdle defaults to 30 minutes if <= 0.
func NewDistinctValueTracker(maxIdle time.Duration) *DistinctValueTracker {
	if maxIdle <= 0 {
		maxIdle = 30 * time.Minute
	}
	return &DistinctValueTracker{byIP: make(map[string]*distinctValueIPState), maxIdle: maxIdle}
}

func (d *DistinctValueTracker) get(ip string) *distinctValueIPState {
	d.mu.Lock()
	defer d.mu.Unlock()
	st, ok := d.byIP[ip]
	if !ok {
		st = &distinctValueIPState{}
		d.byIP[ip] = st
	}
	return st
}

// Record registers one observed value for ip at ts, prunes to window, and
// returns the number of DISTINCT values still within window (including
// this one).
func (d *DistinctValueTracker) Record(ip, value string, ts time.Time, window time.Duration) int {
	st := d.get(ip)
	st.mu.Lock()
	defer st.mu.Unlock()
	st.lastSeen = ts

	cutoff := ts.Add(-window)
	i := 0
	for i < len(st.hits) && st.hits[i].ts.Before(cutoff) {
		i++
	}
	if i > 0 {
		st.hits = append([]distinctValueHit(nil), st.hits[i:]...)
	}
	st.hits = append(st.hits, distinctValueHit{ts: ts, value: value})

	distinct := make(map[string]struct{}, len(st.hits))
	for _, h := range st.hits {
		distinct[h.value] = struct{}{}
	}
	return len(distinct)
}

// Reap removes state for IPs idle longer than maxIdle.
func (d *DistinctValueTracker) Reap(now time.Time) int {
	d.mu.Lock()
	defer d.mu.Unlock()
	removed := 0
	for ip, st := range d.byIP {
		st.mu.Lock()
		idle := now.Sub(st.lastSeen)
		st.mu.Unlock()
		if idle > d.maxIdle {
			delete(d.byIP, ip)
			removed++
		}
	}
	return removed
}

// TrackedIPCount returns how many IPs currently have distinct-value
// state, exposed for diagnostics/tests.
func (d *DistinctValueTracker) TrackedIPCount() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.byIP)
}
