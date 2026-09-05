package detection

import (
	"sync"
	"time"

	"vanguard/core/internal/thresholds"
)

// ---------------------------------------------------------------------------
// Attack Chain Correlation (Task 3: "Smart Detection")
//
// ChainTracker is a lightweight, concurrent-safe in-memory state machine
// (map + per-IP mutex, mirroring state.go's pattern) that tracks, for every
// source IP seen recently, whether each of the three stages of a
// coordinated attack has occurred within a sliding window:
//
//	Recon (port scan) -> Web Probing (403/404 errors) -> Auth Probing (SSH failures)
//
// It is deliberately a standalone structure from the V1 rule state in
// state.go: the V1 rules answer "has THIS signal alone crossed ITS OWN
// threshold" (e.g. 15 distinct ports in 30s for a standalone port-scan
// incident), while ChainTracker answers a different, cross-signal
// question -- "have all three WEAKER signals shown up together on the
// same IP" -- using its own (looser, wider) thresholds. Keeping it
// separate avoids coupling the correlation logic's window/threshold
// tuning to the unrelated standalone rules, and keeps both independently
// testable.
// ---------------------------------------------------------------------------

// chainIPState holds the three stage counters for a single source IP.
type chainIPState struct {
	mu sync.Mutex

	portTouches map[int]time.Time // recon stage: distinct port -> last-seen
	webProbes   []time.Time       // web-probing stage: 403/404 timestamps (sorted, oldest-first)
	authFails   []time.Time       // auth-probing stage: SSH failure timestamps (sorted, oldest-first)

	lastSeen time.Time
}

func newChainIPState() *chainIPState {
	return &chainIPState{portTouches: make(map[int]time.Time)}
}

// ChainTracker is the thread-safe collection of chainIPState, one per
// source IP, with idle-entry reaping to keep memory bounded (same
// contract as state.State.Reap).
type ChainTracker struct {
	mu      sync.Mutex
	byIP    map[string]*chainIPState
	maxIdle time.Duration
}

// NewChainTracker constructs an empty ChainTracker. maxIdle defaults to 30
// minutes if <= 0, matching state.NewState's convention.
func NewChainTracker(maxIdle time.Duration) *ChainTracker {
	if maxIdle <= 0 {
		maxIdle = 30 * time.Minute
	}
	return &ChainTracker{byIP: make(map[string]*chainIPState), maxIdle: maxIdle}
}

func (c *ChainTracker) get(ip string) *chainIPState {
	c.mu.Lock()
	defer c.mu.Unlock()
	st, ok := c.byIP[ip]
	if !ok {
		st = newChainIPState()
		c.byIP[ip] = st
	}
	return st
}

// RecordPortTouch registers a recon-stage signal (a port touch) for ip.
func (c *ChainTracker) RecordPortTouch(ip string, port int, ts time.Time, window time.Duration) {
	st := c.get(ip)
	st.mu.Lock()
	defer st.mu.Unlock()
	st.lastSeen = ts
	cutoff := ts.Add(-window)
	for p, seen := range st.portTouches {
		if seen.Before(cutoff) {
			delete(st.portTouches, p)
		}
	}
	st.portTouches[port] = ts
}

// RecordWebProbe registers a web-probing-stage signal (a 403/404 response)
// for ip.
func (c *ChainTracker) RecordWebProbe(ip string, ts time.Time, window time.Duration) {
	st := c.get(ip)
	st.mu.Lock()
	defer st.mu.Unlock()
	st.lastSeen = ts
	st.webProbes = append(pruneOlderThan(st.webProbes, ts.Add(-window)), ts)
}

// RecordAuthFailure registers an auth-probing-stage signal (a failed SSH
// login) for ip.
func (c *ChainTracker) RecordAuthFailure(ip string, ts time.Time, window time.Duration) {
	st := c.get(ip)
	st.mu.Lock()
	defer st.mu.Unlock()
	st.lastSeen = ts
	st.authFails = append(pruneOlderThan(st.authFails, ts.Add(-window)), ts)
}

// Evaluate prunes ip's state to window and reports whether the full
// coordinated chain is currently present: all three stages must meet
// their minimum counts (see thresholds.AttackChainMin*), AND the earliest
// observed event of each stage must respect the documented order (recon
// first, then web probing, then auth probing -- ties are tolerated). This
// second check is what distinguishes a genuine multi-stage chain from
// three unrelated bursts of activity that happen to coexist in the same
// window with no coherent story.
func (c *ChainTracker) Evaluate(ip string, now time.Time, window time.Duration) (reconCount, webCount, authCount int, matched bool) {
	st := c.get(ip)
	st.mu.Lock()
	defer st.mu.Unlock()

	cutoff := now.Add(-window)
	for p, seen := range st.portTouches {
		if seen.Before(cutoff) {
			delete(st.portTouches, p)
		}
	}
	st.webProbes = pruneOlderThan(st.webProbes, cutoff)
	st.authFails = pruneOlderThan(st.authFails, cutoff)

	reconCount = len(st.portTouches)
	webCount = len(st.webProbes)
	authCount = len(st.authFails)

	if reconCount < thresholds.AttackChainMinDistinctPorts ||
		webCount < thresholds.AttackChainMinWebProbes ||
		authCount < thresholds.AttackChainMinAuthFailures {
		return reconCount, webCount, authCount, false
	}

	reconFirst := earliestPortTouch(st.portTouches)
	webFirst := st.webProbes[0]
	authFirst := st.authFails[0]

	// Sequence check: recon must start no later than web probing, which
	// must start no later than auth probing. Equal timestamps are allowed
	// (<=) since synthetic events / fast automated attacks can legitimately
	// share a timestamp at second-level resolution.
	if reconFirst.After(webFirst) || webFirst.After(authFirst) {
		return reconCount, webCount, authCount, false
	}

	return reconCount, webCount, authCount, true
}

// Reap removes chain state for IPs idle longer than maxIdle. Intended to
// be called periodically by the same maintenance loop that reaps
// state.State, to preserve VANGUARD's bounded in-memory footprint.
func (c *ChainTracker) Reap(now time.Time) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	removed := 0
	for ip, st := range c.byIP {
		st.mu.Lock()
		idle := now.Sub(st.lastSeen)
		st.mu.Unlock()
		if idle > c.maxIdle {
			delete(c.byIP, ip)
			removed++
		}
	}
	return removed
}

// TrackedIPCount returns how many IPs currently have chain-correlation
// state, exposed for diagnostics/tests.
func (c *ChainTracker) TrackedIPCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.byIP)
}

func earliestPortTouch(m map[int]time.Time) time.Time {
	var min time.Time
	for _, t := range m {
		if min.IsZero() || t.Before(min) {
			min = t
		}
	}
	return min
}

// ---------------------------------------------------------------------------
// Web Scanner Behavior Detection (heuristic, Task 3)
//
// ScannerTracker tracks, per source IP, a sliding window of 403/404
// responses together with whether each carried a missing or
// known-scanner-like User-Agent. This is intentionally NOT a pure
// signature match (there is no fixed "if UA == X" rule by itself) --
// it is a *frequency* heuristic (many 4xx errors in a short window) that
// only escalates to an incident when *combined* with the UA signal, which
// is what separates "a scanner is hammering this box" from "a legitimate
// crawler occasionally hits a dead link".
// ---------------------------------------------------------------------------

type scanner4xxHit struct {
	ts         time.Time
	suspicious bool // missing or known-scanner-like User-Agent
}

type scannerIPState struct {
	mu       sync.Mutex
	hits     []scanner4xxHit
	lastSeen time.Time
}

func newScannerIPState() *scannerIPState { return &scannerIPState{} }

// ScannerTracker is the thread-safe collection of scannerIPState, one per
// source IP.
type ScannerTracker struct {
	mu      sync.Mutex
	byIP    map[string]*scannerIPState
	maxIdle time.Duration
}

// NewScannerTracker constructs an empty ScannerTracker. maxIdle defaults
// to 30 minutes if <= 0.
func NewScannerTracker(maxIdle time.Duration) *ScannerTracker {
	if maxIdle <= 0 {
		maxIdle = 30 * time.Minute
	}
	return &ScannerTracker{byIP: make(map[string]*scannerIPState), maxIdle: maxIdle}
}

func (s *ScannerTracker) get(ip string) *scannerIPState {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, ok := s.byIP[ip]
	if !ok {
		st = newScannerIPState()
		s.byIP[ip] = st
	}
	return st
}

// Record4xx registers a 403/404 response for ip, pruning to window, and
// returns the total count of 4xx responses still in window plus how many
// of those carried a missing/suspicious User-Agent.
func (s *ScannerTracker) Record4xx(ip string, ts time.Time, window time.Duration, suspiciousUA bool) (total, suspicious int) {
	st := s.get(ip)
	st.mu.Lock()
	defer st.mu.Unlock()
	st.lastSeen = ts

	cutoff := ts.Add(-window)
	i := 0
	for i < len(st.hits) && st.hits[i].ts.Before(cutoff) {
		i++
	}
	if i > 0 {
		st.hits = append([]scanner4xxHit(nil), st.hits[i:]...)
	}
	st.hits = append(st.hits, scanner4xxHit{ts: ts, suspicious: suspiciousUA})

	total = len(st.hits)
	for _, h := range st.hits {
		if h.suspicious {
			suspicious++
		}
	}
	return total, suspicious
}

// Reap removes scanner state for IPs idle longer than maxIdle.
func (s *ScannerTracker) Reap(now time.Time) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	removed := 0
	for ip, st := range s.byIP {
		st.mu.Lock()
		idle := now.Sub(st.lastSeen)
		st.mu.Unlock()
		if idle > s.maxIdle {
			delete(s.byIP, ip)
			removed++
		}
	}
	return removed
}

// TrackedIPCount returns how many IPs currently have scanner-heuristic
// state, exposed for diagnostics/tests.
func (s *ScannerTracker) TrackedIPCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.byIP)
}
