package detection

import (
	"sync"
	"time"
)

// ---------------------------------------------------------------------------
// API Abuse Detection (Phase 3, feature 13) per-IP state.
//
// Endpoint-aware anomaly detection layered on top of (never duplicating)
// Web Scanner Behavior/HTTP Flood/Web Dir Scan: those existing rules key
// off RAW REQUEST FREQUENCY or SENSITIVE-PATH 404s; this tracker instead
// keys off DISTINCT PATH DIVERSITY combined with a FAILURE RATIO within a
// short window, which is the specific shape of "one client enumerating
// many different API endpoints, mostly unsuccessfully" that neither of
// those rules is designed to catch (a client hitting 25 different valid
// endpoints successfully must never trigger this; a client hitting the
// SAME sensitive path 25 times already triggers ruleWebDirScan instead).
// ---------------------------------------------------------------------------

// apiAbuseHit records one HTTP request's path and whether its response
// counted as a "failure" for this heuristic (401/403/404).
type apiAbuseHit struct {
	ts      time.Time
	path    string
	failure bool
}

type apiAbuseIPState struct {
	mu       sync.Mutex
	hits     []apiAbuseHit // sorted oldest-first
	lastSeen time.Time
}

func newAPIAbuseIPState() *apiAbuseIPState { return &apiAbuseIPState{} }

// APIAbuseTracker is the thread-safe collection of apiAbuseIPState, one
// per source IP, with the same bounded-memory reaping contract as every
// other tracker in this package.
type APIAbuseTracker struct {
	mu      sync.Mutex
	byIP    map[string]*apiAbuseIPState
	maxIdle time.Duration
}

// NewAPIAbuseTracker constructs an empty APIAbuseTracker. maxIdle
// defaults to 30 minutes if <= 0.
func NewAPIAbuseTracker(maxIdle time.Duration) *APIAbuseTracker {
	if maxIdle <= 0 {
		maxIdle = 30 * time.Minute
	}
	return &APIAbuseTracker{byIP: make(map[string]*apiAbuseIPState), maxIdle: maxIdle}
}

func (a *APIAbuseTracker) get(ip string) *apiAbuseIPState {
	a.mu.Lock()
	defer a.mu.Unlock()
	st, ok := a.byIP[ip]
	if !ok {
		st = newAPIAbuseIPState()
		a.byIP[ip] = st
	}
	return st
}

// APIAbuseSnapshot is the read-only view of one IP's current
// sliding-window request shape, used by the pure evaluation function in
// rules_api_abuse.go.
type APIAbuseSnapshot struct {
	TotalRequests int
	DistinctPaths int
	FailureCount  int
}

// RecordRequest registers one HTTP request for ip at ts, prunes to
// window, and returns the resulting snapshot.
func (a *APIAbuseTracker) RecordRequest(ip, path string, failure bool, ts time.Time, window time.Duration) APIAbuseSnapshot {
	st := a.get(ip)
	st.mu.Lock()
	defer st.mu.Unlock()
	st.lastSeen = ts

	cutoff := ts.Add(-window)
	st.hits = pruneAPIAbuseHits(st.hits, cutoff)
	st.hits = append(st.hits, apiAbuseHit{ts: ts, path: path, failure: failure})

	return snapshotAPIAbuse(st)
}

func pruneAPIAbuseHits(hits []apiAbuseHit, cutoff time.Time) []apiAbuseHit {
	i := 0
	for i < len(hits) && hits[i].ts.Before(cutoff) {
		i++
	}
	if i == 0 {
		return hits
	}
	return append([]apiAbuseHit(nil), hits[i:]...)
}

func snapshotAPIAbuse(st *apiAbuseIPState) APIAbuseSnapshot {
	distinct := make(map[string]struct{}, len(st.hits))
	failures := 0
	for _, h := range st.hits {
		distinct[h.path] = struct{}{}
		if h.failure {
			failures++
		}
	}
	return APIAbuseSnapshot{
		TotalRequests: len(st.hits),
		DistinctPaths: len(distinct),
		FailureCount:  failures,
	}
}

// Reap removes API-abuse state for IPs idle longer than maxIdle.
func (a *APIAbuseTracker) Reap(now time.Time) int {
	a.mu.Lock()
	defer a.mu.Unlock()
	removed := 0
	for ip, st := range a.byIP {
		st.mu.Lock()
		idle := now.Sub(st.lastSeen)
		st.mu.Unlock()
		if idle > a.maxIdle {
			delete(a.byIP, ip)
			removed++
		}
	}
	return removed
}

// TrackedIPCount returns how many IPs currently have API-abuse state,
// exposed for diagnostics/tests.
func (a *APIAbuseTracker) TrackedIPCount() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.byIP)
}
