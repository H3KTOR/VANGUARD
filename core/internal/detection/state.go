package detection

import (
	"sync"
	"time"
)

// ipState holds all the sliding-window counters VANGUARD's V1 rules need
// for a single source IP. All timestamp slices are kept sorted
// oldest-first and pruned lazily on read.
type ipState struct {
	mu sync.Mutex

	sshFailures  []time.Time       // for brute-force + failed->success sequence
	sshSuccesses []time.Time       // most recent successes, for the escalation rule
	portTouches  map[int]time.Time // distinct port -> last-seen time, for port scan
	sensitive404 []time.Time       // 404s on sensitive paths, for dir scanning
	httpRequests []time.Time       // all HTTP requests, for flood detection
	lastSeen     time.Time         // last activity of any kind, for reaping stale entries
}

func newIPState() *ipState {
	return &ipState{portTouches: make(map[int]time.Time)}
}

// pruneOlderThan drops timestamps older than cutoff from a sorted slice,
// returning the pruned slice. Since slices are append-only and
// chronologically ordered, this is a simple binary-search-free scan from
// the front.
func pruneOlderThan(ts []time.Time, cutoff time.Time) []time.Time {
	i := 0
	for i < len(ts) && ts[i].Before(cutoff) {
		i++
	}
	if i == 0 {
		return ts
	}
	return append([]time.Time(nil), ts[i:]...)
}

// State is the thread-safe collection of per-IP sliding-window state for
// every source IP the detection Engine has seen recently. It is the
// in-memory complement to the database's CountRecentEventsByIP: State
// answers "is this IP doing something suspicious *right now*", while the
// database answers "has this IP been a repeat offender historically".
type State struct {
	mu      sync.Mutex
	byIP    map[string]*ipState
	maxIdle time.Duration // entries idle longer than this are reaped
}

// NewState constructs an empty State. maxIdle controls how long a
// per-IP entry is retained with no activity before Reap() removes it,
// bounding memory usage on a long-running host (this is what keeps the
// ~25MB footprint promise honest even after weeks of uptime).
func NewState(maxIdle time.Duration) *State {
	if maxIdle <= 0 {
		maxIdle = 30 * time.Minute
	}
	return &State{byIP: make(map[string]*ipState), maxIdle: maxIdle}
}

func (s *State) get(ip string) *ipState {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, ok := s.byIP[ip]
	if !ok {
		st = newIPState()
		s.byIP[ip] = st
	}
	return st
}

// RecordSSHFailure registers a failed SSH login for ip at ts and returns
// the number of failures still within window after pruning.
func (s *State) RecordSSHFailure(ip string, ts time.Time, window time.Duration) int {
	st := s.get(ip)
	st.mu.Lock()
	defer st.mu.Unlock()
	st.lastSeen = ts
	st.sshFailures = append(pruneOlderThan(st.sshFailures, ts.Add(-window)), ts)
	return len(st.sshFailures)
}

// RecordSSHSuccess registers a successful SSH login for ip at ts and
// returns the number of failures that occurred within `lookback` before
// this success (used for the failed->success escalation rule), plus
// whether that count meets minFailed.
func (s *State) RecordSSHSuccess(ip string, ts time.Time, lookback time.Duration, minFailed int) (failedBefore int, escalate bool) {
	st := s.get(ip)
	st.mu.Lock()
	defer st.mu.Unlock()
	st.lastSeen = ts
	st.sshSuccesses = append(pruneOlderThan(st.sshSuccesses, ts.Add(-lookback)), ts)

	cutoff := ts.Add(-lookback)
	count := 0
	for _, f := range st.sshFailures {
		if f.After(cutoff) && f.Before(ts.Add(time.Second)) {
			count++
		}
	}
	return count, count >= minFailed
}

// RecordPortTouch registers a connection to `port` for ip at ts and
// returns the number of *distinct* ports touched within window after
// pruning.
func (s *State) RecordPortTouch(ip string, port int, ts time.Time, window time.Duration) int {
	st := s.get(ip)
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
	return len(st.portTouches)
}

// RecordSensitive404 registers a 404 response on a sensitive path for ip at
// ts and returns the count still within window after pruning.
func (s *State) RecordSensitive404(ip string, ts time.Time, window time.Duration) int {
	st := s.get(ip)
	st.mu.Lock()
	defer st.mu.Unlock()
	st.lastSeen = ts
	st.sensitive404 = append(pruneOlderThan(st.sensitive404, ts.Add(-window)), ts)
	return len(st.sensitive404)
}

// RecordHTTPRequest registers any HTTP request for ip at ts and returns the
// count still within window after pruning (used for flood detection).
func (s *State) RecordHTTPRequest(ip string, ts time.Time, window time.Duration) int {
	st := s.get(ip)
	st.mu.Lock()
	defer st.mu.Unlock()
	st.lastSeen = ts
	st.httpRequests = append(pruneOlderThan(st.httpRequests, ts.Add(-window)), ts)
	return len(st.httpRequests)
}

// Touch registers generic activity for ip (used by rules that trigger on a
// single event, like honeypot hits or path traversal, so the entry doesn't
// get reaped and reputation lookups still make sense).
func (s *State) Touch(ip string, ts time.Time) {
	st := s.get(ip)
	st.mu.Lock()
	st.lastSeen = ts
	st.mu.Unlock()
}

// Reap removes per-IP state entries that have had no activity for longer
// than maxIdle, bounding memory growth. Intended to be called periodically
// (e.g. every few minutes) by the Engine's background loop.
func (s *State) Reap(now time.Time) int {
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

// TrackedIPCount returns how many IPs currently have in-memory state,
// exposed for the dashboard's "active trackers" diagnostic and for tests.
func (s *State) TrackedIPCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.byIP)
}
