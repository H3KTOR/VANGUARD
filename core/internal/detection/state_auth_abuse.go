package detection

import (
	"sync"
	"time"
)

// ---------------------------------------------------------------------------
// Password Spraying (Phase 3, feature 5) & Credential Stuffing (feature 6)
// shared per-IP state.
//
// Both detectors are built from the SAME evidence source as SSH Brute
// Force: internal/detection's AuthLogParser, which already exposes
// Username on every EventSSHAuthFailure/EventSSHAuthSuccess Event (see
// parser_auth.go). VANGUARD has no HTTP-login-form log visibility, so
// these two detectors necessarily operate on the same authentication
// evidence SSH Brute Force does -- the distinction from brute force is
// entirely about the SHAPE of that evidence (many distinct accounts,
// few attempts each) rather than a different data source.
//
// AuthAbuseTracker deliberately does NOT replace or feed
// state.State.RecordSSHFailure: the standalone SSH Brute Force rule
// answers "is one IP hammering logins at all" with its own tight 2-minute
// window, while this tracker answers the username-shape question over a
// wider 10-minute window. Keeping them independent means tuning one
// never perturbs the other, exactly like ChainTracker/ScannerTracker are
// kept independent from state.State in correlation.go.
// ---------------------------------------------------------------------------

// authFailureEvent records a single failed-login attempt against a
// specific username, so the tracker can later compute per-username
// counts (password spraying) as well as raw distinct-username counts
// (credential stuffing).
type authFailureEvent struct {
	ts       time.Time
	username string
}

// authAbuseIPState holds the sliding-window failure/success history for
// one source IP.
type authAbuseIPState struct {
	mu sync.Mutex

	failures  []authFailureEvent // sorted oldest-first
	successes []time.Time        // sorted oldest-first
	lastSeen  time.Time
}

func newAuthAbuseIPState() *authAbuseIPState { return &authAbuseIPState{} }

// AuthAbuseTracker is the thread-safe collection of authAbuseIPState, one
// per source IP, with the same bounded-memory reaping contract as
// state.State.
type AuthAbuseTracker struct {
	mu      sync.Mutex
	byIP    map[string]*authAbuseIPState
	maxIdle time.Duration
}

// NewAuthAbuseTracker constructs an empty AuthAbuseTracker. maxIdle
// defaults to 30 minutes if <= 0, matching every other tracker's
// convention in this package.
func NewAuthAbuseTracker(maxIdle time.Duration) *AuthAbuseTracker {
	if maxIdle <= 0 {
		maxIdle = 30 * time.Minute
	}
	return &AuthAbuseTracker{byIP: make(map[string]*authAbuseIPState), maxIdle: maxIdle}
}

func (a *AuthAbuseTracker) get(ip string) *authAbuseIPState {
	a.mu.Lock()
	defer a.mu.Unlock()
	st, ok := a.byIP[ip]
	if !ok {
		st = newAuthAbuseIPState()
		a.byIP[ip] = st
	}
	return st
}

// AuthAbuseSnapshot is the read-only view of one IP's current
// sliding-window authentication-failure shape, as of the moment it was
// computed. Detectors evaluate against this snapshot rather than poking
// at tracker internals directly, keeping the evaluation logic (see
// engine_websec.go's rulePasswordSpraying/ruleCredentialStuffing) pure
// and unit-testable without any locking concerns.
type AuthAbuseSnapshot struct {
	TotalFailures     int
	DistinctUsernames int
	TotalSuccesses    int
	// PerUserFailureCounts maps each distinct username seen in the window
	// to how many times it failed.
	PerUserFailureCounts map[string]int
}

// RecordFailure registers a failed login attempt for (ip, username) at ts,
// prunes both the failure and success histories to window, and returns a
// snapshot of the resulting shape. An empty username is still recorded
// (grouped under the empty string) since VANGUARD must never invent a
// username the log line did not actually contain -- callers should simply
// not count the empty-string bucket toward "distinct usernames" if they
// want to require genuinely-known usernames (see the doc comment on
// rulePasswordSpraying for how this is handled).
func (a *AuthAbuseTracker) RecordFailure(ip, username string, ts time.Time, window time.Duration) AuthAbuseSnapshot {
	st := a.get(ip)
	st.mu.Lock()
	defer st.mu.Unlock()
	st.lastSeen = ts

	cutoff := ts.Add(-window)
	st.failures = pruneAuthFailures(st.failures, cutoff)
	st.successes = pruneOlderThan(st.successes, cutoff)
	st.failures = append(st.failures, authFailureEvent{ts: ts, username: username})

	return snapshotAuthAbuse(st)
}

// RecordSuccess registers a successful login for ip at ts, prunes both
// histories to window, and returns the resulting snapshot (used by the
// Credential Stuffing failure-ratio computation; a burst of successes
// lowers the ratio and can suppress the detector, which is intentional --
// a source IP that mostly succeeds is not credential-stuffing-shaped).
func (a *AuthAbuseTracker) RecordSuccess(ip string, ts time.Time, window time.Duration) AuthAbuseSnapshot {
	st := a.get(ip)
	st.mu.Lock()
	defer st.mu.Unlock()
	st.lastSeen = ts

	cutoff := ts.Add(-window)
	st.failures = pruneAuthFailures(st.failures, cutoff)
	st.successes = pruneOlderThan(st.successes, cutoff)
	st.successes = append(st.successes, ts)

	return snapshotAuthAbuse(st)
}

func pruneAuthFailures(evs []authFailureEvent, cutoff time.Time) []authFailureEvent {
	i := 0
	for i < len(evs) && evs[i].ts.Before(cutoff) {
		i++
	}
	if i == 0 {
		return evs
	}
	return append([]authFailureEvent(nil), evs[i:]...)
}

func snapshotAuthAbuse(st *authAbuseIPState) AuthAbuseSnapshot {
	perUser := make(map[string]int, len(st.failures))
	for _, f := range st.failures {
		perUser[f.username]++
	}
	return AuthAbuseSnapshot{
		TotalFailures:        len(st.failures),
		DistinctUsernames:    len(perUser),
		TotalSuccesses:       len(st.successes),
		PerUserFailureCounts: perUser,
	}
}

// Reap removes auth-abuse state for IPs idle longer than maxIdle.
// Intended to be called by the same periodic maintenance loop that reaps
// every other tracker in this package.
func (a *AuthAbuseTracker) Reap(now time.Time) int {
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

// TrackedIPCount returns how many IPs currently have auth-abuse state,
// exposed for diagnostics/tests.
func (a *AuthAbuseTracker) TrackedIPCount() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.byIP)
}
