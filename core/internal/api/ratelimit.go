package api

import (
	"sync"
	"time"
)

// Login throttling parameters. Chosen to stop online guessing while leaving a
// human who mistypes a password a comfortable margin.
const (
	loginMaxFailures   = 10
	loginFailureWindow = 15 * time.Minute
	loginMaxTracked    = 10000
	// bcryptConcurrency bounds simultaneous password hashes/compares, each of
	// which costs tens of milliseconds of CPU.
	bcryptConcurrency = 4
	bcryptWait        = 2 * time.Second
)

// failureLimiter counts authentication failures per client address in a fixed
// window. It is bounded (loginMaxTracked entries) and keyed by the TCP peer
// address only, so it never stores emails or passwords.
//
// It is deliberately per-address, not per-account: a per-account lockout would
// let anyone lock the administrator out by guessing wrongly on purpose. The
// cost of that choice is that clients sharing one address (a reverse proxy)
// share one budget; an existing session token keeps working during a lockout,
// since only the login/registration routes are limited.
type failureLimiter struct {
	mu      sync.Mutex
	max     int
	window  time.Duration
	cap     int
	now     func() time.Time
	entries map[string]*failEntry
}

type failEntry struct {
	count int
	start time.Time
}

func newFailureLimiter(max int, window time.Duration, capacity int) *failureLimiter {
	return &failureLimiter{max: max, window: window, cap: capacity, now: time.Now, entries: map[string]*failEntry{}}
}

// blocked reports whether key has used up its failures, and for how long.
func (l *failureLimiter) blocked(key string) (bool, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	e, ok := l.entries[key]
	if !ok {
		return false, 0
	}
	now := l.now()
	if now.Sub(e.start) >= l.window {
		delete(l.entries, key)
		return false, 0
	}
	if e.count >= l.max {
		return true, e.start.Add(l.window).Sub(now)
	}
	return false, 0
}

// fail records one failure.
func (l *failureLimiter) fail(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	e, ok := l.entries[key]
	if ok && now.Sub(e.start) >= l.window {
		ok = false
	}
	if !ok {
		if len(l.entries) >= l.cap {
			l.evictLocked(now)
		}
		e = &failEntry{start: now}
		l.entries[key] = e
	}
	e.count++
}

// reset forgets key (after a successful login).
func (l *failureLimiter) reset(key string) {
	l.mu.Lock()
	delete(l.entries, key)
	l.mu.Unlock()
}

func (l *failureLimiter) len() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.entries)
}

// evictLocked frees room: expired entries first, then the oldest.
func (l *failureLimiter) evictLocked(now time.Time) {
	for k, e := range l.entries {
		if now.Sub(e.start) >= l.window {
			delete(l.entries, k)
		}
	}
	if len(l.entries) < l.cap {
		return
	}
	var oldestKey string
	var oldest time.Time
	first := true
	for k, e := range l.entries {
		if first || e.start.Before(oldest) {
			oldestKey, oldest, first = k, e.start, false
		}
	}
	if !first {
		delete(l.entries, oldestKey)
	}
}

// opGate allows one expensive administrative operation at a time and,
// optionally, a minimum gap between runs. It exists for operations that were
// shown to be abusable: backup creation (disk), IOC import (CPU/memory/DB) and
// simulation (writes that look like real incidents).
type opGate struct {
	mu     sync.Mutex
	busy   bool
	last   time.Time
	minGap time.Duration
	now    func() time.Time
}

func newOpGate(minGap time.Duration) *opGate { return &opGate{minGap: minGap, now: time.Now} }

// enter returns (release, 0, true) when the operation may start, or
// (nil, retryAfter, false). release must be called when it finishes.
func (g *opGate) enter() (func(), time.Duration, bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	now := g.now()
	if g.busy {
		return nil, time.Second, false
	}
	if !g.last.IsZero() && g.minGap > 0 {
		if wait := g.last.Add(g.minGap).Sub(now); wait > 0 {
			return nil, wait, false
		}
	}
	g.busy = true
	return func() {
		g.mu.Lock()
		g.busy = false
		g.last = g.now()
		g.mu.Unlock()
	}, 0, true
}

func newTimer(d time.Duration) *time.Timer { return time.NewTimer(d) }

func nowUnix() int64 { return time.Now().Unix() }
