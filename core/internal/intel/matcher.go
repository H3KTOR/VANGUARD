package intel

// Exact-match engine over an immutable snapshot.
//
// The snapshot is rebuilt from SQLite on demand (after imports and
// operator changes) and periodically, then swapped atomically, so the hot
// path (every observed event) is a few map lookups with no database
// access and no locks. Staleness is bounded two ways: (1) enable/disable/
// delete/import call Reload immediately, (2) a periodic reload, and
// expiry is re-checked against the clock at match time using each
// indicator's ExpiresAt, so an expired indicator can never match even if
// the snapshot predates its expiry.

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	"vanguard/core/internal/database"
)

// Ref is the small, immutable view of an indicator kept in the snapshot.
type Ref struct {
	ID          uint
	Type        database.IOCType
	Value       string
	Source      string
	Confidence  database.IOCConfidence
	Description string
	Reference   string
	ExpiresAt   *time.Time
}

func (r Ref) activeAt(now time.Time) bool { return r.ExpiresAt == nil || now.Before(*r.ExpiresAt) }

type snapshot struct {
	ip, domain, url, sha map[string][]Ref
	loadedAt             time.Time
	loaded               int   // indicators in this snapshot
	activeTotal          int64 // active indicators in the database
	truncated            bool  // activeTotal exceeded the snapshot cap
}

// Status describes the matcher for the API/dashboard.
type Status struct {
	Loaded       bool       `json:"loaded"`
	LoadedAt     *time.Time `json:"loaded_at,omitempty"`
	Indicators   int        `json:"indicators_loaded"`
	ActiveInDB   int64      `json:"active_in_db"`
	Truncated    bool       `json:"truncated"`
	LastError    string     `json:"last_error,omitempty"`
	LastReloadAt *time.Time `json:"last_reload_attempt,omitempty"`
}

// Matcher performs exact IOC lookups.
type Matcher struct {
	db    *database.DB
	snap  atomic.Pointer[snapshot]
	clock func() time.Time

	mu       sync.Mutex // serializes Reload and guards the fields below
	lastErr  string
	lastTry  time.Time
	haveSnap bool

	running atomic.Bool // guards against a second Run loop
}

// NewMatcher builds a matcher and performs the first load. A failed first
// load leaves the matcher empty-but-not-loaded (Status().Loaded == false),
// which is distinguishable from "loaded, nothing matched".
func NewMatcher(db *database.DB) *Matcher {
	m := &Matcher{db: db, clock: func() time.Time { return time.Now().UTC() }}
	m.snap.Store(&snapshot{})
	_ = m.Reload()
	return m
}

// SetClock overrides the clock (tests).
func (m *Matcher) SetClock(f func() time.Time) { m.clock = f }

// Reload rebuilds the snapshot. On error the previous snapshot is kept and
// the error is surfaced via Status; it is never replaced by an empty set.
func (m *Matcher) Reload() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.clock()
	m.lastTry = now
	rows, total, err := m.db.ActiveIOCs(now, MaxActiveIOCs)
	if err != nil {
		m.lastErr = err.Error()
		return err
	}
	s := &snapshot{
		ip: map[string][]Ref{}, domain: map[string][]Ref{}, url: map[string][]Ref{}, sha: map[string][]Ref{},
		loadedAt: now, loaded: len(rows), activeTotal: total, truncated: total > int64(len(rows)),
	}
	for _, r := range rows {
		ref := Ref{ID: r.ID, Type: r.Type, Value: r.Value, Source: r.Source, Confidence: r.Confidence,
			Description: r.Description, Reference: r.Reference, ExpiresAt: r.ExpiresAt}
		switch r.Type {
		case database.IOCIP:
			s.ip[r.Value] = append(s.ip[r.Value], ref)
		case database.IOCDomain:
			s.domain[r.Value] = append(s.domain[r.Value], ref)
		case database.IOCURL:
			k := URLMatchKey(r.Value)
			s.url[k] = append(s.url[k], ref)
		case database.IOCSHA256:
			s.sha[r.Value] = append(s.sha[r.Value], ref)
		}
	}
	m.snap.Store(s)
	m.haveSnap = true
	m.lastErr = ""
	return nil
}

// Run reloads periodically until ctx is cancelled.
func (m *Matcher) Run(ctx context.Context, every time.Duration) {
	// A second concurrent Run would only duplicate reloads; refuse it.
	if !m.running.CompareAndSwap(false, true) {
		return
	}
	defer m.running.Store(false)
	if every <= 0 {
		every = 5 * time.Minute
	}
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			_ = m.Reload()
		}
	}
}

// Status returns a snapshot of matcher health.
func (m *Matcher) Status() Status {
	m.mu.Lock()
	defer m.mu.Unlock()
	s := m.snap.Load()
	st := Status{Loaded: m.haveSnap, LastError: m.lastErr}
	if m.haveSnap {
		la := s.loadedAt
		st.LoadedAt = &la
		st.Indicators, st.ActiveInDB, st.Truncated = s.loaded, s.activeTotal, s.truncated
	}
	if !m.lastTry.IsZero() {
		lt := m.lastTry
		st.LastReloadAt = &lt
	}
	return st
}

func (m *Matcher) filter(refs []Ref) []Ref {
	if len(refs) == 0 {
		return nil
	}
	now := m.clock()
	var out []Ref
	for _, r := range refs {
		if r.activeAt(now) {
			out = append(out, r)
		}
	}
	return out
}

// MatchIP matches an observed address (any textual form) exactly.
func (m *Matcher) MatchIP(raw string) []Ref {
	ip, ok := NormalizeObservedIP(raw)
	if !ok {
		return nil
	}
	return m.filter(m.snap.Load().ip[ip])
}

// MatchHost matches a logged Host header against domain indicators
// (exact, no subdomain matching) and, if it is an address literal, against
// IP indicators.
func (m *Matcher) MatchHost(host string) []Ref {
	h, ok := ObservedHost(host)
	if !ok {
		return nil
	}
	s := m.snap.Load()
	out := m.filter(s.domain[h])
	if ip, ok := NormalizeObservedIP(h); ok {
		out = append(out, m.filter(s.ip[ip])...)
	}
	return out
}

// MatchURL matches host+request target against URL indicators. Without a
// logged Host the request is not observable and nothing matches.
func (m *Matcher) MatchURL(host, target string) []Ref {
	key, ok := ObservedURLKey(host, target)
	if !ok {
		return nil
	}
	return m.filter(m.snap.Load().url[key])
}

// MatchSHA256 matches a file hash VANGUARD computed itself.
func (m *Matcher) MatchSHA256(hexHash string) []Ref {
	h, err := normalizeSHA256(hexHash)
	if err != nil {
		return nil
	}
	return m.filter(m.snap.Load().sha[h])
}

// IsMalicious implements detection.ThreatIntelChecker for the existing
// reputation risk bonus. Only medium/high-confidence IP indicators count:
// unrated and low-confidence entries are matched and reported, but do not
// raise the risk of unrelated detectors.
func (m *Matcher) IsMalicious(ip string) bool {
	for _, r := range m.MatchIP(ip) {
		if r.Confidence == database.IOCConfidenceMedium || r.Confidence == database.IOCConfidenceHigh {
			return true
		}
	}
	return false
}
