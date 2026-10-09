// Package health is VANGUARD's small, local runtime-health registry.
//
// It records what each long-running component actually did (attempts,
// successes, failures, last error) and derives an honest state from that.
// Principles:
//
//   - a component is "healthy" only after a recorded success; a component
//     that has never been observed is "not_yet_observed", not healthy;
//   - a component that stops reporting for longer than its expectation is
//     "unknown" (missing telemetry), never silently healthy;
//   - the last successful operation and the last attempt are separate;
//   - state is in-memory and bounded (fixed component set, short strings).
//
// Health describes whether VANGUARD's own machinery is working. It says
// nothing about whether the monitored host is secure.
package health

import (
	"regexp"
	"sort"
	"sync"
	"time"
)

// State is a component's derived health.
type State string

const (
	Healthy        State = "healthy"
	Degraded       State = "degraded"
	Failed         State = "failed"
	TimedOut       State = "timed_out"
	Disabled       State = "disabled"
	NotYetObserved State = "not_yet_observed"
	Unknown        State = "unknown"
)

// MaxComponents bounds the registry; Register beyond it is refused.
const MaxComponents = 64

const (
	maxDetail = 160
	// StaleFactor: a component with an Expect interval that has produced no
	// success for StaleFactor*Expect is reported Unknown.
	StaleFactor = 3
)

// Component is one tracked component's snapshot.
type Component struct {
	Name        string     `json:"name"`
	State       State      `json:"state"`
	Detail      string     `json:"detail,omitempty"`
	LastAttempt *time.Time `json:"last_attempt,omitempty"`
	LastSuccess *time.Time `json:"last_success,omitempty"`
	Attempts    uint64     `json:"attempts"`
	Failures    uint64     `json:"failures"`
	// Counters are small named monotonic counters (e.g. dropped work).
	Counters map[string]uint64 `json:"counters,omitempty"`
}

type entry struct {
	c        Component
	expect   time.Duration
	disabled bool
	last     State // last explicit state from the component itself
}

// Registry holds the components. Safe for concurrent use.
type Registry struct {
	mu    sync.Mutex
	comps map[string]*entry
	now   func() time.Time
}

// New returns an empty registry.
func New() *Registry {
	return &Registry{comps: map[string]*entry{}, now: func() time.Time { return time.Now().UTC() }}
}

// SetClock overrides the clock (tests).
func (r *Registry) SetClock(f func() time.Time) { r.now = f }

var pathRE = regexp.MustCompile(`(?:[A-Za-z]:)?(?:[\\/][\w.\-@+ ]+){2,}`)

// Sanitize bounds a detail string and masks absolute paths, so error text
// copied from the OS does not reveal filesystem layout.
func Sanitize(s string) string {
	s = pathRE.ReplaceAllString(s, "<path>")
	if len(s) > maxDetail {
		s = s[:maxDetail]
	}
	return s
}

// Register declares a component. expect is the longest silence that is
// normal for it (0 = no staleness rule). Registering twice keeps the
// existing entry. Returns false if the registry is full.
func (r *Registry) Register(name string, expect time.Duration) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.comps[name]; ok {
		return true
	}
	if len(r.comps) >= MaxComponents {
		return false
	}
	r.comps[name] = &entry{c: Component{Name: name, State: NotYetObserved}, expect: expect}
	return true
}

func (r *Registry) get(name string) *entry { return r.comps[name] }

// Success records a successful operation.
func (r *Registry) Success(name string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	e := r.get(name)
	if e == nil {
		return
	}
	now := r.now()
	e.c.Attempts++
	e.c.LastAttempt, e.c.LastSuccess = &now, &now
	e.c.Detail, e.last, e.disabled = "", Healthy, false
}

// Failure records a failed attempt. state should be Failed, TimedOut or
// Degraded.
func (r *Registry) Failure(name string, state State, detail string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	e := r.get(name)
	if e == nil {
		return
	}
	now := r.now()
	e.c.Attempts++
	e.c.Failures++
	e.c.LastAttempt = &now
	e.c.Detail, e.last, e.disabled = Sanitize(detail), state, false
}

// Degrade marks a component degraded without counting a failed attempt
// (e.g. work was shed, an optional source is missing).
func (r *Registry) Degrade(name, detail string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if e := r.get(name); e != nil {
		e.c.Detail, e.last, e.disabled = Sanitize(detail), Degraded, false
	}
}

// Disable records that a component is intentionally off.
func (r *Registry) Disable(name, reason string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if e := r.get(name); e != nil {
		e.c.Detail, e.disabled = Sanitize(reason), true
	}
}

// Count increments a named counter on a component.
func (r *Registry) Count(name, counter string, n uint64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	e := r.get(name)
	if e == nil {
		return
	}
	if e.c.Counters == nil {
		e.c.Counters = map[string]uint64{}
	}
	if _, ok := e.c.Counters[counter]; !ok && len(e.c.Counters) >= 8 {
		return // bounded counter set
	}
	e.c.Counters[counter] += n
}

// SetCounter overwrites a counter (for sources that keep their own totals).
func (r *Registry) SetCounter(name, counter string, v uint64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	e := r.get(name)
	if e == nil {
		return
	}
	if e.c.Counters == nil {
		e.c.Counters = map[string]uint64{}
	}
	if _, ok := e.c.Counters[counter]; !ok && len(e.c.Counters) >= 8 {
		return
	}
	e.c.Counters[counter] = v
}

// Snapshot derives each component's state at the registry clock and
// returns them sorted by name.
func (r *Registry) Snapshot() []Component {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.now()
	out := make([]Component, 0, len(r.comps))
	for _, e := range r.comps {
		c := e.c
		if e.c.Counters != nil {
			c.Counters = make(map[string]uint64, len(e.c.Counters))
			for k, v := range e.c.Counters {
				c.Counters[k] = v
			}
		}
		switch {
		case e.disabled:
			c.State = Disabled
		case e.c.LastAttempt == nil && e.last == "":
			c.State = NotYetObserved
		case e.last == Healthy:
			c.State = Healthy
			if e.expect > 0 && e.c.LastSuccess != nil && now.Sub(*e.c.LastSuccess) > StaleFactor*e.expect {
				c.State = Unknown
				c.Detail = "no successful observation within the expected interval (missing telemetry, not a clean result)"
			}
		default:
			c.State = e.last
		}
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

var severity = map[State]int{Healthy: 0, Disabled: 0, NotYetObserved: 1, Unknown: 2, Degraded: 3, TimedOut: 4, Failed: 5}

// Overall folds component states into one: "healthy" only when every
// component is healthy or intentionally disabled.
func Overall(cs []Component) State {
	worst := Healthy
	for _, c := range cs {
		if severity[c.State] > severity[worst] {
			worst = c.State
		}
	}
	return worst
}
