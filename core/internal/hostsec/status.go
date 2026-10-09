package hostsec

// Phase 5, Milestone 4: per-scanner operational status.
//
// The point is to make "the scanner ran and found nothing" distinguishable
// from "the scanner could not run" (unreadable /proc, missing package
// database, baseline store error, timeout, panic). Status is local,
// in-memory, fixed-cardinality (one entry per scanner) and contains no
// attacker-controlled labels.

import (
	"sort"
	"sync"
	"time"
)

// Scan result labels.
const (
	ResultNever   = "never_run"
	ResultOK      = "ok"
	ResultSkipped = "skipped" // intentionally idle (e.g. unsupported platform / data source absent)
	ResultFailed  = "failed"  // tried and could not complete; baseline preserved
	ResultTimeout = "timeout" // hit the per-scan deadline before finishing
)

var resultRank = map[string]int{ResultOK: 0, ResultSkipped: 1, ResultTimeout: 2, ResultFailed: 3}

// ScanStatus is the snapshot exposed via the API.
type ScanStatus struct {
	Name            string     `json:"name"`
	IntervalSeconds int64      `json:"interval_seconds"`
	LastStarted     *time.Time `json:"last_started,omitempty"`
	LastFinished    *time.Time `json:"last_finished,omitempty"`
	LastDurationMS  int64      `json:"last_duration_ms"`
	LastResult      string     `json:"last_result"`
	LastNote        string     `json:"last_note,omitempty"`
	// LastCleanScan is the last time a scan completed with result "ok".
	// A scanner that keeps failing therefore never advances it.
	LastCleanScan *time.Time `json:"last_clean_scan,omitempty"`
	Runs          uint64     `json:"runs"`
	Failures      uint64     `json:"failures"`
	Skips         uint64     `json:"skips"`
	Timeouts      uint64     `json:"timeouts"`
}

// StatusBoard tracks ScanStatus for a fixed set of scanner names.
type StatusBoard struct {
	mu      sync.Mutex
	entries map[string]*ScanStatus
	// pending holds the in-flight scan's worst result/note.
	pending map[string]pendingResult
}

type pendingResult struct{ result, note string }

// NewStatusBoard returns an empty board.
func NewStatusBoard() *StatusBoard {
	return &StatusBoard{entries: map[string]*ScanStatus{}, pending: map[string]pendingResult{}}
}

// Register declares a scanner (fixed cardinality: only registered names
// are ever recorded).
func (b *StatusBoard) Register(name string, interval time.Duration) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.entries[name] = &ScanStatus{Name: name, IntervalSeconds: int64(interval.Seconds()), LastResult: ResultNever}
}

func (b *StatusBoard) begin(name string, now time.Time) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if e, ok := b.entries[name]; ok {
		e.LastStarted = &now
		b.pending[name] = pendingResult{result: ResultOK}
	}
}

// report lets a running scan downgrade its own result (worst wins; the
// first note of the worst severity is kept).
func (b *StatusBoard) report(name, result, note string) {
	if b == nil {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if _, ok := b.entries[name]; !ok {
		return
	}
	cur := b.pending[name]
	if cur.result == "" {
		cur.result = ResultOK
	}
	if resultRank[result] > resultRank[cur.result] {
		b.pending[name] = pendingResult{result: result, note: truncate(note, 200)}
	}
}

func (b *StatusBoard) end(name string, start, now time.Time, forced string, forcedNote string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	e, ok := b.entries[name]
	if !ok {
		return
	}
	p := b.pending[name]
	delete(b.pending, name)
	result, note := p.result, p.note
	if result == "" {
		result = ResultOK
	}
	if forced != "" && resultRank[forced] > resultRank[result] {
		result, note = forced, forcedNote
	}
	e.LastFinished = &now
	e.LastDurationMS = now.Sub(start).Milliseconds()
	e.LastResult, e.LastNote = result, note
	e.Runs++
	switch result {
	case ResultOK:
		e.LastCleanScan = &now
	case ResultSkipped:
		e.Skips++
	case ResultTimeout:
		e.Timeouts++
	case ResultFailed:
		e.Failures++
	}
}

// Snapshot returns a copy of every scanner's status sorted by name.
func (b *StatusBoard) Snapshot() []ScanStatus {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make([]ScanStatus, 0, len(b.entries))
	for _, e := range b.entries {
		out = append(out, *e)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// scanReporter is the nil-safe hook a detector uses to say "this scan was
// skipped/failed" instead of silently returning.
type scanReporter func(result, note string)

func (r scanReporter) fail(note string) {
	if r != nil {
		r(ResultFailed, note)
	}
}

func (r scanReporter) skip(note string) {
	if r != nil {
		r(ResultSkipped, note)
	}
}
