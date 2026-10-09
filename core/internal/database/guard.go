package database

import (
	"context"
	"errors"
	"sync/atomic"
	"time"
)

// Why this exists (measured, not assumed): with the pure-Go SQLite driver in
// use, cancelling a context does NOT interrupt a statement that is already
// executing. A query given a 200 ms deadline still ran to completion (38 s in
// the experiment recorded in docs/PHASE12.md) and only then returned
// context.DeadlineExceeded. A context parameter therefore cannot, by itself,
// stop a slow query.
//
// The QueryGuard provides containment instead of cancellation:
//   - at most Limit guarded operations run at once, so slow readers cannot
//     take every connection of the (8-connection) pool from writers;
//   - the CALLER gets an answer within Timeout (ErrTimeout) even if the
//     statement keeps running in the background;
//   - the slot of an abandoned operation stays occupied until the statement
//     really finishes, so abandoned work still counts against the limit and
//     cannot pile up without bound.
//
// The abandoned statement itself keeps its connection until it ends; this is
// documented, bounded by Limit, and reported by Stats.

var (
	// ErrBusy: every guard slot is in use (or abandoned operations still hold them).
	ErrBusy = errors.New("database busy: too many expensive queries in flight")
	// ErrTimeout: the operation did not finish within the guard timeout. It may
	// still be running; its result is discarded.
	ErrTimeout = errors.New("database operation timed out")
)

// GuardStats are cumulative counters plus current gauges.
type GuardStats struct {
	Limit     int
	InFlight  int    // slots currently held (including abandoned operations)
	Abandoned int    // timed-out operations whose statement is still running
	Started   uint64 // operations that obtained a slot
	Rejected  uint64 // ErrBusy
	TimedOut  uint64 // ErrTimeout
}

// QueryGuard bounds concurrent expensive operations. The zero value is not usable; use NewQueryGuard.
type QueryGuard struct {
	sem     chan struct{}
	timeout time.Duration
	wait    time.Duration

	abandoned atomic.Int64
	started   atomic.Uint64
	rejected  atomic.Uint64
	timedOut  atomic.Uint64
}

// NewQueryGuard builds a guard allowing limit concurrent operations. A caller
// that cannot get a slot within wait is rejected; an operation that does not
// finish within timeout is abandoned.
func NewQueryGuard(limit int, wait, timeout time.Duration) *QueryGuard {
	if limit < 1 {
		limit = 1
	}
	if wait < 0 {
		wait = 0
	}
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	return &QueryGuard{sem: make(chan struct{}, limit), timeout: timeout, wait: wait}
}

// Do runs fn under the guard. fn must not touch request-scoped objects
// (such as an HTTP context) after Do returns, because on timeout it keeps
// running in its own goroutine. Results must be written to variables owned by
// the caller and only read after Do returned nil.
func (g *QueryGuard) Do(ctx context.Context, fn func() error) error {
	t := time.NewTimer(g.wait)
	defer t.Stop()
	select {
	case g.sem <- struct{}{}:
	case <-ctx.Done():
		g.rejected.Add(1)
		return ctx.Err()
	case <-t.C:
		g.rejected.Add(1)
		return ErrBusy
	}
	g.started.Add(1)

	const (
		running   = 0
		finished  = 1
		abandoned = 2
	)
	var state atomic.Int32 // arbitrates the finish-vs-give-up race exactly once
	done := make(chan error, 1)
	go func() {
		var err error
		defer func() {
			if r := recover(); r != nil {
				err = errors.New("database operation panicked")
			}
			if !state.CompareAndSwap(running, finished) {
				g.abandoned.Add(-1) // the caller already gave up on us
			}
			<-g.sem // the slot is released only when the statement truly ends
			done <- err
		}()
		err = fn()
	}()

	timer := time.NewTimer(g.timeout)
	defer timer.Stop()
	select {
	case err := <-done:
		return err
	case <-timer.C:
	case <-ctx.Done():
	}
	g.abandoned.Add(1) // before the CAS so the worker's decrement can never go first
	if !state.CompareAndSwap(running, abandoned) {
		g.abandoned.Add(-1) // it finished in the instant before we gave up
		return <-done
	}
	g.timedOut.Add(1)
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return ErrTimeout
}

// Stats returns a snapshot.
func (g *QueryGuard) Stats() GuardStats {
	return GuardStats{
		Limit: cap(g.sem), InFlight: len(g.sem), Abandoned: int(g.abandoned.Load()),
		Started: g.started.Load(), Rejected: g.rejected.Load(), TimedOut: g.timedOut.Load(),
	}
}
