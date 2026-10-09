// Package pipeline decouples log ingestion from detection work with a
// bounded, ordered, observable queue.
//
// Why a queue and why only one worker per source: detection state
// (sliding windows, attack-chain trackers, dedupe) is keyed by source IP and
// is order-sensitive within one log source, so each source gets exactly one
// worker that applies lines in arrival order. Different sources already run
// concurrently today and the engine's trackers are lock-protected; this
// package changes neither fact. It adds burst absorption, a hard memory
// bound, panic containment and honest loss accounting.
//
// Backpressure, not silent loss: when the queue is full Submit BLOCKS the
// producer (the log tailer) until a slot frees up or shutdown begins. The log
// file itself is the durable buffer while the producer waits. The only lines
// this package ever discards are (a) lines larger than MaxLineBytes, which no
// supported parser can interpret, and (b) lines still queued when the drain
// deadline passes at shutdown. Both are counted, timestamped, and surfaced
// through Stats so health reporting can never claim a clean result.
package pipeline

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

const (
	DefaultSize         = 1024
	MaxSize             = 65536
	DefaultMaxLineBytes = 64 * 1024
	DefaultDrainTimeout = 2 * time.Second
)

// Config controls one Queue.
type Config struct {
	Name string
	// Size is the queue capacity in lines (default DefaultSize, capped at
	// MaxSize).
	Size int
	// MaxLineBytes: longer lines are dropped and counted (default 64 KiB).
	MaxLineBytes int
	// DrainTimeout bounds how long Run keeps processing already-queued lines
	// after shutdown begins (default 2s). Lines left afterwards are counted
	// as abandoned.
	DrainTimeout time.Duration
}

// Stats is a point-in-time snapshot. All counters are since process start.
type Stats struct {
	Name      string
	Capacity  int
	Depth     int
	HighWater uint64
	Running   bool

	Enqueued  uint64
	Processed uint64
	// Failed: handler panics (the line was lost, the worker continued).
	Failed uint64
	// Waits: how many times a producer found the queue full and had to wait.
	Waits uint64
	// Oversize: lines larger than MaxLineBytes that were dropped.
	Oversize uint64
	// RejectedShutdown: lines offered after shutdown began (not accepted).
	RejectedShutdown uint64
	// Abandoned: queued lines never processed because the drain deadline
	// passed.
	Abandoned uint64

	LastLoss     time.Time // zero = no loss ever
	LastLossKind string
	LastError    string
}

// Lost is the total number of lines that were definitely not processed.
func (s Stats) Lost() uint64 { return s.Failed + s.Oversize + s.RejectedShutdown + s.Abandoned }

// Queue is a bounded FIFO with a single worker.
type Queue struct {
	cfg     Config
	handler func(string)
	ch      chan string

	stop     chan struct{} // closed when shutdown begins
	stopOnce sync.Once
	running  atomic.Bool
	started  atomic.Bool
	finished atomic.Bool // the worker has exited; nothing will consume the queue

	enqueued, processed, failed, waits, oversize, rejected, abandoned atomic.Uint64
	highWater                                                         atomic.Uint64

	mu           sync.Mutex
	lastLoss     time.Time
	lastLossKind string
	lastErr      string
	now          func() time.Time
}

// New builds a queue; Run must be started for lines to be processed.
func New(cfg Config, handler func(string)) *Queue {
	if cfg.Size <= 0 {
		cfg.Size = DefaultSize
	}
	if cfg.Size > MaxSize {
		cfg.Size = MaxSize
	}
	if cfg.MaxLineBytes <= 0 {
		cfg.MaxLineBytes = DefaultMaxLineBytes
	}
	if cfg.DrainTimeout <= 0 {
		cfg.DrainTimeout = DefaultDrainTimeout
	}
	return &Queue{
		cfg: cfg, handler: handler,
		ch:   make(chan string, cfg.Size),
		stop: make(chan struct{}),
		now:  func() time.Time { return time.Now().UTC() },
	}
}

// Name returns the configured source name.
func (q *Queue) Name() string { return q.cfg.Name }

func (q *Queue) noteLoss(kind string) {
	q.mu.Lock()
	q.lastLoss, q.lastLossKind = q.now(), kind
	q.mu.Unlock()
}

// Submit offers one line. It returns true when the line was queued. It blocks
// while the queue is full (backpressure) and returns false only when the line
// was dropped as oversize or shutdown has begun; both are counted.
func (q *Queue) Submit(line string) bool {
	if len(line) > q.cfg.MaxLineBytes {
		q.oversize.Add(1)
		q.noteLoss("oversize_line")
		return false
	}
	select {
	case <-q.stop:
		q.rejected.Add(1)
		q.noteLoss("rejected_after_shutdown")
		return false
	default:
	}
	select {
	case q.ch <- line:
	default:
		q.waits.Add(1)
		select {
		case q.ch <- line:
		case <-q.stop:
			q.rejected.Add(1)
			q.noteLoss("rejected_after_shutdown")
			return false
		}
	}
	if q.finished.Load() {
		// Raced with the end of Run: nobody will consume this line. Count it
		// rather than let it vanish (may over-count by a line in this race).
		q.abandoned.Add(1)
		q.noteLoss("abandoned_at_shutdown")
		return false
	}
	q.enqueued.Add(1)
	if d := uint64(len(q.ch)); d > q.highWater.Load() {
		q.highWater.Store(d) // approximate; monitoring only
	}
	return true
}

// Run processes lines until ctx is cancelled, then drains what is queued for
// at most DrainTimeout. It must be called at most once; a second call is a
// no-op that returns immediately.
func (q *Queue) Run(ctx context.Context) {
	if !q.started.CompareAndSwap(false, true) {
		return
	}
	q.running.Store(true)
	defer q.running.Store(false)
	// Producers must be released the moment shutdown begins, even if the
	// handler is wedged and the worker cannot get back to its select.
	stopAll := context.AfterFunc(ctx, func() { q.stopOnce.Do(func() { close(q.stop) }) })
	defer stopAll()

	for {
		select {
		case <-ctx.Done():
			q.stopOnce.Do(func() { close(q.stop) })
			q.drain()
			q.finished.Store(true)
			if n := uint64(len(q.ch)); n > 0 { // arrivals that raced the end of the drain
				for len(q.ch) > 0 {
					<-q.ch
				}
				q.abandoned.Add(n)
				q.noteLoss("abandoned_at_shutdown")
			}
			return
		case line := <-q.ch:
			q.process(line)
		}
	}
}

func (q *Queue) drain() {
	deadline := time.Now().Add(q.cfg.DrainTimeout)
	for {
		select {
		case line := <-q.ch:
			if time.Now().After(deadline) {
				n := uint64(1 + len(q.ch))
				for len(q.ch) > 0 {
					<-q.ch
				}
				q.abandoned.Add(n)
				q.noteLoss("abandoned_at_shutdown")
				return
			}
			q.process(line)
		default:
			return
		}
	}
}

// process runs the handler with panic containment: one poisonous line must
// not kill the worker (which would silently stop all detection for the
// source), and must be counted as a processing failure.
func (q *Queue) process(line string) {
	defer func() {
		if r := recover(); r != nil {
			q.failed.Add(1)
			q.mu.Lock()
			q.lastErr = fmt.Sprintf("handler panic: %v", r)
			q.mu.Unlock()
			q.noteLoss("handler_panic")
			return
		}
		q.processed.Add(1)
	}()
	q.handler(line)
}

// Stats returns a snapshot.
func (q *Queue) Stats() Stats {
	q.mu.Lock()
	ll, lk, le := q.lastLoss, q.lastLossKind, q.lastErr
	q.mu.Unlock()
	return Stats{
		Name: q.cfg.Name, Capacity: cap(q.ch), Depth: len(q.ch), HighWater: q.highWater.Load(),
		Running: q.running.Load(), Enqueued: q.enqueued.Load(), Processed: q.processed.Load(),
		Failed: q.failed.Load(), Waits: q.waits.Load(), Oversize: q.oversize.Load(),
		RejectedShutdown: q.rejected.Load(), Abandoned: q.abandoned.Load(),
		LastLoss: ll, LastLossKind: lk, LastError: le,
	}
}
