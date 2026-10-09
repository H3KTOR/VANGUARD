package detection

import (
	"context"
	"log"
	"os"

	"github.com/nxadm/tail"
)

// LineHandler processes a single new log line. AuthLogParser/WebLogParser
// wrapped via Engine.IngestAuthLogLine / IngestWebLogLine satisfy this
// signature.
type LineHandler func(line string)

// TailObserver receives lifecycle facts about one tailer so runtime health
// can report what actually happened (a tailer that never opened its file is
// missing telemetry, not a quiet log). All methods may be called from the
// tailer goroutine only; implementations must be cheap and non-blocking.
type TailObserver interface {
	// Waiting: the file does not exist (yet); the tailer is waiting for it.
	Waiting()
	// Started: the file is open and being followed.
	Started()
	// StartFailed: the tailer could not start and will not run.
	StartFailed(err error)
	// Line: one line was delivered to the handler.
	Line()
	// Error: the tail library reported a per-line error.
	Error(err error)
	// Stopped: the tailer exited (context cancelled or channel closed).
	Stopped()
}

// TailFile follows path like TailFileObserved without an observer. A
// missing file is non-fatal: VANGUARD logs a warning and keeps waiting.
func TailFile(ctx context.Context, path string, handler LineHandler) error {
	return TailFileObserved(ctx, path, handler, nil)
}

// TailFileObserved follows path (like `tail -f`) starting from the end of
// the file (ReOpen handles log rotation via copytruncate or rename+create,
// which is how logrotate configures auth.log/nginx by default on most
// distros), and calls handler for every new line until ctx is cancelled.
// obs, when non-nil, is told what happened so health can be reported
// honestly.
//
// It blocks until ctx is done or an unrecoverable error occurs; run it in
// its own goroutine per log source. A source that cannot be started never
// prevents the rest of the agent from starting, but it is reported via obs
// instead of disappearing into a log line.
func TailFileObserved(ctx context.Context, path string, handler LineHandler, obs TailObserver) error {
	if obs == nil {
		obs = noopTailObserver{}
	}
	if _, err := os.Stat(path); err != nil {
		obs.Waiting()
	}
	t, err := tail.TailFile(path, tail.Config{
		Follow:    true,
		ReOpen:    true,
		MustExist: false,
		Poll:      false,
		Location:  &tail.SeekInfo{Whence: 2}, // start at EOF: only new events, never replay history
	})
	if err != nil {
		log.Printf("[detection] could not tail %s: %v (this log source will be skipped)", path, err)
		obs.StartFailed(err)
		return nil
	}
	defer t.Cleanup()
	defer obs.Stopped()

	log.Printf("[detection] tailing %s", path)
	if _, err := os.Stat(path); err == nil {
		obs.Started()
	}

	for {
		select {
		case <-ctx.Done():
			_ = t.Stop()
			return nil
		case line, ok := <-t.Lines:
			if !ok {
				return nil
			}
			if line.Err != nil {
				log.Printf("[detection] tail error on %s: %v", path, line.Err)
				obs.Error(line.Err)
				continue
			}
			// A delivered line proves the file is open even if it appeared
			// after startup.
			obs.Started()
			obs.Line()
			handler(line.Text)
		}
	}
}

type noopTailObserver struct{}

func (noopTailObserver) Waiting()          {}
func (noopTailObserver) Started()          {}
func (noopTailObserver) StartFailed(error) {}
func (noopTailObserver) Line()             {}
func (noopTailObserver) Error(error)       {}
func (noopTailObserver) Stopped()          {}
