package detection

import (
	"context"
	"log"

	"github.com/nxadm/tail"
)

// LineHandler processes a single new log line. AuthLogParser/WebLogParser
// wrapped via Engine.IngestAuthLogLine / IngestWebLogLine satisfy this
// signature.
type LineHandler func(line string)

// TailFile follows path (like `tail -f`) starting from the end of the file
// (ReOpen handles log rotation via copytruncate or rename+create, which is
// how logrotate configures auth.log/nginx by default on most distros), and
// calls handler for every new line until ctx is cancelled.
//
// TailFile blocks until ctx is done or an unrecoverable error occurs; run
// it in its own goroutine per log source. A missing file is treated as
// non-fatal: VANGUARD logs a warning and returns nil so one absent log
// source (e.g. no Nginx installed) never prevents the rest of the agent
// from starting.
func TailFile(ctx context.Context, path string, handler LineHandler) error {
	t, err := tail.TailFile(path, tail.Config{
		Follow:    true,
		ReOpen:    true,
		MustExist: false,
		Poll:      false,
		Location:  &tail.SeekInfo{Whence: 2}, // start at EOF: only new events, never replay history
	})
	if err != nil {
		log.Printf("[detection] could not tail %s: %v (this log source will be skipped)", path, err)
		return nil
	}
	defer t.Cleanup()

	log.Printf("[detection] tailing %s", path)

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
				continue
			}
			handler(line.Text)
		}
	}
}
