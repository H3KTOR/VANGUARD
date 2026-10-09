package database

import (
	"errors"
	"log"
	"os"
	"runtime"
)

// prepareFile makes sure a NEW database file is created private (mode 0600)
// instead of with the process umask (typically 0644, readable by every local
// account: it holds password hashes and incident data). SQLite gives its -wal
// and -shm files the same mode as the main file, so this covers them too.
//
// An EXISTING database is never modified - changing an operator's file mode
// behind their back could break a backup tool or a co-located job - but a
// loose mode is logged so it is not silent. `vanguard doctor` reports it as well.
func prepareFile(path string) {
	if path == "" || path == ":memory:" || runtime.GOOS == "windows" {
		return
	}
	st, err := os.Stat(path)
	switch {
	case err == nil:
		if m := st.Mode().Perm(); m&0o077 != 0 {
			log.Printf("[database] WARNING: %s has mode %04o, readable by other accounts; consider chmod 600 (and the -wal/-shm files) while the service is stopped", path, m)
		}
	case errors.Is(err, os.ErrNotExist):
		f, cerr := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if cerr == nil {
			_ = f.Close()
		}
		// Any failure here (missing directory, read-only volume) is left for
		// SQLite to report with its own, more specific error.
	}
}
