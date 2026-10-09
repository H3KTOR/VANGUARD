package detection

import (
	"time"

	"vanguard/core/internal/database"
)

// persistAttempts bounds how often createIncident tries to store one incident.
// SQLite already waits up to its busy timeout inside each attempt; the extra
// attempts only cover brief errors, and the total added delay is bounded
// (persistBackoff[0]+persistBackoff[1]) so a failing database can never stall
// a log source for long.
const persistAttempts = 3

var persistBackoff = [persistAttempts - 1]time.Duration{50 * time.Millisecond, 200 * time.Millisecond}

// PersistStats describes incident-persistence outcomes since start. A
// non-zero Failed means incidents were detected but NOT recorded and NOT
// handed to response; the dedupe cooldown for those keys is still running,
// so repeats within the cooldown are suppressed too.
type PersistStats struct {
	Created       uint64
	Failed        uint64
	LastFailureAt time.Time // zero = never
	LastError     string
}

// Stats reports incident persistence outcomes.
func (e *Engine) Stats() PersistStats {
	e.pmu.Lock()
	defer e.pmu.Unlock()
	return PersistStats{Created: e.persistOK, Failed: e.persistFail, LastFailureAt: e.persistLastAt, LastError: e.persistLastErr}
}

// persist stores inc with a small bounded retry and records the outcome.
func (e *Engine) persist(inc *database.Incident) error {
	var err error
	for attempt := 0; attempt < persistAttempts; attempt++ {
		if attempt > 0 {
			time.Sleep(persistBackoff[attempt-1])
		}
		// A failed Create may have left an ID behind on the struct; reset so a
		// retry cannot attempt to insert a half-initialised primary key.
		inc.ID = 0
		if err = e.db.CreateIncident(inc); err == nil {
			e.pmu.Lock()
			e.persistOK++
			e.pmu.Unlock()
			return nil
		}
	}
	e.pmu.Lock()
	e.persistFail++
	e.persistLastAt = time.Now().UTC()
	e.persistLastErr = err.Error()
	e.pmu.Unlock()
	return err
}
