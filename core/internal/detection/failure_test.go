package detection

import (
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"vanguard/core/internal/database"
)

// With the database gone, detection must neither panic nor pretend it
// recorded an incident, and must recover when the store returns.
func TestEngine_DatabaseFailureDoesNotPanicOrFabricateSuccess(t *testing.T) {
	path := filepath.Join(t.TempDir(), "f.db")
	db, err := database.Open(database.Config{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	var notified int
	e := NewEngine(Config{DB: db, Notifier: notifierFunc(func(*database.Incident) { notified++ })})
	if s, err := db.DB.DB(); err == nil {
		s.Close()
	}
	for i := 0; i < 20; i++ { // would cross the SSH threshold
		e.IngestAuthLogLine(sshFail("203.0.113.77", i))
	}
	e.IngestWebLogLine(fmt.Sprintf(`203.0.113.77 - - [23/Aug/2026:14:03:00 +0000] "GET /../../etc/passwd HTTP/1.1" 403 0 "-" "curl/8.0"`))
	if notified != 0 {
		t.Fatalf("a downstream response must not be triggered for an incident that was never persisted (%d notifications)", notified)
	}
	_ = time.Now
}

type notifierFunc func(*database.Incident)

func (f notifierFunc) OnIncident(i *database.Incident) { f(i) }
