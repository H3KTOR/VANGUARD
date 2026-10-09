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
	st := e.Stats()
	if st.Failed == 0 || st.Created != 0 || st.LastError == "" || st.LastFailureAt.IsZero() {
		t.Fatalf("a lost incident must be visible in Stats, got %+v", st)
	}
}

func TestEngine_PersistRetriesAreBoundedAndCounted(t *testing.T) {
	old := persistBackoff
	persistBackoff = [persistAttempts - 1]time.Duration{time.Millisecond, time.Millisecond}
	defer func() { persistBackoff = old }()

	db, err := database.Open(database.Config{Path: filepath.Join(t.TempDir(), "p.db")})
	if err != nil {
		t.Fatal(err)
	}
	e := NewEngine(Config{DB: db})
	for i := 0; i < 20; i++ {
		e.IngestAuthLogLine(sshFail("203.0.113.78", i))
	}
	if st := e.Stats(); st.Created != 1 || st.Failed != 0 {
		t.Fatalf("healthy database: want 1 created / 0 failed, got %+v", st)
	}
	var n int64
	db.Model(&database.Incident{}).Count(&n)
	if n != 1 {
		t.Fatalf("expected exactly one stored incident, got %d", n)
	}

	// Dead store: the attempt count is bounded and exactly one failure recorded.
	if s, err := db.DB.DB(); err == nil {
		s.Close()
	}
	start := time.Now()
	for i := 0; i < 20; i++ {
		e.IngestAuthLogLine(sshFail("203.0.113.79", i))
	}
	if time.Since(start) > 5*time.Second {
		t.Fatalf("failing persistence stalled ingestion for %s", time.Since(start))
	}
	if st := e.Stats(); st.Failed != 1 || st.Created != 1 {
		t.Fatalf("want 1 created / 1 failed, got %+v", st)
	}
}

type notifierFunc func(*database.Incident)

func (f notifierFunc) OnIncident(i *database.Incident) { f(i) }
