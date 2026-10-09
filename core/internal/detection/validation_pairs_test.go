package detection

// Phase 8 positive/benign pairs and threshold-boundary tests for the
// classic (Phase 0-1) detectors. Each case asserts both the presence and
// the ABSENCE of incidents, at, one below and one above the documented
// threshold. Observed semantics (verified against the implementation):
//
//	port scan        incident when distinct ports  >  PortScanDistinctPorts
//	web dir scan     incident when sensitive 404s  >= WebDirScanMin404s
//	http flood       incident when requests        >  HTTPFloodMaxRequests
//	ssh brute force  incident when failures        >  SSHBruteForceMinAttempts
//	failed->success  incident when failures        >= FailedThenSuccessMinFailed

import (
	"fmt"
	"testing"
	"time"

	"vanguard/core/internal/database"
	"vanguard/core/internal/thresholds"
)

func nIncidents(t *testing.T, db *database.DB, typ database.IncidentType) int {
	t.Helper()
	return len(incidentsOfType(t, db, typ))
}

func sshFail(ip string, i int) string {
	return fmt.Sprintf("%s host sshd[1]: Failed password for root from %s port 4%04d ssh2", time.Now().In(time.Local).Format("Jan _2 15:04:05"), ip, i)
}

func sshOK(ip string) string {
	return fmt.Sprintf("%s host sshd[1]: Accepted password for root from %s port 4000 ssh2", time.Now().In(time.Local).Format("Jan _2 15:04:05"), ip)
}

func TestPairs_PortScan(t *testing.T) {
	for _, c := range []struct {
		name  string
		ports int
		want  int
	}{{"below", thresholds.PortScanDistinctPorts - 1, 0}, {"at", thresholds.PortScanDistinctPorts, 0}, {"above", thresholds.PortScanDistinctPorts + 1, 1}} {
		e, db := testEngine(t)
		for p := 0; p < c.ports; p++ {
			e.IngestPortTouch("203.0.113.1", 1000+p, time.Now().UTC())
		}
		if got := nIncidents(t, db, database.IncidentPortScan); got != c.want {
			t.Errorf("%s (%d ports): got %d incidents, want %d", c.name, c.ports, got, c.want)
		}
	}
	// benign control: one service hit many times is not a scan
	e, db := testEngine(t)
	for i := 0; i < 200; i++ {
		e.IngestPortTouch("203.0.113.1", 443, time.Now().UTC())
	}
	if nIncidents(t, db, database.IncidentPortScan) != 0 {
		t.Error("repeated touches of ONE port must not look like a scan")
	}
}

func TestPairs_WebDirScan(t *testing.T) {
	line := func(i int, path string) string {
		return fmt.Sprintf(`203.0.113.2 - - [23/Aug/2026:14:02:%02d +0000] "GET %s HTTP/1.1" 404 162 "-" "Mozilla/5.0"`, i%60, path)
	}
	for _, c := range []struct {
		name string
		n    int
		want int
	}{{"below", thresholds.WebDirScanMin404s - 1, 0}, {"at", thresholds.WebDirScanMin404s, 1}, {"above", thresholds.WebDirScanMin404s + 1, 1}} {
		e, db := testEngine(t)
		for i := 0; i < c.n; i++ {
			e.IngestWebLogLine(line(i, "/wp-admin"))
		}
		if got := nIncidents(t, db, database.IncidentWebDirScan); got != c.want {
			t.Errorf("%s (%d): got %d want %d", c.name, c.n, got, c.want)
		}
	}
	// benign control: many 404s on ordinary, non-sensitive paths (broken links)
	e, db := testEngine(t)
	for i := 0; i < 60; i++ {
		e.IngestWebLogLine(line(i, fmt.Sprintf("/old-page-%d.html", i)))
	}
	if nIncidents(t, db, database.IncidentWebDirScan) != 0 {
		t.Error("404s on non-sensitive paths must not be a directory scan")
	}
}

func TestPairs_HTTPFlood(t *testing.T) {
	const req = `203.0.113.3 - - [23/Aug/2026:14:05:00 +0000] "GET /index.html HTTP/1.1" 200 512 "-" "curl/8.0"`
	for _, c := range []struct {
		name string
		n    int
		want int
	}{{"below", thresholds.HTTPFloodMaxRequests - 1, 0}, {"at", thresholds.HTTPFloodMaxRequests, 0}, {"above", thresholds.HTTPFloodMaxRequests + 1, 1}} {
		e, db := testEngine(t)
		for i := 0; i < c.n; i++ {
			e.IngestWebLogLine(req)
		}
		if got := nIncidents(t, db, database.IncidentHTTPFlood); got != c.want {
			t.Errorf("%s (%d): got %d want %d", c.name, c.n, got, c.want)
		}
	}
	// benign control: the same total volume spread across many clients
	e, db := testEngine(t)
	for i := 0; i < thresholds.HTTPFloodMaxRequests*2; i++ {
		e.IngestWebLogLine(fmt.Sprintf(`203.0.113.%d - - [23/Aug/2026:14:05:00 +0000] "GET /index.html HTTP/1.1" 200 512 "-" "curl/8.0"`, 10+i%100))
	}
	if nIncidents(t, db, database.IncidentHTTPFlood) != 0 {
		t.Error("popular-site traffic spread over many clients is not a flood")
	}
}

func TestPairs_SSHBruteForceAndFailedThenSuccess(t *testing.T) {
	for _, c := range []struct {
		name string
		n    int
		want int
	}{{"at", thresholds.SSHBruteForceMinAttempts, 0}, {"above", thresholds.SSHBruteForceMinAttempts + 1, 1}} {
		e, db := testEngine(t)
		for i := 0; i < c.n; i++ {
			e.IngestAuthLogLine(sshFail("203.0.113.4", i))
		}
		if got := nIncidents(t, db, database.IncidentSSHBruteForce); got != c.want {
			t.Errorf("ssh %s (%d): got %d want %d", c.name, c.n, got, c.want)
		}
	}
	// benign control: the same failure volume from many different sources
	e, db := testEngine(t)
	for i := 0; i < 40; i++ {
		e.IngestAuthLogLine(sshFail(fmt.Sprintf("203.0.113.%d", 20+i), i))
	}
	if nIncidents(t, db, database.IncidentSSHBruteForce) != 0 {
		t.Error("failures must not be pooled across sources")
	}

	// failed -> success: below, at; and a plain success
	for _, c := range []struct {
		name string
		n    int
		want int
	}{{"success only", 0, 0}, {"below", thresholds.FailedThenSuccessMinFailed - 1, 0}, {"at", thresholds.FailedThenSuccessMinFailed, 1}} {
		e, db := testEngine(t)
		for i := 0; i < c.n; i++ {
			e.IngestAuthLogLine(sshFail("203.0.113.6", i))
		}
		e.IngestAuthLogLine(sshOK("203.0.113.6"))
		if got := nIncidents(t, db, database.IncidentFailedThenSuccess); got != c.want {
			t.Errorf("failed->success %s (%d): got %d want %d", c.name, c.n, got, c.want)
		}
	}
	// benign control: a different host's success after someone else's failures
	e2, db2 := testEngine(t)
	for i := 0; i < 20; i++ {
		e2.IngestAuthLogLine(sshFail("203.0.113.7", i))
	}
	e2.IngestAuthLogLine(sshOK("203.0.113.8"))
	if nIncidents(t, db2, database.IncidentFailedThenSuccess) != 0 {
		t.Error("a success from a different source must not be paired with another source's failures")
	}
}

// A resolved incident must not suppress a genuine recurrence once the
// dedupe cooldown has passed, and must not be re-raised inside it.
func TestPairs_RecurrenceAfterResolutionVersusRepeat(t *testing.T) {
	e, db := testEngine(t)
	e.dedupe = newDedupeWindow(80 * time.Millisecond)
	burst := func() {
		for i := 0; i < thresholds.SSHBruteForceMinAttempts+1; i++ {
			e.IngestAuthLogLine(sshFail("203.0.113.9", i))
		}
	}
	burst()
	first := incidentsOfType(t, db, database.IncidentSSHBruteForce)
	if len(first) != 1 {
		t.Fatalf("first burst: %d", len(first))
	}
	if _, err := db.TransitionIncident(first[0].ID, database.StatusResolved, "analyst", "blocked upstream"); err != nil {
		t.Fatal(err)
	}
	burst() // immediately again: inside the cooldown => same episode, not re-raised
	if n := nIncidents(t, db, database.IncidentSSHBruteForce); n != 1 {
		t.Fatalf("repeat inside cooldown created a duplicate: %d", n)
	}
	time.Sleep(120 * time.Millisecond)
	burst() // genuine recurrence after resolution + cooldown
	all := incidentsOfType(t, db, database.IncidentSSHBruteForce)
	if len(all) != 2 {
		t.Fatalf("recurrence after resolution must be reported: %d incidents", len(all))
	}
	cur, _ := db.GetIncident(first[0].ID)
	if cur.Status != database.StatusResolved {
		t.Fatal("the resolved incident must stay resolved; recurrence is a new incident")
	}
}
