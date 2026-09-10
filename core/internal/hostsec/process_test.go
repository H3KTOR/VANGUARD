package hostsec

import (
	"testing"

	"vanguard/core/internal/database"
	"vanguard/core/internal/thresholds"
)

func TestProcessDetector_FirstScanIsSilent(t *testing.T) {
	db := testDB(t)
	rep := &fakeReporter{}
	d := NewProcessDetector(db, rep)

	first, err := isFirstScan(db, database.BaselineProcess)
	if err != nil || !first {
		t.Fatalf("expected first scan, err=%v first=%v", err, first)
	}

	procs := []ProcessInfo{
		{PID: 1, PPID: 0, Comm: "systemd", Exe: "/sbin/init"},
		{PID: 100, PPID: 1, Comm: "bash", Exe: "/tmp/malicious-but-preexisting"}, // in a writable dir, but this is the FIRST scan
	}
	d.evaluate(procs, true)
	if err := markSeeded(db, database.BaselineProcess); err != nil {
		t.Fatalf("markSeeded: %v", err)
	}

	if len(rep.findings) != 0 {
		t.Fatalf("expected 0 findings on cold-start seeding scan, got %d: %+v", len(rep.findings), rep.findings)
	}
}

func TestProcessDetector_DetectsDeletedExeRunning(t *testing.T) {
	db := testDB(t)
	rep := &fakeReporter{}
	d := NewProcessDetector(db, rep)

	seed := []ProcessInfo{{PID: 1, Comm: "systemd", Exe: "/sbin/init"}}
	d.evaluate(seed, true)
	markSeeded(db, database.BaselineProcess)

	rep.reset()
	procs := []ProcessInfo{
		{PID: 1, Comm: "systemd", Exe: "/sbin/init"},
		{PID: 500, PPID: 1, Comm: "backdoor", Exe: "/tmp/backdoor", Deleted: true},
	}
	d.evaluate(procs, false)

	got := rep.byChange("deleted_exe_running")
	if len(got) != 1 {
		t.Fatalf("expected exactly 1 'deleted_exe_running' finding, got %d: %+v", len(got), rep.findings)
	}
	if got[0].Type != database.IncidentSuspiciousProcess {
		t.Errorf("expected type %s, got %s", database.IncidentSuspiciousProcess, got[0].Type)
	}
	if !got[0].Critical {
		t.Errorf("expected Critical=true for a deleted-but-running executable")
	}

	// Re-scanning with the SAME still-running PID must not re-fire.
	rep.reset()
	d.evaluate(procs, false)
	if len(rep.findings) != 0 {
		t.Fatalf("expected 0 findings when the same anomalous PID is still running, got %d: %+v", len(rep.findings), rep.findings)
	}
}

func TestProcessDetector_DetectsProcessFromWritableDir(t *testing.T) {
	db := testDB(t)
	rep := &fakeReporter{}
	d := NewProcessDetector(db, rep)
	d.evaluate(nil, true)
	markSeeded(db, database.BaselineProcess)

	rep.reset()
	procs := []ProcessInfo{
		{PID: 42, Comm: "payload", Exe: "/tmp/payload"},
	}
	d.evaluate(procs, false)

	got := rep.byChange("process_from_unusual_directory")
	if len(got) != 1 {
		t.Fatalf("expected exactly 1 'process_from_unusual_directory' finding, got %d: %+v", len(got), rep.findings)
	}
}

func TestProcessDetector_DetectsSuspiciousParentChild(t *testing.T) {
	db := testDB(t)
	rep := &fakeReporter{}
	d := NewProcessDetector(db, rep)
	d.evaluate(nil, true)
	markSeeded(db, database.BaselineProcess)

	rep.reset()
	procs := []ProcessInfo{
		{PID: 10, Comm: "nginx", Exe: "/usr/sbin/nginx"},
		{PID: 11, PPID: 10, Comm: "bash", Exe: "/bin/bash"}, // nginx spawning a shell -- classic post-RCE
	}
	d.evaluate(procs, false)

	got := rep.byChange("suspicious_parent_child")
	if len(got) != 1 {
		t.Fatalf("expected exactly 1 'suspicious_parent_child' finding, got %d: %+v", len(got), rep.findings)
	}
}

func TestProcessDetector_NormalParentChildNotFlagged(t *testing.T) {
	db := testDB(t)
	rep := &fakeReporter{}
	d := NewProcessDetector(db, rep)
	d.evaluate(nil, true)
	markSeeded(db, database.BaselineProcess)

	rep.reset()
	procs := []ProcessInfo{
		{PID: 1, Comm: "systemd", Exe: "/sbin/init"},
		{PID: 10, PPID: 1, Comm: "nginx", Exe: "/usr/sbin/nginx"},
		{PID: 20, PPID: 10, Comm: "nginx", Exe: "/usr/sbin/nginx"}, // nginx worker forked from nginx master: normal
	}
	d.evaluate(procs, false)

	if len(rep.findings) != 0 {
		t.Fatalf("expected 0 findings for a normal nginx worker fork, got %d: %+v", len(rep.findings), rep.findings)
	}
}

func TestProcessDetector_DetectsCreationBurst(t *testing.T) {
	db := testDB(t)
	rep := &fakeReporter{}
	d := NewProcessDetector(db, rep)

	// First scan establishes the baseline PID set (10 processes).
	var baseline []ProcessInfo
	for i := 1; i <= 10; i++ {
		baseline = append(baseline, ProcessInfo{PID: i, Comm: "worker", Exe: "/usr/bin/worker"})
	}
	d.evaluate(baseline, true)
	markSeeded(db, database.BaselineProcess)

	// Second scan: same 10 PIDs plus a burst of new ones.
	rep.reset()
	procs := append([]ProcessInfo{}, baseline...)
	for i := 1000; i < 1000+thresholds.ProcessCreationBurstThreshold+5; i++ {
		procs = append(procs, ProcessInfo{PID: i, Comm: "worker", Exe: "/usr/bin/worker"})
	}
	d.evaluate(procs, false)

	got := rep.byChange("process_creation_burst")
	if len(got) != 1 {
		t.Fatalf("expected exactly 1 'process_creation_burst' finding, got %d: %+v", len(got), rep.findings)
	}
}

func TestProcessDetector_NoBurstBelowThreshold(t *testing.T) {
	db := testDB(t)
	rep := &fakeReporter{}
	d := NewProcessDetector(db, rep)

	baseline := []ProcessInfo{{PID: 1, Comm: "init"}}
	d.evaluate(baseline, true)
	markSeeded(db, database.BaselineProcess)

	rep.reset()
	procs := []ProcessInfo{
		{PID: 1, Comm: "init"},
		{PID: 2, Comm: "worker"}, // just one new process: not a burst
	}
	d.evaluate(procs, false)

	if got := rep.byChange("process_creation_burst"); len(got) != 0 {
		t.Fatalf("expected 0 burst findings for a single new process, got %d: %+v", len(got), got)
	}
}

func TestProcessDetector_CleansUpExitedPIDBaseline(t *testing.T) {
	db := testDB(t)
	rep := &fakeReporter{}
	d := NewProcessDetector(db, rep)
	d.evaluate(nil, true)
	markSeeded(db, database.BaselineProcess)

	rep.reset()
	procs := []ProcessInfo{{PID: 999, Comm: "payload", Exe: "/tmp/payload"}}
	d.evaluate(procs, false)
	if got := rep.byChange("process_from_unusual_directory"); len(got) != 1 {
		t.Fatalf("expected the anomalous process to be reported once, got %d", len(got))
	}

	// The process exits (no longer in the live snapshot).
	rep.reset()
	d.evaluate(nil, false)
	if len(rep.findings) != 0 {
		t.Fatalf("expected 0 findings on an empty snapshot, got %d", len(rep.findings))
	}

	// A DIFFERENT process later reuses PID 999 -- must be treated as a
	// brand-new occurrence, not suppressed by stale baseline state.
	rep.reset()
	d.evaluate(procs, false)
	if got := rep.byChange("process_from_unusual_directory"); len(got) != 1 {
		t.Fatalf("expected the recycled PID to be re-reported as new, got %d findings: %+v", len(got), rep.findings)
	}
}

func TestProcessDetector_DeletedExeTakesPrecedenceOverUnusualDir(t *testing.T) {
	// A process that is BOTH deleted AND in a writable dir is reported
	// under both reasons (different (pid,reason) keys), not deduped away
	// -- each is independently valuable evidence.
	db := testDB(t)
	rep := &fakeReporter{}
	d := NewProcessDetector(db, rep)
	d.evaluate(nil, true)
	markSeeded(db, database.BaselineProcess)

	rep.reset()
	procs := []ProcessInfo{
		{PID: 7, Comm: "x", Exe: "/tmp/x", Deleted: true},
	}
	d.evaluate(procs, false)

	if got := rep.byChange("deleted_exe_running"); len(got) != 1 {
		t.Errorf("expected 1 'deleted_exe_running' finding, got %d", len(got))
	}
	if got := rep.byChange("process_from_unusual_directory"); len(got) != 1 {
		t.Errorf("expected 1 'process_from_unusual_directory' finding, got %d", len(got))
	}
}

// ---------------------------------------------------------------------------
// Pure-function /proc/net/tcp parsing tests (no real /proc needed).
// ---------------------------------------------------------------------------

func TestParseProcNetTCPLine(t *testing.T) {
	// A real /proc/net/tcp data row (fields: sl local rem st tx:rx tr:tm
	// retrnsmt uid timeout inode ...). Remote 0100007F:1F90 = 127.0.0.1:8080,
	// state 01 = ESTABLISHED, inode 12345.
	line := "   1: 0100007F:9C40 0100007F:1F90 01 00000000:00000000 00:00000000 00000000  1000        0 12345 1 0000000000000000 20 4 30 10 -1"
	remoteAddr, state, inode, err := parseProcNetTCPLine(line)
	if err != nil {
		t.Fatalf("parseProcNetTCPLine failed: %v", err)
	}
	if remoteAddr != "127.0.0.1:8080" {
		t.Errorf("expected remoteAddr=127.0.0.1:8080, got %s", remoteAddr)
	}
	if state != tcpStateEstablished {
		t.Errorf("expected state=ESTABLISHED(1), got %d", state)
	}
	if inode != 12345 {
		t.Errorf("expected inode=12345, got %d", inode)
	}
}

func TestParseProcNetTCPLine_MalformedLineReturnsError(t *testing.T) {
	if _, _, _, err := parseProcNetTCPLine("garbage"); err == nil {
		t.Fatalf("expected an error for a malformed line, got nil")
	}
}

func TestDecodeHexAddr(t *testing.T) {
	// 0100007F is 127.0.0.1 in little-endian hex; 1F90 is 8080 decimal.
	ip, port, err := decodeHexAddr("0100007F:1F90")
	if err != nil {
		t.Fatalf("decodeHexAddr failed: %v", err)
	}
	if ip != "127.0.0.1" || port != 8080 {
		t.Errorf("expected 127.0.0.1:8080, got %s:%d", ip, port)
	}
}

func TestParseSocketInode(t *testing.T) {
	inode, ok := parseSocketInode("socket:[98765]")
	if !ok || inode != 98765 {
		t.Errorf("expected inode=98765 ok=true, got inode=%d ok=%v", inode, ok)
	}

	if _, ok := parseSocketInode("/dev/null"); ok {
		t.Errorf("expected ok=false for a non-socket fd target")
	}
}
