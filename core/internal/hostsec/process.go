package hostsec

// ---------------------------------------------------------------------------
// Feature 6: Process Anomaly Detection
//
// Detection:   periodic /proc walk building a lightweight process
//              inventory (PID, executable path, parent PID, UID, command
//              name, and -- best-effort -- outbound TCP connections via
//              /proc/net/tcp + per-process fd/socket-inode matching).
// Evidence:    the specific PID/exe/parent-child pairing/new-process-count
//              that triggered.
// Risk:        database.IncidentSuspiciousProcess (see risk.BaseSeverity).
//              MEDIUM/HIGH tier deliberately: this is periodic-snapshot
//              userspace detection, not a reliable exec-time monitor (see
//              below), so it is scored lower than the Phase 1 host
//              signatures despite being conceptually similar.
// Correlation: every finding's Details carries any discovered outbound
//              remote addresses, which internal/detection's
//              ReportHostFinding forwards to a small correlator (feature
//              7, see detection/correlation_hostsec.go) that combines it
//              with recent FIM/Binary-Integrity findings and Threat
//              Intelligence to raise HIGH_CONFIDENCE_COMPROMISE.
// Response:    alert-only (SourceIP=HostLocalIP; see fim.go doc comment).
// False positives: deliberately narrow triggers -- an exe unlinked from
//              disk while still running, a process executing from a
//              world-writable/temp directory, a shell/interpreter
//              spawned directly by a network-facing service, or an
//              outright abnormal process-creation burst. Ordinary
//              process churn (cron jobs, package manager runs, normal
//              shell usage) does not match any of these narrow patterns.
//              Each distinct (pid, reason) fact is reported once and its
//              baseline row is cleaned up once that PID exits, so the
//              SAME still-running anomalous process is never re-reported
//              every scan tick, while a genuinely new occurrence (even
//              with a recycled PID) fires again.
//
// BEST-EFFORT DETECTION: this entire feature is explicitly best-effort
// per Architectural Rule #3 (no eBPF/kernel modules). VANGUARD can only
// see a point-in-time /proc snapshot on each scan tick -- a short-lived
// process that starts and exits entirely between two ticks is invisible,
// and there is no exec-time hooking, process ancestry history, or
// syscall visibility of any kind. This is a coarse periodic heuristic,
// not a process execution monitor. It deliberately does NOT duplicate
// PrivEsc's own "unexpected root process" best-effort check (see
// database.IncidentPrivilegeEscalation's doc comment) -- that remains
// PrivEsc's exclusive signal, to avoid two detectors raising overlapping
// findings for the same underlying /proc evidence.
// ---------------------------------------------------------------------------

import (
	"bufio"
	"context"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"vanguard/core/internal/database"
	"vanguard/core/internal/thresholds"
)

// ProcessInfo is one process's inventory entry for a single scan tick.
type ProcessInfo struct {
	PID     int
	PPID    int
	UID     string
	Comm    string // short process name, e.g. "bash"
	Exe     string // resolved /proc/<pid>/exe target (may be "" if unreadable)
	Deleted bool   // exe was unlinked from disk while this process is still running

	// RemoteAddrs are best-effort outbound ESTABLISHED TCP connections
	// ("ip:port" strings) discovered via fd-to-socket-inode matching
	// against /proc/net/tcp. May be empty even for a process that does
	// have real network activity (permission denied on /proc/<pid>/fd,
	// UDP-only traffic, or the connection isn't ESTABLISHED at scan
	// time) -- "when available", per the mega-prompt's own wording.
	RemoteAddrs []string
}

// ProcessDetector implements Process Anomaly Detection.
type ProcessDetector struct {
	db       *database.DB
	reporter Reporter

	mu       sync.Mutex
	lastPIDs map[int]bool // previous scan's live-PID set, for burst detection only (never persisted -- PIDs are not meaningful across a VANGUARD restart)
}

// NewProcessDetector constructs a Process Anomaly Detector.
func NewProcessDetector(db *database.DB, reporter Reporter) *ProcessDetector {
	return &ProcessDetector{db: db, reporter: reporter}
}

// Scan performs one full pass: build the process inventory, then evaluate
// every sub-heuristic against it.
func (d *ProcessDetector) Scan(ctx context.Context) {
	first, err := isFirstScan(d.db, database.BaselineProcess)
	if err != nil {
		logf("process", "failed to check first-scan marker: %v", err)
		return
	}

	procs := d.readProcessInventory()
	if ctx.Err() != nil {
		return
	}
	d.evaluate(procs, first)

	if first {
		if err := markSeeded(d.db, database.BaselineProcess); err != nil {
			logf("process", "failed to mark category seeded: %v", err)
		}
	}
}

// evaluate fans out to every sub-heuristic. Split out from Scan so tests
// can exercise the detection logic against a synthetic []ProcessInfo
// without needing a real /proc filesystem.
func (d *ProcessDetector) evaluate(procs []ProcessInfo, firstScan bool) {
	d.detectDeletedExe(procs, firstScan)
	d.detectUnusualDir(procs, firstScan)
	d.detectSuspiciousParentChild(procs, firstScan)
	d.detectCreationBurst(procs, firstScan)
	d.cleanupExitedPIDs(procs)
}

// detectDeletedExe flags any process whose executable has been unlinked
// from disk while still running (readlink("/proc/<pid>/exe") gets a
// " (deleted)" suffix appended by the kernel) -- classic fileless-
// malware / self-deleting-payload evasion.
func (d *ProcessDetector) detectDeletedExe(procs []ProcessInfo, firstScan bool) {
	for _, p := range procs {
		if !p.Deleted {
			continue
		}
		d.reportOncePerPID(p, "deleted_exe_running", true,
			"process executing from a binary already unlinked from disk (fileless-malware / anti-forensics indicator)",
			firstScan)
	}
}

// detectUnusualDir flags any process whose executable lives under a
// world-writable/temp directory (thresholds.WritableScanRoots) -- the
// same classic drop-and-execute location the SUID monitor watches.
func (d *ProcessDetector) detectUnusualDir(procs []ProcessInfo, firstScan bool) {
	for _, p := range procs {
		if p.Exe == "" {
			continue
		}
		for _, root := range thresholds.WritableScanRoots {
			if strings.HasPrefix(p.Exe, root+"/") || p.Exe == root {
				d.reportOncePerPID(p, "process_from_unusual_directory", true,
					"executable running from a world-writable/temp directory ("+root+")",
					firstScan)
				break
			}
		}
	}
}

// detectSuspiciousParentChild flags a shell/interpreter (thresholds.
// ShellAndInterpreterNames) spawned directly by a network-facing service
// (thresholds.NetworkFacingServiceNames) -- a classic post-RCE reverse
// shell / webshell-spawns-a-shell pattern.
func (d *ProcessDetector) detectSuspiciousParentChild(procs []ProcessInfo, firstScan bool) {
	byPID := make(map[int]ProcessInfo, len(procs))
	for _, p := range procs {
		byPID[p.PID] = p
	}
	for _, p := range procs {
		parent, ok := byPID[p.PPID]
		if !ok {
			continue // parent not present in this snapshot (already exited, or PID 1's parent 0)
		}
		if !isNetworkFacingService(parent.Comm) || !isShellOrInterpreter(p.Comm) {
			continue
		}
		d.reportOncePerPID(p, "suspicious_parent_child", true,
			fmt.Sprintf("shell/interpreter %q spawned directly by network-facing service %q", p.Comm, parent.Comm),
			firstScan)
	}
}

// detectCreationBurst compares this scan's live-PID set against the
// previous one and flags an abnormal number of brand-new PIDs within a
// single ProcessScanInterval tick. This is the one heuristic that is
// deliberately NOT gated by firstScan alone -- it additionally requires a
// previous snapshot to diff against (d.lastPIDs != nil), since the very
// first scan ever has no prior baseline to compare to at all.
func (d *ProcessDetector) detectCreationBurst(procs []ProcessInfo, firstScan bool) {
	current := make(map[int]bool, len(procs))
	for _, p := range procs {
		current[p.PID] = true
	}

	d.mu.Lock()
	prev := d.lastPIDs
	d.lastPIDs = current
	d.mu.Unlock()

	if firstScan || prev == nil {
		return
	}

	newCount := 0
	for pid := range current {
		if !prev[pid] {
			newCount++
		}
	}
	if newCount <= thresholds.ProcessCreationBurstThreshold {
		return
	}

	d.reporter.ReportHostFinding(Finding{
		Type:           database.IncidentSuspiciousProcess,
		Change:         "process_creation_burst",
		Subject:        fmt.Sprintf("%d new processes in one scan interval", newCount),
		BestEffort:     true,
		EscalationNote: "abnormal process-creation burst",
		Details: map[string]any{
			"new_process_count": newCount,
			"threshold":         thresholds.ProcessCreationBurstThreshold,
			"detection_confidence": "BEST-EFFORT: point-in-time /proc snapshot comparison only, " +
				"no eBPF/kernel visibility per architectural constraint",
		},
	})
}

// reportOncePerPID reports a Finding at most once per (pid, reason) pair
// -- see the package doc comment above for why PID (not just the
// underlying fact) is part of the dedupe key.
func (d *ProcessDetector) reportOncePerPID(p ProcessInfo, reason string, critical bool, note string, firstScan bool) {
	key := fmt.Sprintf("pid:%d:%s", p.PID, reason)
	_, err := d.db.GetHostBaseline(database.BaselineProcess, key)
	if err == nil {
		return // already reported for this still-running PID
	}
	if err != database.ErrNotFound {
		logf("process", "baseline lookup failed for %s: %v", key, err)
		return
	}
	if !firstScan {
		d.reporter.ReportHostFinding(Finding{
			Type:           database.IncidentSuspiciousProcess,
			Change:         reason,
			Subject:        nonEmptyStr(p.Exe, p.Comm),
			Critical:       critical,
			BestEffort:     true,
			EscalationNote: note,
			RemoteAddrs:    p.RemoteAddrs,
			Details: map[string]any{
				"pid": p.PID, "ppid": p.PPID, "uid": p.UID, "comm": p.Comm, "exe": p.Exe,
				"remote_addrs": p.RemoteAddrs,
				"detection_confidence": "BEST-EFFORT: point-in-time /proc snapshot only, " +
					"no eBPF/kernel visibility per architectural constraint",
			},
		})
	}
	if err := d.db.UpsertHostBaseline(database.BaselineProcess, key, `{"seen":true}`); err != nil {
		logf("process", "failed to save baseline for %s: %v", key, err)
	}
}

// cleanupExitedPIDs removes every BaselineProcess "pid:<n>:..." row whose
// PID is no longer present in the current live snapshot, so (a) memory
// doesn't grow unbounded over the host's uptime and (b) a PID number
// reused much later by a genuinely new, unrelated process is correctly
// treated as brand new rather than silently suppressed by stale state.
func (d *ProcessDetector) cleanupExitedPIDs(procs []ProcessInfo) {
	live := make(map[int]bool, len(procs))
	for _, p := range procs {
		live[p.PID] = true
	}
	rows, err := d.db.ListHostBaseline(database.BaselineProcess)
	if err != nil {
		logf("process", "failed to list baseline for cleanup: %v", err)
		return
	}
	for _, row := range rows {
		rest, ok := strings.CutPrefix(row.Key, "pid:")
		if !ok {
			continue // e.g. the reserved __seeded__ marker row
		}
		pidStr, _, _ := strings.Cut(rest, ":")
		pid, err := strconv.Atoi(pidStr)
		if err != nil {
			continue
		}
		if live[pid] {
			continue
		}
		if err := d.db.DeleteHostBaseline(database.BaselineProcess, row.Key); err != nil {
			logf("process", "failed to delete stale baseline for %s: %v", row.Key, err)
		}
	}
}

func isNetworkFacingService(comm string) bool {
	return containsExact(thresholds.NetworkFacingServiceNames, comm)
}

func isShellOrInterpreter(comm string) bool {
	return containsExact(thresholds.ShellAndInterpreterNames, comm)
}

func containsExact(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

func nonEmptyStr(s, fallback string) string {
	if s != "" {
		return s
	}
	return fallback
}

// ---------------------------------------------------------------------------
// /proc inventory reading (real filesystem only -- not unit tested, same
// limitation as privesc.go's root-process scan: /proc cannot be
// meaningfully faked under a tmpdir root for a unit test).
// ---------------------------------------------------------------------------

// readProcessInventory walks /proc, building one ProcessInfo per live
// PID directory, including a best-effort outbound-connection lookup.
func (d *ProcessDetector) readProcessInventory() []ProcessInfo {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		logf("process", "process inventory scan unavailable: %v", err)
		return nil
	}

	tcpConns := readProcNetTCP("/proc/net/tcp")

	var procs []ProcessInfo
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue // not a PID directory
		}
		procs = append(procs, readOneProcess(pid, tcpConns))
	}
	return procs
}

func readOneProcess(pid int, tcpConns map[uint64]procNetConn) ProcessInfo {
	p := ProcessInfo{PID: pid}
	base := "/proc/" + strconv.Itoa(pid)

	if b, err := os.ReadFile(base + "/comm"); err == nil {
		p.Comm = strings.TrimSpace(string(b))
	}

	if f, err := os.Open(base + "/status"); err == nil {
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			line := scanner.Text()
			switch {
			case strings.HasPrefix(line, "Uid:"):
				if fields := strings.Fields(line); len(fields) >= 2 {
					p.UID = fields[1]
				}
			case strings.HasPrefix(line, "PPid:"):
				if fields := strings.Fields(line); len(fields) >= 2 {
					p.PPID, _ = strconv.Atoi(fields[1])
				}
			}
		}
		f.Close()
	}

	if exe, err := os.Readlink(base + "/exe"); err == nil {
		if strings.HasSuffix(exe, " (deleted)") {
			p.Deleted = true
			p.Exe = strings.TrimSuffix(exe, " (deleted)")
		} else {
			p.Exe = exe
		}
	}

	if len(tcpConns) > 0 {
		p.RemoteAddrs = matchProcessSockets(base, tcpConns)
	}

	return p
}

// procNetConn is one parsed row of /proc/net/tcp.
type procNetConn struct {
	remoteAddr string // "ip:port"
	state      int    // TCP state, e.g. 0x01 = ESTABLISHED
}

const tcpStateEstablished = 0x01

// readProcNetTCP parses /proc/net/tcp into inode -> connection. A missing
// or unreadable file yields an empty map (never an error the caller must
// handle), since network association is explicitly "when available".
func readProcNetTCP(path string) map[uint64]procNetConn {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	out := make(map[uint64]procNetConn)
	scanner := bufio.NewScanner(f)
	first := true
	for scanner.Scan() {
		if first {
			first = false
			continue // header row
		}
		remoteAddr, state, inode, err := parseProcNetTCPLine(scanner.Text())
		if err != nil {
			continue
		}
		out[inode] = procNetConn{remoteAddr: remoteAddr, state: state}
	}
	return out
}

// parseProcNetTCPLine parses a single non-header /proc/net/tcp row into
// its remote address ("ip:port"), TCP state, and socket inode. Pure
// function (no filesystem access), so it is fully unit-testable against
// captured sample lines without needing a real /proc.
func parseProcNetTCPLine(line string) (remoteAddr string, state int, inode uint64, err error) {
	fields := strings.Fields(line)
	// Expected columns: sl local_address rem_address st tx_queue:rx_queue
	// tr:tm->when retrnsmt uid timeout inode ...
	if len(fields) < 10 {
		return "", 0, 0, fmt.Errorf("unexpected /proc/net/tcp line: %q", line)
	}
	ip, port, err := decodeHexAddr(fields[2])
	if err != nil {
		return "", 0, 0, err
	}
	st, err := strconv.ParseInt(fields[3], 16, 32)
	if err != nil {
		return "", 0, 0, err
	}
	ino, err := strconv.ParseUint(fields[9], 10, 64)
	if err != nil {
		return "", 0, 0, err
	}
	return fmt.Sprintf("%s:%d", ip, port), int(st), ino, nil
}

// decodeHexAddr decodes a /proc/net/tcp "IP:PORT" field (e.g.
// "FEA9FEA9:0050") into a dotted-quad IP string and decimal port. The
// four IP bytes are stored in the kernel word's native (little-endian on
// every VANGUARD-supported platform) byte order, so they must be
// reversed to produce the standard network-order dotted-quad.
func decodeHexAddr(field string) (ip string, port int, err error) {
	parts := strings.SplitN(field, ":", 2)
	if len(parts) != 2 || len(parts[0]) != 8 {
		return "", 0, fmt.Errorf("unexpected address field: %q", field)
	}
	b, err := hex.DecodeString(parts[0])
	if err != nil {
		return "", 0, err
	}
	portVal, err := strconv.ParseInt(parts[1], 16, 32)
	if err != nil {
		return "", 0, err
	}
	return fmt.Sprintf("%d.%d.%d.%d", b[3], b[2], b[1], b[0]), int(portVal), nil
}

// matchProcessSockets lists /proc/<pid>/fd, resolves each "socket:[N]"
// symlink to its inode, and returns "ip:port" for every ESTABLISHED TCP
// connection found in tcpConns. Best-effort: permission errors (a
// process owned by another user) are silently skipped, never logged as
// warnings, since this is an expected, extremely common case.
func matchProcessSockets(procBase string, tcpConns map[uint64]procNetConn) []string {
	entries, err := os.ReadDir(procBase + "/fd")
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range entries {
		target, err := os.Readlink(filepath.Join(procBase, "fd", e.Name()))
		if err != nil {
			continue
		}
		inode, ok := parseSocketInode(target)
		if !ok {
			continue
		}
		conn, ok := tcpConns[inode]
		if !ok || conn.state != tcpStateEstablished {
			continue
		}
		out = append(out, conn.remoteAddr)
	}
	return out
}

// parseSocketInode extracts the inode number from a "socket:[12345]"
// fd-symlink target. Pure function, unit-testable.
func parseSocketInode(target string) (uint64, bool) {
	if !strings.HasPrefix(target, "socket:[") || !strings.HasSuffix(target, "]") {
		return 0, false
	}
	inner := target[len("socket:[") : len(target)-1]
	n, err := strconv.ParseUint(inner, 10, 64)
	if err != nil {
		return 0, false
	}
	return n, true
}
