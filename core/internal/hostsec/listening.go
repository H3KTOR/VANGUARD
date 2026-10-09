package hostsec

// ---------------------------------------------------------------------------
// Phase 4, Detector C: Listening Service Drift
//
// Detection:   /proc/net/{tcp,tcp6,udp,udp6} is parsed (no netstat/ss, no
//              external binary) for LISTENING sockets only -- TCP state
//              LISTEN (0x0A) and unconnected UDP sockets (state 0x07,
//              zero remote address). Established connections and other
//              transient states are never inventoried.
// Identity normalization:
//              a listener is identified by (protocol, bind address,
//              port) rendered as "<proto>:<addr>:<port>":
//                tcp:0.0.0.0:22      tcp6:[::]:22      udp:127.0.0.1:53
//              The protocol label carries the address family (tcp vs
//              tcp6, udp vs udp6), and addresses are canonical
//              netip.Addr strings, so 0.0.0.0:22 and [::]:22 are
//              deliberately DISTINCT listeners (an IPv4-wildcard and an
//              IPv6-wildcard socket are different exposure). IPv4-mapped
//              IPv6 addresses keep their ::ffff: form.
// Owner:       the owning process NAME (never the command line, which
//              may contain secrets) is resolved best-effort by matching
//              socket inodes against /proc/<pid>/fd, bounded to
//              thresholds.MaxProcPIDsScanned processes. When it cannot
//              be resolved safely it is recorded as unknown -- an
//              identity is never invented.
// Baseline:    one atomic JSON snapshot row (BaselineListeningService,
//              key "snapshot"). The first scan establishes it silently;
//              for GracePeriod after process start further changes are
//              absorbed silently as well (slow-starting services).
// Drift:       new listener, removed listener, protocol change,
//              bind-address change, port change, process-owner change
//              (only when both owners are known).
// Allowlist:   Expected/Ignored listeners are matched explicitly
//              (protocol, address, port, optional process name) and are
//              excluded from the inventory in BOTH directions. Nothing
//              becomes trusted merely because it was seen before.
// Fail-safe:   if /proc cannot be read or parsed the scan aborts with a
//              log line; the previous baseline is untouched (an empty
//              inventory is never fabricated).
// ---------------------------------------------------------------------------

import (
	"bufio"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"vanguard/core/internal/database"
	"vanguard/core/internal/thresholds"
)

const listeningSnapshotKey = "snapshot"

// ListeningConfig controls the Listening Service Drift detector.
type ListeningConfig struct {
	// Expected are listeners that are explicitly allowed (never reported).
	Expected []thresholds.ExpectedListener
	// Ignored are listeners excluded from inspection entirely.
	Ignored []thresholds.ExpectedListener
	// GracePeriod is the window after process start during which changes
	// are absorbed silently. <0 selects the default; 0 disables it.
	GracePeriod time.Duration
	// ResolveProcesses enables best-effort owner resolution.
	ResolveProcesses bool
}

// DefaultListeningConfig returns the out-of-the-box configuration.
func DefaultListeningConfig() ListeningConfig {
	return ListeningConfig{
		Expected:         thresholds.DefaultExpectedListeners,
		GracePeriod:      thresholds.ListeningServiceGracePeriod,
		ResolveProcesses: true,
	}
}

// Listener is one normalized listening socket (and the persisted shape).
type Listener struct {
	Proto        string `json:"proto"`   // tcp, tcp6, udp, udp6
	Addr         string `json:"addr"`    // canonical bind address
	Port         int    `json:"port"`    // 1..65535
	Family       string `json:"family"`  // ipv4 | ipv6
	Process      string `json:"process"` // empty when unknown
	ProcessKnown bool   `json:"process_known"`
}

// Key is the stable normalized identity ("tcp6:[::]:22").
func (l Listener) Key() string {
	if l.Family == "ipv6" {
		return l.Proto + ":[" + l.Addr + "]:" + strconv.Itoa(l.Port)
	}
	return l.Proto + ":" + l.Addr + ":" + strconv.Itoa(l.Port)
}

// Exposure classifies the bind address scope.
func (l Listener) Exposure() string {
	a, err := netip.ParseAddr(l.Addr)
	if err != nil {
		return "specific"
	}
	switch {
	case a.IsLoopback():
		return "loopback"
	case a.IsUnspecified():
		return "wildcard"
	default:
		return "specific"
	}
}

type listeningSnapshot struct {
	Listeners map[string]Listener `json:"listeners"`
	UpdatedAt time.Time           `json:"updated_at"`
}

// ListenerChange is one detected drift between two inventories.
type ListenerChange struct {
	Kind string // new_listener, removed_listener, protocol_changed, bind_address_changed, port_changed, process_changed
	Prev *Listener
	Curr *Listener
}

// ListeningDetector implements Listening Service Drift.
type ListeningDetector struct {
	db       *database.DB
	reporter Reporter
	cfg      ListeningConfig

	procRoot  string // "/proc"; overridden by tests
	rep       scanReporter
	startedAt time.Time
}

// NewListeningDetector constructs the detector.
func NewListeningDetector(db *database.DB, reporter Reporter, cfg ListeningConfig) *ListeningDetector {
	if cfg.GracePeriod < 0 {
		cfg.GracePeriod = thresholds.ListeningServiceGracePeriod
	}
	return &ListeningDetector{db: db, reporter: reporter, cfg: cfg, procRoot: "/proc", startedAt: time.Now()}
}

// WithProcRoot returns a copy reading from root instead of /proc (tests).
func (d *ListeningDetector) WithProcRoot(root string) *ListeningDetector {
	d2 := *d
	d2.procRoot = root
	return &d2
}

// Scan performs one full Listening Service Drift pass.
func (d *ListeningDetector) Scan(ctx context.Context) {
	socks, inodes, err := d.readListeners(ctx)
	if err != nil {
		logf("listening", "scan failure: %v (baseline preserved)", err)
		d.rep.fail("could not read /proc/net: " + err.Error())
		return
	}

	if d.cfg.ResolveProcesses && len(socks) > 0 {
		d.resolveOwners(ctx, socks, inodes)
	}

	curr := make(map[string]Listener, len(socks))
	for _, l := range socks {
		if matchesListener(d.cfg.Ignored, l) || matchesListener(d.cfg.Expected, l) {
			continue
		}
		curr[l.Key()] = l
	}

	var prev listeningSnapshot
	have, err := loadSnapshot(d.db, database.BaselineListeningService, listeningSnapshotKey, &prev)
	if err != nil {
		logf("listening", "baseline unavailable: %v (not replacing it)", err)
		d.rep.fail("baseline store unavailable: " + err.Error())
		return
	}
	save := func() {
		snap := listeningSnapshot{Listeners: curr, UpdatedAt: time.Now().UTC()}
		if err := saveJSON(d.db, database.BaselineListeningService, listeningSnapshotKey, snap); err != nil {
			logf("listening", "failed to store baseline: %v", err)
		}
	}
	if !have {
		save()
		logf("listening", "baseline created (%d listeners)", len(curr))
		return
	}

	// An allowlist that grew since the baseline was taken must not show
	// up as "removed listeners".
	prevFiltered := make(map[string]Listener, len(prev.Listeners))
	for k, l := range prev.Listeners {
		if matchesListener(d.cfg.Ignored, l) || matchesListener(d.cfg.Expected, l) {
			continue
		}
		prevFiltered[k] = l
	}

	changes := diffListeners(prevFiltered, curr)
	if len(changes) == 0 {
		if len(curr) != len(prev.Listeners) {
			save() // allowlist-only difference: keep stored baseline tidy
		}
		return
	}
	if time.Since(d.startedAt) < d.cfg.GracePeriod {
		logf("listening", "%d change(s) absorbed into baseline during startup grace period", len(changes))
		save()
		return
	}
	for _, c := range changes {
		d.report(c, prev.UpdatedAt)
	}
	save()
	logf("listening", "baseline changed (%d change(s))", len(changes))
}

// matchesListener reports whether l matches any explicit allowlist entry.
func matchesListener(list []thresholds.ExpectedListener, l Listener) bool {
	for _, e := range list {
		if e.Port != l.Port {
			continue
		}
		if e.Protocol != "*" && e.Protocol != l.Proto {
			continue
		}
		if e.AddressPattern != "*" && e.AddressPattern != l.Addr {
			continue
		}
		if e.ProcessNameHint != "" && (!l.ProcessKnown || e.ProcessNameHint != l.Process) {
			continue
		}
		return true
	}
	return false
}

// diffListeners computes the drift between two inventories. Pure
// function: output order is deterministic (sorted by identity).
func diffListeners(prev, curr map[string]Listener) []ListenerChange {
	var added, removed []Listener
	var changes []ListenerChange
	for k, c := range curr {
		p, ok := prev[k]
		if !ok {
			added = append(added, c)
			continue
		}
		if p.ProcessKnown && c.ProcessKnown && p.Process != c.Process {
			pp, cc := p, c
			changes = append(changes, ListenerChange{Kind: "process_changed", Prev: &pp, Curr: &cc})
		}
	}
	for k, p := range prev {
		if _, ok := curr[k]; !ok {
			removed = append(removed, p)
		}
	}
	sortListeners(added)
	sortListeners(removed)

	// Pair a removal with an addition when they are plausibly the same
	// service that moved, to report one meaningful change instead of two.
	usedAdd := make(map[int]bool)
	var unpairedRemoved []Listener
	for _, r := range removed {
		paired := false
		for i, a := range added {
			if usedAdd[i] {
				continue
			}
			kind := ""
			switch {
			case a.Port == r.Port && a.Proto == r.Proto && a.Addr != r.Addr:
				kind = "bind_address_changed"
			case a.Port == r.Port && a.Addr == r.Addr && a.Proto != r.Proto && a.Family == r.Family:
				kind = "protocol_changed"
			case a.Port != r.Port && a.Proto == r.Proto && a.Addr == r.Addr &&
				r.ProcessKnown && a.ProcessKnown && r.Process == a.Process:
				kind = "port_changed"
			}
			if kind == "" {
				continue
			}
			usedAdd[i] = true
			rr, aa := r, a
			changes = append(changes, ListenerChange{Kind: kind, Prev: &rr, Curr: &aa})
			paired = true
			break
		}
		if !paired {
			unpairedRemoved = append(unpairedRemoved, r)
		}
	}
	for i, a := range added {
		if !usedAdd[i] {
			aa := a
			changes = append(changes, ListenerChange{Kind: "new_listener", Curr: &aa})
		}
	}
	for _, r := range unpairedRemoved {
		rr := r
		changes = append(changes, ListenerChange{Kind: "removed_listener", Prev: &rr})
	}
	sort.SliceStable(changes, func(i, j int) bool {
		return changeKey(changes[i]) < changeKey(changes[j])
	})
	return changes
}

func changeKey(c ListenerChange) string {
	l := c.Curr
	if l == nil {
		l = c.Prev
	}
	return l.Key() + "|" + c.Kind
}

func sortListeners(ls []Listener) {
	sort.Slice(ls, func(i, j int) bool { return ls[i].Key() < ls[j].Key() })
}

// listenerRisk converts exposure context into a graded risk adjustment.
// Pure function. Rationale (documented in README): loopback-only is
// mitigated, wildcard binds and privileged ports aggravate, an unknown
// owner is mildly aggravating, removals are informational.
func listenerRisk(c ListenerChange) (adjust int, note string) {
	l := c.Curr
	if l == nil {
		return -20, "listener removed (informational)"
	}
	var parts []string
	switch l.Exposure() {
	case "loopback":
		adjust -= 15
		parts = append(parts, "loopback-only")
	case "wildcard":
		adjust += 10
		parts = append(parts, "bound to all interfaces")
	default:
		adjust += 5
		parts = append(parts, "bound to a specific non-loopback address")
	}
	if l.Port <= thresholds.PrivilegedPortThreshold && l.Exposure() != "loopback" {
		adjust += 10
		parts = append(parts, "privileged port")
	}
	if !l.ProcessKnown {
		adjust += 5
		parts = append(parts, "owning process unresolved")
	}
	if c.Kind == "process_changed" {
		adjust += 5
		parts = append(parts, "owning process changed")
	}
	return adjust, strings.Join(parts, ", ")
}

func (d *ListeningDetector) report(c ListenerChange, baselineAt time.Time) {
	adjust, note := listenerRisk(c)
	cur := c.Curr
	if cur == nil {
		cur = c.Prev
	}
	details := map[string]any{
		"change":           c.Kind,
		"protocol":         cur.Proto,
		"local_address":    cur.Addr,
		"port":             cur.Port,
		"address_family":   cur.Family,
		"exposure":         cur.Exposure(),
		"process":          cur.Process,
		"process_known":    cur.ProcessKnown,
		"newly_observed":   c.Kind == "new_listener",
		"risk_context":     note,
		"baseline_age_sec": ageSeconds(baselineAt),
		"detected_at":      time.Now().UTC(),
	}
	if c.Prev != nil {
		details["previous_state"] = c.Prev
	}
	if c.Curr != nil {
		details["current_state"] = c.Curr
	}
	d.reporter.ReportHostFinding(Finding{
		Type:       database.IncidentListeningServiceDrift,
		Change:     c.Kind,
		Subject:    "listening_service_drift:" + c.Kind + ":" + cur.Key() + ":" + cur.Process,
		RiskAdjust: adjust,
		Details:    details,
	})
}

// ---------------------------------------------------------------------------
// /proc parsing
// ---------------------------------------------------------------------------

type procSocket struct {
	Listener
	inode uint64
}

// readListeners parses the four /proc/net tables. At least one table
// must be readable and parse cleanly; a table that exists but is
// unreadable or entirely malformed aborts the scan (fail-safe).
func (d *ListeningDetector) readListeners(ctx context.Context) ([]Listener, map[string][]uint64, error) {
	tables := []struct{ name, proto string }{
		{"tcp", "tcp"}, {"tcp6", "tcp6"}, {"udp", "udp"}, {"udp6", "udp6"},
	}
	var all []procSocket
	readable := 0
	for _, t := range tables {
		if ctx.Err() != nil {
			return nil, nil, ctx.Err()
		}
		f, err := os.Open(filepath.Join(d.procRoot, "net", t.name))
		if err != nil {
			if os.IsNotExist(err) {
				continue // e.g. IPv6 disabled
			}
			return nil, nil, fmt.Errorf("open /proc/net/%s: %w", t.name, err)
		}
		socks, malformed, rows, err := parseProcNetSockets(f, t.proto)
		f.Close()
		if err != nil {
			return nil, nil, fmt.Errorf("read /proc/net/%s: %w", t.name, err)
		}
		if rows > 0 && malformed == rows {
			return nil, nil, fmt.Errorf("/proc/net/%s: all %d rows malformed", t.name, rows)
		}
		if malformed > 0 {
			logf("listening", "/proc/net/%s: skipped %d malformed row(s)", t.name, malformed)
		}
		readable++
		all = append(all, socks...)
	}
	if readable == 0 {
		return nil, nil, errors.New("no /proc/net socket table is readable")
	}

	sort.Slice(all, func(i, j int) bool { return all[i].Key() < all[j].Key() })
	// Deduplicate identical identities (SO_REUSEPORT workers).
	out := make([]Listener, 0, len(all))
	inodes := make(map[string][]uint64)
	for _, s := range all {
		k := s.Key()
		if _, seen := inodes[k]; !seen {
			if len(out) >= thresholds.MaxListeningSockets {
				logf("listening", "listener limit (%d) reached, ignoring further sockets", thresholds.MaxListeningSockets)
				break
			}
			out = append(out, s.Listener)
		}
		inodes[k] = append(inodes[k], s.inode)
	}
	return out, inodes, nil
}

// parseProcNetSockets parses one /proc/net table, returning only
// LISTENING sockets plus counts of data rows and malformed rows. Pure
// (reader-based) so it is unit-testable against captured samples.
func parseProcNetSockets(r io.Reader, proto string) (socks []procSocket, malformed, rows int, err error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	first := true
	for sc.Scan() {
		if first {
			first = false
			continue // header
		}
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		rows++
		s, listening, perr := parseProcNetSocketLine(line, proto)
		if perr != nil {
			malformed++
			continue
		}
		if listening {
			socks = append(socks, s)
		}
	}
	return socks, malformed, rows, sc.Err()
}

// parseProcNetSocketLine parses one data row. Columns:
// sl local_address rem_address st tx:rx tr:when retrnsmt uid timeout inode
func parseProcNetSocketLine(line, proto string) (s procSocket, listening bool, err error) {
	f := strings.Fields(line)
	if len(f) < 10 {
		return s, false, fmt.Errorf("short row")
	}
	addr, port, family, err := decodeProcAddr(f[1])
	if err != nil {
		return s, false, err
	}
	remAddr, remPort, _, err := decodeProcAddr(f[2])
	if err != nil {
		return s, false, err
	}
	st, err := strconv.ParseUint(f[3], 16, 8)
	if err != nil {
		return s, false, err
	}
	inode, err := strconv.ParseUint(f[9], 10, 64)
	if err != nil {
		return s, false, err
	}
	switch {
	case strings.HasPrefix(proto, "tcp"):
		listening = st == 0x0A
	default: // udp
		listening = st == 0x07 && remAddr.IsUnspecified() && remPort == 0
	}
	if port == 0 {
		listening = false
	}
	s = procSocket{
		Listener: Listener{Proto: proto, Addr: addr.String(), Port: port, Family: family},
		inode:    inode,
	}
	return s, listening, nil
}

// decodeProcAddr decodes a /proc/net "HEXIP:HEXPORT" field. IPv4 is one
// little-endian 32-bit word; IPv6 is four little-endian 32-bit words.
func decodeProcAddr(field string) (netip.Addr, int, string, error) {
	parts := strings.SplitN(field, ":", 2)
	if len(parts) != 2 {
		return netip.Addr{}, 0, "", fmt.Errorf("bad address field %q", field)
	}
	raw, err := hex.DecodeString(parts[0])
	if err != nil {
		return netip.Addr{}, 0, "", err
	}
	p, err := strconv.ParseUint(parts[1], 16, 16)
	if err != nil {
		return netip.Addr{}, 0, "", err
	}
	switch len(raw) {
	case 4:
		return netip.AddrFrom4([4]byte{raw[3], raw[2], raw[1], raw[0]}), int(p), "ipv4", nil
	case 16:
		var b [16]byte
		for w := 0; w < 4; w++ {
			for i := 0; i < 4; i++ {
				b[w*4+i] = raw[w*4+3-i]
			}
		}
		return netip.AddrFrom16(b), int(p), "ipv6", nil
	}
	return netip.Addr{}, 0, "", fmt.Errorf("bad address length in %q", field)
}

// resolveOwners fills Process/ProcessKnown best-effort by matching the
// listening sockets' inodes against /proc/<pid>/fd. Bounded by
// MaxProcPIDsScanned and a per-process fd cap; permission errors are
// expected and skipped silently. Only the short process name (comm) is
// read -- never the command line or environment.
func (d *ListeningDetector) resolveOwners(ctx context.Context, listeners []Listener, inodes map[string][]uint64) {
	wanted := make(map[uint64]int) // inode -> index into listeners
	for i, l := range listeners {
		for _, ino := range inodes[l.Key()] {
			wanted[ino] = i
		}
	}
	if len(wanted) == 0 {
		return
	}
	entries, err := os.ReadDir(d.procRoot)
	if err != nil {
		return
	}
	scanned := 0
	for _, e := range entries {
		if ctx.Err() != nil || len(wanted) == 0 {
			return
		}
		if !e.IsDir() {
			continue
		}
		if _, err := strconv.Atoi(e.Name()); err != nil {
			continue
		}
		if scanned++; scanned > thresholds.MaxProcPIDsScanned {
			return
		}
		fdDir := filepath.Join(d.procRoot, e.Name(), "fd")
		fds, err := os.ReadDir(fdDir)
		if err != nil {
			continue
		}
		comm := ""
		for n, fd := range fds {
			if n >= 4096 {
				break
			}
			target, err := os.Readlink(filepath.Join(fdDir, fd.Name()))
			if err != nil {
				continue
			}
			ino, ok := parseSocketInode(target)
			if !ok {
				continue
			}
			idx, hit := wanted[ino]
			if !hit {
				continue
			}
			if comm == "" {
				b, err := os.ReadFile(filepath.Join(d.procRoot, e.Name(), "comm"))
				if err != nil {
					break
				}
				comm = strings.TrimSpace(string(b))
				if len(comm) > 64 {
					comm = comm[:64]
				}
				if comm == "" {
					break
				}
			}
			if !listeners[idx].ProcessKnown {
				listeners[idx].Process = comm
				listeners[idx].ProcessKnown = true
			}
			delete(wanted, ino)
		}
	}
}
