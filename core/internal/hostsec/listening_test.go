package hostsec

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"vanguard/core/internal/database"
	"vanguard/core/internal/thresholds"
)

// lockedReporter is a concurrency-safe Reporter for race tests.
type lockedReporter struct {
	mu sync.Mutex
	n  int
}

func (r *lockedReporter) ReportHostFinding(Finding) { r.mu.Lock(); r.n++; r.mu.Unlock() }

const procNetHeader = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"

func tcpRow(sl int, local, rem, st string, inode int) string {
	return fmt.Sprintf("   %d: %s %s %s 00000000:00000000 00:00000000 00000000     0        0 %d 1 0000000000000000 100 0 0 10 0\n",
		sl, local, rem, st, inode)
}

// Samples: 0100007F:0016 = 127.0.0.1:22 ; 00000000:0016 = 0.0.0.0:22
func writeProc(t *testing.T, root string, tables map[string]string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(root, "net"), 0o755); err != nil {
		t.Fatal(err)
	}
	for name, body := range tables {
		if err := os.WriteFile(filepath.Join(root, "net", name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func newListenFixture(t *testing.T, tables map[string]string) (*ListeningDetector, *fakeReporter, string) {
	t.Helper()
	db := testDB(t)
	rep := &fakeReporter{}
	root := t.TempDir()
	writeProc(t, root, tables)
	cfg := DefaultListeningConfig()
	cfg.Expected = nil
	cfg.GracePeriod = 0
	cfg.ResolveProcesses = false
	d := NewListeningDetector(db, rep, cfg).WithProcRoot(root)
	return d, rep, root
}

var (
	lo22     = tcpRow(0, "0100007F:0016", "00000000:0000", "0A", 1)
	any22    = tcpRow(1, "00000000:0016", "00000000:0000", "0A", 2)
	any80    = tcpRow(2, "00000000:0050", "00000000:0000", "0A", 3)
	conn     = tcpRow(3, "0100007F:C350", "0100007F:0050", "01", 4)
	v6any22  = tcpRow(0, "00000000000000000000000000000000:0016", "00000000000000000000000000000000:0000", "0A", 5)
	v6lo8080 = tcpRow(1, "00000000000000000000000001000000:1F90", "00000000000000000000000000000000:0000", "0A", 6)
)

func TestParseProcNet_ListeningOnly_IPv4(t *testing.T) {
	socks, bad, rows, err := parseProcNetSockets(strings.NewReader(procNetHeader+lo22+any22+conn), "tcp")
	if err != nil || bad != 0 || rows != 3 {
		t.Fatalf("err=%v bad=%d rows=%d", err, bad, rows)
	}
	if len(socks) != 2 {
		t.Fatalf("established connection must be ignored, got %d listeners", len(socks))
	}
	if k := socks[0].Key(); k != "tcp:127.0.0.1:22" {
		t.Errorf("key = %s", k)
	}
	if k := socks[1].Key(); k != "tcp:0.0.0.0:22" {
		t.Errorf("key = %s", k)
	}
}

func TestParseProcNet_IPv6Normalization(t *testing.T) {
	socks, _, _, err := parseProcNetSockets(strings.NewReader(procNetHeader+v6any22+v6lo8080), "tcp6")
	if err != nil || len(socks) != 2 {
		t.Fatalf("err=%v n=%d", err, len(socks))
	}
	if socks[0].Key() != "tcp6:[::]:22" {
		t.Errorf("wildcard v6 key = %s", socks[0].Key())
	}
	if socks[1].Key() != "tcp6:[::1]:8080" || socks[1].Exposure() != "loopback" {
		t.Errorf("loopback v6 = %s / %s", socks[1].Key(), socks[1].Exposure())
	}
	// 0.0.0.0:22 and [::]:22 must be distinct identities
	v4, _, _, _ := parseProcNetSockets(strings.NewReader(procNetHeader+any22), "tcp")
	if v4[0].Key() == socks[0].Key() {
		t.Fatal("v4 and v6 wildcard must not be identical")
	}
}

func TestParseProcNet_UDP(t *testing.T) {
	unconn := tcpRow(0, "0100007F:0035", "00000000:0000", "07", 9)
	connected := tcpRow(1, "0100007F:0036", "0100007F:0999", "01", 10)
	socks, _, _, _ := parseProcNetSockets(strings.NewReader(procNetHeader+unconn+connected), "udp")
	if len(socks) != 1 || socks[0].Key() != "udp:127.0.0.1:53" {
		t.Fatalf("udp parse = %+v", socks)
	}
}

func TestParseProcNet_MalformedRows(t *testing.T) {
	body := procNetHeader + "garbage line\n" + "  0: ZZZZ:0016 00000000:0000 0A x x x x x x 1\n" + lo22
	socks, bad, rows, err := parseProcNetSockets(strings.NewReader(body), "tcp")
	if err != nil || bad != 2 || rows != 3 || len(socks) != 1 {
		t.Fatalf("err=%v bad=%d rows=%d socks=%d", err, bad, rows, len(socks))
	}
}

func TestListening_FirstScanBaselineThenUnchanged(t *testing.T) {
	d, rep, _ := newListenFixture(t, map[string]string{"tcp": procNetHeader + lo22 + any22})
	d.Scan(bg())
	d.Scan(bg())
	if len(rep.findings) != 0 {
		t.Fatalf("baseline/unchanged must be silent: %+v", rep.findings)
	}
}

func TestListening_NewListenerAndDedupe(t *testing.T) {
	d, rep, root := newListenFixture(t, map[string]string{"tcp": procNetHeader + lo22})
	d.Scan(bg())
	writeProc(t, root, map[string]string{"tcp": procNetHeader + lo22 + any80})
	d.Scan(bg())
	got := rep.byChange("new_listener")
	if len(got) != 1 {
		t.Fatalf("expected 1 new_listener, got %+v", rep.findings)
	}
	f := got[0]
	if f.Type != database.IncidentListeningServiceDrift || f.Details["port"] != 80 ||
		f.Details["protocol"] != "tcp" || f.Details["local_address"] != "0.0.0.0" ||
		f.Details["address_family"] != "ipv4" || f.Details["newly_observed"] != true {
		t.Errorf("bad evidence: %+v", f.Details)
	}
	rep.reset()
	for i := 0; i < 5; i++ {
		d.Scan(bg())
	}
	if len(rep.findings) != 0 {
		t.Fatalf("persistent listener re-reported: %+v", rep.findings)
	}
}

func TestListening_RemovedListener(t *testing.T) {
	d, rep, root := newListenFixture(t, map[string]string{"tcp": procNetHeader + lo22 + any80})
	d.Scan(bg())
	writeProc(t, root, map[string]string{"tcp": procNetHeader + lo22})
	d.Scan(bg())
	if len(rep.byChange("removed_listener")) != 1 {
		t.Fatalf("expected removed_listener, got %+v", rep.findings)
	}
}

func TestListening_BindAddressChange(t *testing.T) {
	d, rep, root := newListenFixture(t, map[string]string{"tcp": procNetHeader + lo22})
	d.Scan(bg())
	writeProc(t, root, map[string]string{"tcp": procNetHeader + any22})
	d.Scan(bg())
	if len(rep.findings) != 1 || rep.findings[0].Change != "bind_address_changed" {
		t.Fatalf("expected one bind_address_changed, got %+v", rep.findings)
	}
	// moving from loopback to wildcard must score higher than the
	// reverse
	up := rep.findings[0].RiskAdjust
	if up <= 0 {
		t.Errorf("wildcard exposure adjust = %d, want >0", up)
	}
}

func TestListening_ProtocolChange(t *testing.T) {
	d, rep, root := newListenFixture(t, map[string]string{"tcp": procNetHeader + any22})
	d.Scan(bg())
	writeProc(t, root, map[string]string{
		"tcp": procNetHeader,
		"udp": procNetHeader + tcpRow(0, "00000000:0016", "00000000:0000", "07", 7),
	})
	d.Scan(bg())
	if len(rep.findings) != 1 || rep.findings[0].Change != "protocol_changed" {
		t.Fatalf("expected protocol_changed, got %+v", rep.findings)
	}
}

func TestListening_ExpectedAndIgnoredSuppressed(t *testing.T) {
	d, rep, root := newListenFixture(t, map[string]string{"tcp": procNetHeader + lo22})
	d.cfg.Expected = []thresholds.ExpectedListener{{Protocol: "tcp", AddressPattern: "0.0.0.0", Port: 80}}
	d.cfg.Ignored = []thresholds.ExpectedListener{{Protocol: "*", AddressPattern: "*", Port: 22}}
	d.Scan(bg())
	writeProc(t, root, map[string]string{"tcp": procNetHeader + any80 + any22})
	d.Scan(bg())
	if len(rep.findings) != 0 {
		t.Fatalf("expected/ignored listeners must not produce drift: %+v", rep.findings)
	}
}

func TestListening_GracePeriodAbsorbsChanges(t *testing.T) {
	d, rep, root := newListenFixture(t, map[string]string{"tcp": procNetHeader + lo22})
	d.cfg.GracePeriod = time.Hour
	d.Scan(bg())
	writeProc(t, root, map[string]string{"tcp": procNetHeader + lo22 + any80})
	d.Scan(bg())
	if len(rep.findings) != 0 {
		t.Fatalf("change inside grace must be absorbed: %+v", rep.findings)
	}
	d.cfg.GracePeriod = 0
	d.Scan(bg())
	if len(rep.findings) != 0 {
		t.Fatalf("absorbed listener must be part of the baseline now: %+v", rep.findings)
	}
}

func TestListening_ProcFailureDoesNotFabricateEmptyBaseline(t *testing.T) {
	d, rep, root := newListenFixture(t, map[string]string{"tcp": procNetHeader + lo22 + any22})
	d.Scan(bg())
	// /proc/net/tcp disappears entirely: scan must abort, not report
	// "everything removed" nor overwrite the baseline.
	_ = os.RemoveAll(filepath.Join(root, "net"))
	d.Scan(bg())
	if len(rep.findings) != 0 {
		t.Fatalf("unreadable /proc must not report: %+v", rep.findings)
	}
	writeProc(t, root, map[string]string{"tcp": procNetHeader + lo22 + any22})
	d.Scan(bg())
	if len(rep.findings) != 0 {
		t.Fatalf("baseline must have survived the outage: %+v", rep.findings)
	}
}

func TestListening_AllRowsMalformedAborts(t *testing.T) {
	d, rep, root := newListenFixture(t, map[string]string{"tcp": procNetHeader + lo22})
	d.Scan(bg())
	writeProc(t, root, map[string]string{"tcp": procNetHeader + "junk\nmore junk\n"})
	d.Scan(bg())
	if len(rep.findings) != 0 {
		t.Fatalf("malformed table must not look like removal: %+v", rep.findings)
	}
}

func TestListening_ProcessOwnerResolutionAndChange(t *testing.T) {
	d, rep, root := newListenFixture(t, map[string]string{"tcp": procNetHeader + any80})
	d.cfg.ResolveProcesses = true
	mkProc := func(pid, comm string, inode int) {
		dir := filepath.Join(root, pid)
		_ = os.RemoveAll(dir)
		_ = os.MkdirAll(filepath.Join(dir, "fd"), 0o755)
		_ = os.WriteFile(filepath.Join(dir, "comm"), []byte(comm+"\n"), 0o644)
		if err := os.Symlink(fmt.Sprintf("socket:[%d]", inode), filepath.Join(dir, "fd", "3")); err != nil {
			t.Skip("symlinks unavailable: ", err)
		}
	}
	mkProc("100", "nginx", 3)
	d.Scan(bg())
	mkProc("100", "evilsrv", 3)
	d.Scan(bg())
	got := rep.byChange("process_changed")
	if len(got) != 1 || got[0].Details["process"] != "evilsrv" {
		t.Fatalf("expected process_changed to evilsrv, got %+v", rep.findings)
	}
}

func TestDiffListeners_Deterministic(t *testing.T) {
	mk := func(p string, port int) Listener {
		return Listener{Proto: p, Addr: "0.0.0.0", Port: port, Family: "ipv4"}
	}
	prev := map[string]Listener{}
	curr := map[string]Listener{}
	for _, l := range []Listener{mk("tcp", 3), mk("tcp", 1), mk("tcp", 2)} {
		curr[l.Key()] = l
	}
	a := diffListeners(prev, curr)
	b := diffListeners(prev, curr)
	if len(a) != 3 || len(b) != 3 {
		t.Fatal("expected 3 changes")
	}
	for i := range a {
		if changeKey(a[i]) != changeKey(b[i]) {
			t.Fatal("diff not deterministic")
		}
	}
	if a[0].Curr.Port != 1 {
		t.Errorf("not sorted: %v", a[0].Curr)
	}
}

func TestListenerRisk_ExposureOrdering(t *testing.T) {
	lo := ListenerChange{Kind: "new_listener", Curr: &Listener{Proto: "tcp", Addr: "127.0.0.1", Port: 9000, Family: "ipv4", ProcessKnown: true}}
	wild := ListenerChange{Kind: "new_listener", Curr: &Listener{Proto: "tcp", Addr: "0.0.0.0", Port: 9000, Family: "ipv4", ProcessKnown: true}}
	priv := ListenerChange{Kind: "new_listener", Curr: &Listener{Proto: "tcp", Addr: "0.0.0.0", Port: 22, Family: "ipv4"}}
	rem := ListenerChange{Kind: "removed_listener", Prev: &Listener{Proto: "tcp", Addr: "0.0.0.0", Port: 22}}
	al, _ := listenerRisk(lo)
	aw, _ := listenerRisk(wild)
	ap, _ := listenerRisk(priv)
	ar, _ := listenerRisk(rem)
	if !(al < aw && aw < ap) || ar >= al {
		t.Fatalf("risk ordering wrong: lo=%d wild=%d priv=%d removed=%d", al, aw, ap, ar)
	}
}

func TestListening_ConcurrentScansRaceFree(t *testing.T) {
	d, _, root := newListenFixture(t, map[string]string{"tcp": procNetHeader + lo22})
	d.reporter = &lockedReporter{}
	d.Scan(bg())
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if i == 3 {
				writeProc(t, root, map[string]string{"tcp": procNetHeader + lo22 + any80})
			}
			d.Scan(bg())
		}(i)
	}
	wg.Wait()
}
