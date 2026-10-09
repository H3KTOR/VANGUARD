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
)

func mustFuture() time.Time { return time.Now().Add(48 * time.Hour) }

func stanza(name, ver, arch, status string) string {
	return fmt.Sprintf("Package: %s\nStatus: %s\nPriority: optional\nArchitecture: %s\nVersion: %s\nDescription: test pkg\n continuation line\n\n",
		name, status, arch, ver)
}

const installed = "install ok installed"

func newPkgFixture(t *testing.T, body string) (*PackageDetector, *fakeReporter, string) {
	t.Helper()
	db := testDB(t)
	rep := &fakeReporter{}
	path := filepath.Join(t.TempDir(), "status")
	if body != "" {
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	cfg := DefaultPackageConfig()
	cfg.StatusPath = path
	return NewPackageDetector(db, rep, cfg), rep, path
}

func write(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestPackage_FirstBaselineAndUnchangedSilent(t *testing.T) {
	d, rep, _ := newPkgFixture(t, stanza("curl", "7.1-1", "amd64", installed))
	d.Scan(bg())
	d.Scan(bg())
	if len(rep.findings) != 0 {
		t.Fatalf("baseline must be silent: %+v", rep.findings)
	}
}

func TestPackage_InstallThenDedupe(t *testing.T) {
	base := stanza("curl", "7.1-1", "amd64", installed)
	d, rep, path := newPkgFixture(t, base)
	d.Scan(bg())
	write(t, path, base+stanza("nmap", "7.9-1", "amd64", installed))
	d.Scan(bg())
	got := rep.byChange("installed")
	if len(got) != 1 || got[0].Details["package"] != "nmap" || got[0].Type != database.IncidentPackageDrift {
		t.Fatalf("install not detected: %+v", rep.findings)
	}
	if got[0].RiskAdjust < 15 {
		t.Errorf("high-risk pattern install should weigh more, adjust=%d", got[0].RiskAdjust)
	}
	rep.reset()
	d.Scan(bg())
	d.Scan(bg())
	if len(rep.findings) != 0 {
		t.Fatalf("re-reported: %+v", rep.findings)
	}
}

func TestPackage_RemoveWatchedIsCritical(t *testing.T) {
	d, rep, path := newPkgFixture(t, stanza("sudo", "1.9-1", "amd64", installed)+stanza("curl", "7-1", "amd64", installed))
	d.Scan(bg())
	write(t, path, stanza("curl", "7-1", "amd64", installed))
	d.Scan(bg())
	got := rep.byChange("removed")
	if len(got) != 1 || !got[0].Critical {
		t.Fatalf("watched removal must escalate: %+v", rep.findings)
	}
}

func TestPackage_RemoveOrdinaryNotCritical(t *testing.T) {
	d, rep, path := newPkgFixture(t, stanza("curl", "7-1", "amd64", installed)+stanza("vim", "8-1", "amd64", installed))
	d.Scan(bg())
	write(t, path, stanza("curl", "7-1", "amd64", installed))
	d.Scan(bg())
	if got := rep.byChange("removed"); len(got) != 1 || got[0].Critical {
		t.Fatalf("ordinary removal: %+v", rep.findings)
	}
}

func TestPackage_UpgradeLowDowngradeHigher(t *testing.T) {
	d, rep, path := newPkgFixture(t, stanza("curl", "7.1-1", "amd64", installed))
	d.Scan(bg())
	write(t, path, stanza("curl", "7.2-1", "amd64", installed))
	d.Scan(bg())
	up := rep.byChange("upgraded")
	if len(up) != 1 || up[0].RiskAdjust >= 0 {
		t.Fatalf("upgrade should be low risk: %+v", rep.findings)
	}
	rep.reset()
	write(t, path, stanza("curl", "7.0-1", "amd64", installed))
	d.Scan(bg())
	down := rep.byChange("downgraded")
	if len(down) != 1 || down[0].RiskAdjust <= 0 {
		t.Fatalf("downgrade should be higher risk: %+v", rep.findings)
	}
	if down[0].Details["old_version"] != "7.2-1" || down[0].Details["new_version"] != "7.0-1" {
		t.Errorf("versions: %+v", down[0].Details)
	}
}

func TestPackage_WatchedDowngradeCritical(t *testing.T) {
	d, rep, path := newPkgFixture(t, stanza("openssh-server", "9.2-1", "amd64", installed))
	d.Scan(bg())
	write(t, path, stanza("openssh-server", "8.0-1", "amd64", installed))
	d.Scan(bg())
	if got := rep.byChange("downgraded"); len(got) != 1 || !got[0].Critical {
		t.Fatalf("%+v", rep.findings)
	}
}

func TestPackage_ArchitectureChange(t *testing.T) {
	d, rep, path := newPkgFixture(t, stanza("foo", "1-1", "amd64", installed))
	d.Scan(bg())
	write(t, path, stanza("foo", "1-1", "arm64", installed))
	d.Scan(bg())
	if len(rep.findings) != 1 || rep.findings[0].Change != "architecture_changed" {
		t.Fatalf("%+v", rep.findings)
	}
}

func TestPackage_MultiarchInstallIsInstallNotArchChange(t *testing.T) {
	d, rep, path := newPkgFixture(t, stanza("libc6", "2.36", "amd64", installed))
	d.Scan(bg())
	write(t, path, stanza("libc6", "2.36", "amd64", installed)+stanza("libc6", "2.36", "i386", installed))
	d.Scan(bg())
	if len(rep.findings) != 1 || rep.findings[0].Change != "installed" {
		t.Fatalf("%+v", rep.findings)
	}
}

func TestPackage_StateChangeSuspicious(t *testing.T) {
	d, rep, path := newPkgFixture(t, stanza("foo", "1-1", "amd64", installed))
	d.Scan(bg())
	write(t, path, stanza("foo", "1-1", "amd64", "install ok half-configured"))
	d.Scan(bg())
	got := rep.byChange("state_changed")
	if len(got) != 1 || got[0].RiskAdjust <= 0 {
		t.Fatalf("%+v", rep.findings)
	}
}

func TestPackage_IgnoredPackageNeverReported(t *testing.T) {
	d, rep, path := newPkgFixture(t, stanza("base-files", "12-1", "amd64", installed)+stanza("curl", "1-1", "amd64", installed))
	d.Scan(bg())
	write(t, path, stanza("base-files", "12-2", "amd64", installed)+stanza("curl", "1-1", "amd64", installed))
	d.Scan(bg())
	if len(rep.findings) != 0 {
		t.Fatalf("ignored package drifted: %+v", rep.findings)
	}
}

func TestPackage_UnavailableDatabaseFailSafe(t *testing.T) {
	d, rep, path := newPkgFixture(t, stanza("curl", "1-1", "amd64", installed))
	d.Scan(bg())
	_ = os.Remove(path)
	d.Scan(bg())
	d.Scan(bg())
	if len(rep.findings) != 0 {
		t.Fatalf("missing db must not report removals: %+v", rep.findings)
	}
	write(t, path, stanza("curl", "1-1", "amd64", installed))
	d.Scan(bg())
	if len(rep.findings) != 0 {
		t.Fatalf("baseline must survive outage: %+v", rep.findings)
	}
}

func TestPackage_MalformedMetadata(t *testing.T) {
	// garbage only -> error, no findings, baseline preserved
	d, rep, path := newPkgFixture(t, stanza("curl", "1-1", "amd64", installed))
	d.Scan(bg())
	write(t, path, "this is not a dpkg status file\nat all\n")
	d.Scan(bg())
	if len(rep.findings) != 0 {
		t.Fatalf("%+v", rep.findings)
	}
	// stanzas missing required fields are skipped, valid ones kept
	pk, _, err := parseDpkgStatus(strings.NewReader("Package: broken\n\n" + stanza("ok", "1", "amd64", installed)))
	if err != nil || len(pk) != 1 {
		t.Fatalf("pk=%v err=%v", pk, err)
	}
}

func TestPackage_RemovedAndConfigFilesAreAbsent(t *testing.T) {
	pk, _, _ := parseDpkgStatus(strings.NewReader(
		stanza("a", "1", "amd64", "deinstall ok config-files") + stanza("b", "1", "amd64", "install ok not-installed") + stanza("c", "1", "amd64", installed)))
	if len(pk) != 1 || pk["c:amd64"].State != "installed" {
		t.Fatalf("%v", pk)
	}
}

func TestPackage_RestartPersistence(t *testing.T) {
	db := testDB(t)
	rep := &fakeReporter{}
	path := filepath.Join(t.TempDir(), "status")
	write(t, path, stanza("curl", "1-1", "amd64", installed))
	cfg := DefaultPackageConfig()
	cfg.StatusPath = path
	NewPackageDetector(db, rep, cfg).Scan(bg())
	d2 := NewPackageDetector(db, rep, cfg)
	d2.Scan(bg())
	if len(rep.findings) != 0 {
		t.Fatal("restart not silent")
	}
	write(t, path, stanza("curl", "1-2", "amd64", installed))
	d2.Scan(bg())
	if len(rep.byChange("upgraded")) != 1 {
		t.Fatalf("%+v", rep.findings)
	}
}

func TestCompareDebVersions(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"1.0", "1.0", 0}, {"1.0", "1.1", -1}, {"1.10", "1.9", 1},
		{"1.0~rc1", "1.0", -1}, {"1:1.0", "2.0", 1}, {"1.0-1", "1.0-2", -1},
		{"1.0+dfsg-1", "1.0-1", 1}, {"2.36-9+deb12u3", "2.36-9+deb12u4", -1},
		{"7.88.1-10+deb12u5", "7.88.1-10+deb12u5", 0}, {"1.0a", "1.0", 1},
	}
	for _, c := range cases {
		got := compareDebVersions(c.a, c.b)
		if (got < 0) != (c.want < 0) || (got > 0) != (c.want > 0) {
			t.Errorf("compare(%q,%q)=%d want sign %d", c.a, c.b, got, c.want)
		}
		if back := compareDebVersions(c.b, c.a); (back < 0) != (c.want > 0) || (back > 0) != (c.want < 0) {
			t.Errorf("not antisymmetric for %q,%q", c.a, c.b)
		}
	}
}

func TestPackage_ConcurrentScansRaceFree(t *testing.T) {
	d, _, path := newPkgFixture(t, stanza("curl", "1-1", "amd64", installed))
	d.reporter = &lockedReporter{}
	d.Scan(bg())
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if i == 2 {
				write(t, path, stanza("curl", "1-2", "amd64", installed))
			}
			d.Scan(bg())
		}(i)
	}
	wg.Wait()
}
