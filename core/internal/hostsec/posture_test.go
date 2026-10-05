package hostsec

import (
	"os"
	"path/filepath"
	"testing"

	"vanguard/core/internal/database"
)

func TestPostureDetector_SafeModeNoFinding(t *testing.T) {
	db := testDB(t)
	rep := &fakeReporter{}
	dir := t.TempDir()
	target := filepath.Join(dir, "safe.conf")
	if err := os.WriteFile(target, []byte("content\n"), 0o640); err != nil {
		t.Fatalf("write: %v", err)
	}

	cfg := DefaultPostureConfig()
	cfg.SSHDConfigPath = filepath.Join(dir, "nonexistent-sshd-isolation")
	cfg.Paths = []string{target}
	d := NewPostureDetector(db, rep, cfg)
	d.Scan(bg())

	if len(rep.findings) != 0 {
		t.Fatalf("expected 0 findings for a safe-mode file, got %d: %+v", len(rep.findings), rep.findings)
	}
}

func TestPostureDetector_UnsafeModeDetected(t *testing.T) {
	db := testDB(t)
	rep := &fakeReporter{}
	dir := t.TempDir()
	target := filepath.Join(dir, "unsafe.conf")
	if err := os.WriteFile(target, []byte("content\n"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := os.Chmod(target, 0o666); err != nil {
		t.Fatalf("chmod: %v", err)
	}

	cfg := DefaultPostureConfig()
	cfg.SSHDConfigPath = filepath.Join(dir, "nonexistent-sshd-isolation")
	cfg.Paths = []string{target}
	d := NewPostureDetector(db, rep, cfg)
	d.Scan(bg())

	got := rep.byChange("dangerous_permissions")
	if len(got) != 1 {
		t.Fatalf("expected exactly 1 dangerous_permissions finding, got %d: %+v", len(got), rep.findings)
	}
	if got[0].Type != database.IncidentConfigurationPosture {
		t.Errorf("expected type %s, got %s", database.IncidentConfigurationPosture, got[0].Type)
	}
	if got[0].Details["resource"] != target {
		t.Errorf("expected resource %s, got %v", target, got[0].Details["resource"])
	}

	// Re-scanning with the SAME unsafe state must not re-fire (dedup on
	// unchanged posture result).
	rep.reset()
	d.Scan(bg())
	if len(rep.findings) != 0 {
		t.Fatalf("expected 0 findings on repeated scan of unchanged unsafe state, got %d: %+v", len(rep.findings), rep.findings)
	}
}

func TestPostureDetector_UnsafeThenFixedThenUnsafeAgainReports(t *testing.T) {
	db := testDB(t)
	rep := &fakeReporter{}
	dir := t.TempDir()
	target := filepath.Join(dir, "flaky.conf")
	if err := os.WriteFile(target, []byte("content\n"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := os.Chmod(target, 0o666); err != nil {
		t.Fatalf("chmod: %v", err)
	}

	cfg := DefaultPostureConfig()
	cfg.SSHDConfigPath = filepath.Join(dir, "nonexistent-sshd-isolation")
	cfg.Paths = []string{target}
	d := NewPostureDetector(db, rep, cfg)
	d.Scan(bg())
	if len(rep.byChange("dangerous_permissions")) != 1 {
		t.Fatalf("expected initial unsafe finding")
	}

	// Fix it.
	if err := os.Chmod(target, 0o640); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	rep.reset()
	d.Scan(bg())
	if len(rep.findings) != 0 {
		t.Fatalf("expected 0 findings once fixed, got %+v", rep.findings)
	}

	// Regress back to the exact same unsafe mode -- must be reported
	// again, not permanently suppressed by stale baseline state.
	if err := os.Chmod(target, 0o666); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	rep.reset()
	d.Scan(bg())
	if len(rep.byChange("dangerous_permissions")) != 1 {
		t.Fatalf("expected the regression to be reported again, got %+v", rep.findings)
	}
}

func TestPostureDetector_ExpectedOwnerMatch(t *testing.T) {
	db := testDB(t)
	rep := &fakeReporter{}
	dir := t.TempDir()
	target := filepath.Join(dir, "owned.conf")
	if err := os.WriteFile(target, []byte("content\n"), 0o640); err != nil {
		t.Fatalf("write: %v", err)
	}

	myUID := os.Getuid()
	myGID := os.Getgid()

	cfg := DefaultPostureConfig()
	cfg.SSHDConfigPath = filepath.Join(dir, "nonexistent-sshd-isolation")
	cfg.Paths = []string{target}
	cfg.ExpectedOwners = map[string]string{
		target: itoa(myUID) + ":" + itoa(myGID),
	}
	d := NewPostureDetector(db, rep, cfg)
	d.Scan(bg())

	if got := rep.byChange("unexpected_ownership"); len(got) != 0 {
		t.Fatalf("expected 0 ownership findings when owner matches, got %+v", got)
	}
}

func TestPostureDetector_UnexpectedOwnerDetected(t *testing.T) {
	db := testDB(t)
	rep := &fakeReporter{}
	dir := t.TempDir()
	target := filepath.Join(dir, "owned.conf")
	if err := os.WriteFile(target, []byte("content\n"), 0o640); err != nil {
		t.Fatalf("write: %v", err)
	}

	cfg := DefaultPostureConfig()
	cfg.SSHDConfigPath = filepath.Join(dir, "nonexistent-sshd-isolation")
	cfg.Paths = []string{target}
	cfg.ExpectedOwners = map[string]string{
		// Deliberately wrong (current process almost certainly isn't
		// uid 99999).
		target: "99999:99999",
	}
	d := NewPostureDetector(db, rep, cfg)
	d.Scan(bg())

	got := rep.byChange("unexpected_ownership")
	if len(got) != 1 {
		t.Fatalf("expected exactly 1 unexpected_ownership finding, got %d: %+v", len(got), rep.findings)
	}
	if got[0].Details["expected"] != "99999:99999" {
		t.Errorf("expected expected=99999:99999, got %v", got[0].Details["expected"])
	}
}

func TestPostureDetector_MissingOptionalPathNoFinding(t *testing.T) {
	db := testDB(t)
	rep := &fakeReporter{}
	dir := t.TempDir()
	missing := filepath.Join(dir, "does-not-exist.conf")

	cfg := DefaultPostureConfig()
	cfg.SSHDConfigPath = filepath.Join(dir, "nonexistent-sshd-isolation")
	cfg.Paths = []string{missing}
	cfg.ExpectedOwners = map[string]string{missing: "0:0"}
	d := NewPostureDetector(db, rep, cfg)
	d.Scan(bg())

	if len(rep.findings) != 0 {
		t.Fatalf("expected 0 findings for a missing optional path, got %+v", rep.findings)
	}
}

func TestPostureDetector_DisabledCheckNeverFires(t *testing.T) {
	db := testDB(t)
	rep := &fakeReporter{}
	dir := t.TempDir()
	target := filepath.Join(dir, "unsafe.conf")
	if err := os.WriteFile(target, []byte("content\n"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := os.Chmod(target, 0o666); err != nil {
		t.Fatalf("chmod: %v", err)
	}

	cfg := DefaultPostureConfig()
	cfg.SSHDConfigPath = filepath.Join(dir, "nonexistent-sshd-isolation")
	cfg.Paths = []string{target}
	cfg.EnablePermissionCheck = false // explicitly disabled
	d := NewPostureDetector(db, rep, cfg)
	d.Scan(bg())

	if len(rep.findings) != 0 {
		t.Fatalf("expected 0 findings when the permission check is disabled, got %+v", rep.findings)
	}
}

func TestPostureDetector_InvalidOwnerSpecSkipsFailSafe(t *testing.T) {
	db := testDB(t)
	rep := &fakeReporter{}
	dir := t.TempDir()
	target := filepath.Join(dir, "owned.conf")
	if err := os.WriteFile(target, []byte("content\n"), 0o640); err != nil {
		t.Fatalf("write: %v", err)
	}

	cfg := DefaultPostureConfig()
	cfg.SSHDConfigPath = filepath.Join(dir, "nonexistent-sshd-isolation")
	cfg.Paths = []string{target}
	cfg.ExpectedOwners = map[string]string{
		target: "not-a-valid-spec",
	}
	d := NewPostureDetector(db, rep, cfg)
	d.Scan(bg()) // must not panic, must not report

	if len(rep.findings) != 0 {
		t.Fatalf("expected 0 findings for an invalid expected-owner spec (fail-safe skip), got %+v", rep.findings)
	}
}

func TestPostureDetector_SSHDDangerousDirective(t *testing.T) {
	db := testDB(t)
	rep := &fakeReporter{}
	dir := t.TempDir()
	sshdConf := filepath.Join(dir, "sshd_config")
	content := "Port 22\nPermitRootLogin yes\nPasswordAuthentication yes\n"
	if err := os.WriteFile(sshdConf, []byte(content), 0o640); err != nil {
		t.Fatalf("write: %v", err)
	}

	cfg := DefaultPostureConfig()
	cfg.SSHDConfigPath = sshdConf
	d := NewPostureDetector(db, rep, cfg)
	d.Scan(bg())

	got := rep.byChange("sshd_permitrootlogin")
	if len(got) != 1 {
		t.Fatalf("expected exactly 1 sshd_permitrootlogin finding, got %d: %+v", len(got), rep.findings)
	}

	// Re-scanning with no change must not re-fire.
	rep.reset()
	d.Scan(bg())
	if len(rep.findings) != 0 {
		t.Fatalf("expected 0 findings on stable re-scan, got %+v", rep.findings)
	}
}

func TestPostureDetector_SSHDSafeDirectiveNoFinding(t *testing.T) {
	db := testDB(t)
	rep := &fakeReporter{}
	dir := t.TempDir()
	sshdConf := filepath.Join(dir, "sshd_config")
	content := "Port 22\nPermitRootLogin no\n"
	if err := os.WriteFile(sshdConf, []byte(content), 0o640); err != nil {
		t.Fatalf("write: %v", err)
	}

	cfg := DefaultPostureConfig()
	cfg.SSHDConfigPath = sshdConf
	d := NewPostureDetector(db, rep, cfg)
	d.Scan(bg())

	if len(rep.findings) != 0 {
		t.Fatalf("expected 0 findings for a safe sshd_config, got %+v", rep.findings)
	}
}

func TestPostureDetector_SSHDMissingConfigNoFinding(t *testing.T) {
	db := testDB(t)
	rep := &fakeReporter{}
	dir := t.TempDir()
	missing := filepath.Join(dir, "does-not-exist")

	cfg := DefaultPostureConfig()
	cfg.SSHDConfigPath = missing
	d := NewPostureDetector(db, rep, cfg)
	d.Scan(bg())

	if len(rep.findings) != 0 {
		t.Fatalf("expected 0 findings for a missing sshd_config, got %+v", rep.findings)
	}
}

func TestPostureDetector_ServiceConfigCheckDisabled(t *testing.T) {
	db := testDB(t)
	rep := &fakeReporter{}
	dir := t.TempDir()
	sshdConf := filepath.Join(dir, "sshd_config")
	content := "PermitRootLogin yes\n"
	if err := os.WriteFile(sshdConf, []byte(content), 0o640); err != nil {
		t.Fatalf("write: %v", err)
	}

	cfg := DefaultPostureConfig()
	cfg.SSHDConfigPath = sshdConf
	cfg.EnableServiceConfigCheck = false
	d := NewPostureDetector(db, rep, cfg)
	d.Scan(bg())

	if len(rep.findings) != 0 {
		t.Fatalf("expected 0 findings when the service-config check is disabled, got %+v", rep.findings)
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
