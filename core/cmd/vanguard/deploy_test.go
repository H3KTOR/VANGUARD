package main

import (
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// deployDir is <repo>/deploy relative to this package.
func deployDir(t *testing.T) string {
	t.Helper()
	d, err := filepath.Abs(filepath.Join("..", "..", "..", "deploy"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(d); err != nil {
		t.Fatalf("deploy directory missing: %v", err)
	}
	return d
}

// unit is a parsed systemd unit/drop-in: section -> key -> values in order.
type unit map[string]map[string][]string

func parseUnit(t *testing.T, path string) unit {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	u := unit{}
	sec := ""
	var pending string
	for _, raw := range strings.Split(strings.ReplaceAll(string(b), "\r\n", "\n"), "\n") {
		line := strings.TrimSpace(raw)
		if pending != "" {
			line = pending + " " + line
			pending = ""
		}
		if strings.HasSuffix(line, "\\") { // systemd line continuation
			pending = strings.TrimSpace(strings.TrimSuffix(line, "\\"))
			continue
		}
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			sec = line[1 : len(line)-1]
			if u[sec] == nil {
				u[sec] = map[string][]string{}
			}
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok || sec == "" {
			t.Fatalf("unparseable unit line %q", line)
		}
		u[sec][k] = append(u[sec][k], strings.TrimSpace(v))
	}
	return u
}

func (u unit) one(sec, key string) string {
	v := u[sec][key]
	if len(v) == 0 {
		return ""
	}
	return v[len(v)-1]
}

// execArgs returns the argument list after "vanguard" of an ExecStart value.
func execArgs(t *testing.T, line string) []string {
	t.Helper()
	f := strings.Fields(line)
	for i, w := range f {
		if strings.HasSuffix(w, "/vanguard") {
			return f[i+1:]
		}
	}
	t.Fatalf("no vanguard executable in %q", line)
	return nil
}

func TestServiceUnit_LeastPrivilegeAndHardeningDirectives(t *testing.T) {
	u := parseUnit(t, filepath.Join(deployDir(t), "vanguard.service"))
	svc := "Service"
	if u.one(svc, "User") == "" || u.one(svc, "User") == "root" || u.one(svc, "Group") == "root" {
		t.Fatalf("the service must run as an unprivileged account, got User=%q Group=%q", u.one(svc, "User"), u.one(svc, "Group"))
	}
	want := map[string]string{
		"ProtectSystem": "strict", "ProtectHome": "true", "PrivateTmp": "true", "ProtectKernelTunables": "true",
		"ProtectKernelModules": "true", "ProtectControlGroups": "true", "LockPersonality": "true", "RestrictSUIDSGID": "true",
		"RestrictNamespaces": "true", "UMask": "0077", "Restart": "on-failure", "KillSignal": "SIGTERM",
	}
	for k, v := range want {
		if got := u.one(svc, k); got != v {
			t.Errorf("%s=%q, want %q", k, got, v)
		}
	}
	// the single, documented reason NoNewPrivileges is off in this variant
	if u.one(svc, "NoNewPrivileges") != "false" {
		t.Error("the enforcing variant documents NoNewPrivileges=false (sudo ufw); do not change it silently")
	}
	hdr, _ := os.ReadFile(filepath.Join(deployDir(t), "vanguard.service"))
	if !strings.Contains(string(hdr), "NoNewPrivileges must be false") {
		t.Error("the reason for NoNewPrivileges=false must stay documented in the unit")
	}
	if got := u.one(svc, "AmbientCapabilities"); got != "" {
		t.Errorf("no ambient capabilities are needed (all ports > 1024); got %q", got)
	}
	if !strings.Contains(u.one(svc, "ReadWritePaths"), "/opt/vanguard/data") || strings.Contains(u.one(svc, "ReadWritePaths"), " / ") {
		t.Errorf("ReadWritePaths: %q", u.one(svc, "ReadWritePaths"))
	}
	for _, k := range []string{"MemoryMax", "CPUQuota", "TasksMax", "LimitNOFILE", "TimeoutStopSec"} {
		if u.one(svc, k) == "" {
			t.Errorf("%s must be set", k)
		}
	}
	// the doctor pre-check must not block start until it is verified on Linux
	if pre := u.one(svc, "ExecStartPre"); !strings.HasPrefix(pre, "-") || !strings.Contains(pre, "doctor") {
		t.Errorf("ExecStartPre should be a non-blocking doctor run, got %q", pre)
	}
	if u.one("Install", "WantedBy") != "multi-user.target" {
		t.Error("WantedBy")
	}
}

// Every flag the shipped units pass must be a real `serve` flag and the whole
// command line must satisfy the daemon's own startup validation.
func TestServiceUnits_ExecStartParsesWithTheRealFlagSet(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"vanguard.service", "vanguard-monitor-only.conf"} {
		u := parseUnit(t, filepath.Join(deployDir(t), name))
		starts := u["Service"]["ExecStart"]
		line := starts[len(starts)-1]
		args := execArgs(t, line)
		if len(args) == 0 || args[0] != "serve" {
			t.Fatalf("%s: ExecStart should run `serve`, got %q", name, line)
		}
		// point the file-system flags at a directory that exists in the test
		patched := []string{}
		for i := 1; i < len(args); i++ {
			a := args[i]
			if a == "-db" && i+1 < len(args) {
				patched = append(patched, "-db", filepath.Join(dir, "v.db"))
				i++
				continue
			}
			patched = append(patched, a)
		}
		cfg, err := parseServeFlagsE(patched, io.Discard)
		if err != nil {
			t.Fatalf("%s: the unit's flags are rejected by the daemon: %v\n%s", name, err, line)
		}
		if cfg.HTTPAddr != "127.0.0.1:8080" {
			t.Errorf("%s: units must bind loopback by default, got %q", name, cfg.HTTPAddr)
		}
		if bindWarning(cfg.HTTPAddr) != "" {
			t.Errorf("%s: unexpected bind warning", name)
		}
	}
	// the doctor pre-check line must also use real doctor flags
	u := parseUnit(t, filepath.Join(deployDir(t), "vanguard.service"))
	pre := strings.TrimPrefix(u.one("Service", "ExecStartPre"), "-")
	args := execArgs(t, pre)
	if args[0] != "doctor" {
		t.Fatalf("ExecStartPre: %q", pre)
	}
	for _, a := range args[1:] {
		if strings.HasPrefix(a, "-") && !doctorFlagNames[strings.TrimLeft(a, "-")] {
			t.Errorf("ExecStartPre uses unknown doctor flag %q", a)
		}
	}
}

var doctorFlagNames = map[string]bool{"db": true, "backup-dir": true, "env-file": true, "http-addr": true, "auth-log": true, "health-url": true, "check-ufw": true, "ufw-sudo": true, "json": true}

func TestMonitorOnlyDropIn_RemovesPrivilege(t *testing.T) {
	u := parseUnit(t, filepath.Join(deployDir(t), "vanguard-monitor-only.conf"))
	s := u["Service"]
	if got := s["NoNewPrivileges"]; len(got) != 1 || got[0] != "true" {
		t.Fatalf("monitor-only must set NoNewPrivileges=true, got %v", got)
	}
	starts := s["ExecStart"]
	if len(starts) != 2 || starts[0] != "" {
		t.Fatalf("a drop-in must clear ExecStart before redefining it, got %q", starts)
	}
	if strings.Contains(starts[1], "-ufw") {
		t.Fatalf("monitor-only must not enforce with ufw: %s", starts[1])
	}
	rw := s["ReadWritePaths"]
	if len(rw) != 2 || rw[0] != "" || strings.Contains(rw[1], "ufw") {
		t.Fatalf("ReadWritePaths must be reset and minimal, got %q", rw)
	}
}

func TestEnvExample_HasNoRealSecretsAndDocumentsTheRules(t *testing.T) {
	b, err := os.ReadFile(filepath.Join(deployDir(t), "vanguard.env.example"))
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "#") || line == "" {
			continue
		}
		k, v, _ := strings.Cut(line, "=")
		if v != "" {
			t.Errorf("the example must not carry a value for %s", k)
		}
	}
	for _, must := range []string{"0600", "32", "openssl rand -hex 32", "VANGUARD_ALLOWED_HOSTS"} {
		if !strings.Contains(s, must) {
			t.Errorf("env example should mention %q", must)
		}
	}
}

func TestDeployScripts_SyntaxAndSafetyProperties(t *testing.T) {
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("bash not available; run `make check-deploy` on a host with bash")
	}
	for _, name := range []string{"install.sh", "upgrade.sh", "release.sh"} {
		p := filepath.Join(deployDir(t), name)
		if out, err := exec.Command(bash, "-n", p).CombinedOutput(); err != nil {
			t.Errorf("%s fails bash -n: %v\n%s", name, err, out)
		}
		b, _ := os.ReadFile(p)
		s := string(b)
		if strings.Contains(s, "\r") {
			t.Errorf("%s contains CR characters (CRLF would break it on Linux)", name)
		}
		if !strings.HasPrefix(s, "#!/usr/bin/env bash\n") || !strings.Contains(s, "set -euo pipefail") {
			t.Errorf("%s must start with a bash shebang and use strict mode", name)
		}
		// nothing here may fetch code from the network or pipe it into a shell
		for _, l := range strings.Split(s, "\n") {
			l = strings.TrimSpace(l)
			if strings.HasPrefix(l, "#") {
				continue
			}
			for _, banned := range []string{"wget ", "| sh", "| bash", "curl "} {
				if strings.Contains(l, banned) {
					t.Errorf("%s runs a network fetch / pipe-to-shell: %q", name, l)
				}
			}
		}
	}
	// install.sh must never alter the firewall or overwrite what exists
	b, _ := os.ReadFile(filepath.Join(deployDir(t), "install.sh"))
	s := string(b)
	for _, banned := range []string{"ufw enable", "ufw disable", "ufw reset", "ufw allow ", "ufw deny ", "ufw default"} {
		for _, l := range strings.Split(s, "\n") {
			l = strings.TrimSpace(l)
			if strings.HasPrefix(l, "#") || strings.HasPrefix(l, "say ") {
				continue
			}
			if strings.Contains(l, banned) {
				t.Errorf("install.sh must not change firewall state: %q", l)
			}
		}
	}
	for _, must := range []string{`refusing to overwrite existing`, `[skip] $ENV_FILE exists`, `.new`, `--dry-run`} {
		if !strings.Contains(s, must) {
			t.Errorf("install.sh lost a non-destructive guard: %q", must)
		}
	}
	// upgrade.sh must take a verified backup before replacing anything
	u, _ := os.ReadFile(filepath.Join(deployDir(t), "upgrade.sh"))
	us := string(u)
	iBackup := strings.Index(us, "backup create")
	iVerify := strings.Index(us, "backup verify")
	iStop := strings.Index(us, `run systemctl stop`)
	iMove := strings.Index(us, `run mv -f "$BIN_DEST.new"`)
	if !(iBackup > 0 && iVerify > iBackup && iStop > iVerify && iMove > iStop) {
		t.Errorf("upgrade.sh order must be: backup create -> verify -> stop -> replace (got %d %d %d %d)", iBackup, iVerify, iStop, iMove)
	}
	if strings.Contains(us, "backup restore") && strings.Contains(us, "-confirm") && !strings.Contains(us, "cat >&2 <<EOF") {
		t.Error("upgrade.sh may only PRINT the restore command, never run it")
	}
}
