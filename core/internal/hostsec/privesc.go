package hostsec

// ---------------------------------------------------------------------------
// Feature 3: Privilege Escalation Detection
//
// Detection combines four independent signals, each individually weaker
// but each worth its own finding:
//   1. New UID 0 (root-equivalent) accounts other than "root" itself.
//   2. New membership in a privileged group (thresholds.PrivilegedGroups:
//      sudo/wheel/root/adm/docker/shadow/disk).
//   3. Dangerous sudoers rules (NOPASSWD, or "ALL=(ALL) ALL" grants to a
//      non-root user/group).
//   4. BEST-EFFORT DETECTION: an unexpected process running as UID 0 whose
//      executable path is outside the standard system binary directories.
//      This is explicitly labeled best-effort because, per Architectural
//      Rule #3 (no eBPF/kernel modules), VANGUARD can only see a point-in-
//      time /proc snapshot on each scan tick -- a short-lived root process
//      that starts and exits between two scans is invisible, and process
//      ancestry/exec history is not available at all. This signal is
//      therefore a coarse, periodic heuristic, not a reliable process
//      execution monitor.
//
// Evidence:    the specific account/group/rule/process that triggered.
// Risk:        database.IncidentPrivilegeEscalation.
// Correlation: standard Incident pipeline.
// Response:    alert-only (SourceIP=HostLocalIP; see fim.go doc comment).
// False positives: signal 4 (root process) is scoped to a generous
//              allowlist of expected root-owned system daemons/paths so
//              routine services (sshd, systemd internals, nginx master,
//              cron, rsyslogd, VANGUARD itself) never fire it; operators
//              can extend the allowlist via config in a future phase.
// ---------------------------------------------------------------------------

import (
	"bufio"
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"vanguard/core/internal/database"
	"vanguard/core/internal/thresholds"
)

// expectedRootProcessPaths are executable paths (or path prefixes) that
// are normal to see running as root and must never trigger the
// best-effort root-process heuristic. Intentionally generous: this signal
// is meant to catch a root shell/backdoor running from an unusual
// location (e.g. /tmp/.hidden/backdoor), not to police the standard
// system daemon set.
var expectedRootProcessPaths = []string{
	"/usr/sbin/", "/usr/bin/", "/sbin/", "/bin/", "/usr/local/bin/vanguard",
	"/usr/lib/systemd/", "/lib/systemd/",
}

// PrivEscDetector implements Privilege Escalation Detection.
type PrivEscDetector struct {
	db       *database.DB
	reporter Reporter
}

// NewPrivEscDetector constructs a Privilege Escalation Detector.
func NewPrivEscDetector(db *database.DB, reporter Reporter) *PrivEscDetector {
	return &PrivEscDetector{db: db, reporter: reporter}
}

// Scan performs one full pass across all four signals.
func (p *PrivEscDetector) Scan(ctx context.Context) {
	first, err := isFirstScan(p.db, database.BaselinePrivEsc)
	if err != nil {
		logf("privesc", "failed to check first-scan marker: %v", err)
		return
	}

	p.scanUID0Accounts(first)
	if ctx.Err() != nil {
		return
	}
	p.scanPrivilegedGroups(first)
	if ctx.Err() != nil {
		return
	}
	p.scanSudoersRules(first)
	if ctx.Err() != nil {
		return
	}
	p.scanRootProcessesBestEffort(first)

	if first {
		if err := markSeeded(p.db, database.BaselinePrivEsc); err != nil {
			logf("privesc", "failed to mark category seeded: %v", err)
		}
	}
}

// scanUID0Accounts flags any /etc/passwd entry with UID "0" whose name
// isn't "root" -- a classic privilege-escalation persistence technique
// (creating a second root-equivalent account).
func (p *PrivEscDetector) scanUID0Accounts(firstScan bool) {
	users := parsePasswd()
	if len(users) == 0 {
		return
	}
	for name, entry := range users {
		if entry.UID != "0" || name == "root" {
			continue
		}
		key := "uid0:" + name
		_, err := p.db.GetHostBaseline(database.BaselinePrivEsc, key)
		if err == nil {
			continue
		}
		if err != database.ErrNotFound {
			logf("privesc", "baseline lookup failed for %s: %v", key, err)
			continue
		}
		if !firstScan {
			p.reporter.ReportHostFinding(Finding{
				Type: database.IncidentPrivilegeEscalation, Change: "uid0_account",
				Subject: name, Critical: true,
				EscalationNote: "non-root account with UID 0 (root-equivalent)",
				Details:        map[string]any{"user": name},
			})
		}
		if err := p.db.UpsertHostBaseline(database.BaselinePrivEsc, key, `{"seen":true}`); err != nil {
			logf("privesc", "failed to save baseline for %s: %v", key, err)
		}
	}
}

// scanPrivilegedGroups flags any new member of a group in
// thresholds.PrivilegedGroups. This intentionally duplicates part of
// account.go's group-membership diff, but under a distinct incident type
// (PRIVILEGE_ESCALATION_INDICATOR, not ACCOUNT_SECURITY_CHANGE) and a
// distinct baseline category, since "someone joined a privileged group"
// is specifically privilege-escalation-relevant evidence, worth its own
// signature and its own (higher) base severity.
func (p *PrivEscDetector) scanPrivilegedGroups(firstScan bool) {
	groups := parseGroup()
	if len(groups) == 0 {
		return
	}
	privileged := make(map[string]bool, len(thresholds.PrivilegedGroups))
	for _, g := range thresholds.PrivilegedGroups {
		privileged[g] = true
	}
	for name, entry := range groups {
		if !privileged[name] {
			continue
		}
		for _, member := range entry.Members {
			key := "group_member:" + name + ":" + member
			_, err := p.db.GetHostBaseline(database.BaselinePrivEsc, key)
			if err == nil {
				continue
			}
			if err != database.ErrNotFound {
				logf("privesc", "baseline lookup failed for %s: %v", key, err)
				continue
			}
			if !firstScan {
				p.reporter.ReportHostFinding(Finding{
					Type: database.IncidentPrivilegeEscalation, Change: "privileged_group_join",
					Subject: member,
					Details: map[string]any{"user": member, "group": name},
				})
			}
			if err := p.db.UpsertHostBaseline(database.BaselinePrivEsc, key, `{"seen":true}`); err != nil {
				logf("privesc", "failed to save baseline for %s: %v", key, err)
			}
		}
	}
}

// scanSudoersRules parses every sudoers source and flags dangerous grants:
// NOPASSWD (no password required for a sudo command) or a blanket
// "ALL=(ALL) ALL"/"ALL=(ALL:ALL) ALL" rule for anyone other than the
// standard %sudo/%wheel groups (which are expected to have it).
func (p *PrivEscDetector) scanSudoersRules(firstScan bool) {
	p.diffSudoersFile("/etc/sudoers", firstScan)
	entries, err := os.ReadDir("/etc/sudoers.d")
	if err != nil {
		return
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		p.diffSudoersFile(filepath.Join("/etc/sudoers.d", e.Name()), firstScan)
	}
}

func (p *PrivEscDetector) diffSudoersFile(path string, firstScan bool) {
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if !nonComment(line) {
			continue
		}
		trimmed := strings.TrimSpace(line)
		lower := strings.ToLower(trimmed)
		dangerous := strings.Contains(lower, "nopasswd") ||
			(strings.Contains(trimmed, "ALL=(ALL") && !strings.HasPrefix(trimmed, "%sudo") && !strings.HasPrefix(trimmed, "%wheel") && !strings.HasPrefix(trimmed, "root "))
		if !dangerous {
			continue
		}
		key := "sudo_rule:" + path + ":" + shortHash(trimmed)
		_, err := p.db.GetHostBaseline(database.BaselinePrivEsc, key)
		if err == nil {
			continue
		}
		if err != database.ErrNotFound {
			logf("privesc", "baseline lookup failed for %s: %v", key, err)
			continue
		}
		if !firstScan {
			p.reporter.ReportHostFinding(Finding{
				Type: database.IncidentPrivilegeEscalation, Change: "dangerous_sudo_rule",
				Subject: path,
				Details: map[string]any{"source": path, "rule": truncate(trimmed, 400)},
			})
		}
		if err := p.db.UpsertHostBaseline(database.BaselinePrivEsc, key, `{"seen":true}`); err != nil {
			logf("privesc", "failed to save baseline for %s: %v", key, err)
		}
	}
}

// scanRootProcessesBestEffort is explicitly BEST-EFFORT DETECTION -- see
// the package/file doc comment above for why. It walks /proc/<pid>,
// checks the process's effective owner via the status file's Uid line,
// and -- for any UID-0 process -- resolves /proc/<pid>/exe and flags it
// if its target path doesn't start with any expectedRootProcessPaths
// prefix.
func (p *PrivEscDetector) scanRootProcessesBestEffort(firstScan bool) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		logf("privesc", "best-effort root-process scan unavailable: %v", err)
		return
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue // not a PID directory (e.g. /proc/self, /proc/cpuinfo)
		}
		if !isRootProcess(pid) {
			continue
		}
		exe, err := os.Readlink("/proc/" + e.Name() + "/exe")
		if err != nil {
			continue // permission denied, kernel thread, or process already exited (race) -- skip silently
		}
		if isExpectedRootPath(exe) {
			continue
		}
		key := "root_proc:" + exe
		_, err = p.db.GetHostBaseline(database.BaselinePrivEsc, key)
		if err == nil {
			continue
		}
		if err != database.ErrNotFound {
			logf("privesc", "baseline lookup failed for %s: %v", key, err)
			continue
		}
		if !firstScan {
			p.reporter.ReportHostFinding(Finding{
				Type: database.IncidentPrivilegeEscalation, Change: "unexpected_root_process",
				Subject:    exe,
				BestEffort: true,
				Details: map[string]any{
					"exe": exe, "pid": pid,
					"detection_confidence": "BEST-EFFORT: point-in-time /proc snapshot only, no eBPF/kernel visibility per architectural constraint",
				},
			})
		}
		if err := p.db.UpsertHostBaseline(database.BaselinePrivEsc, key, `{"seen":true}`); err != nil {
			logf("privesc", "failed to save baseline for %s: %v", key, err)
		}
	}
}

// isRootProcess reads /proc/<pid>/status and checks whether the process's
// real (or effective) UID is 0.
func isRootProcess(pid int) bool {
	f, err := os.Open("/proc/" + strconv.Itoa(pid) + "/status")
	if err != nil {
		return false
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "Uid:") {
			fields := strings.Fields(line)
			return len(fields) >= 2 && fields[1] == "0"
		}
	}
	return false
}

func isExpectedRootPath(exe string) bool {
	for _, prefix := range expectedRootProcessPaths {
		if strings.HasPrefix(exe, prefix) {
			return true
		}
	}
	return false
}
