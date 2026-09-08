package hostsec

// ---------------------------------------------------------------------------
// Feature 2: Persistence Detection
//
// Detection:   periodic parse of every well-known Linux persistence
//              mechanism: cron (/etc/crontab, /etc/cron.d/*), systemd
//              units/timers (/etc/systemd/system/*.service|*.timer), SSH
//              authorized_keys (every local user's home directory, parsed
//              from /etc/passwd), shell startup files (/etc/profile,
//              /etc/profile.d/*, /etc/bash.bashrc), and sudoers
//              (/etc/sudoers, /etc/sudoers.d/*).
// Evidence:    the new/changed line or unit filename, plus its source file.
// Risk:        database.IncidentPersistenceDetected.
// Correlation: routed through the standard Incident pipeline.
// Response:    alert-only (SourceIP=HostLocalIP is whitelisted; see FIM's
//              doc comment for the shared rationale).
// False positives: each source is line-oriented and diffed against its own
//              baseline, so routine administration (e.g. cron-managed
//              logrotate already present at first scan) is captured once
//              as the baseline and never re-fires; only genuinely NEW
//              lines/units raise a finding. Comments and blank lines are
//              ignored (see nonComment in hostsec.go).
// ---------------------------------------------------------------------------

import (
	"bufio"
	"context"
	"os"
	"path/filepath"
	"strings"

	"vanguard/core/internal/database"
	"vanguard/core/internal/thresholds"
)

// PersistenceDetector implements Persistence Detection.
type PersistenceDetector struct {
	db       *database.DB
	reporter Reporter
}

// NewPersistenceDetector constructs a Persistence Detector.
func NewPersistenceDetector(db *database.DB, reporter Reporter) *PersistenceDetector {
	return &PersistenceDetector{db: db, reporter: reporter}
}

// Scan performs one full pass over every persistence source.
func (d *PersistenceDetector) Scan(ctx context.Context) {
	first, err := isFirstScan(d.db, database.BaselinePersistence)
	if err != nil {
		logf("persistence", "failed to check first-scan marker: %v", err)
		return
	}

	d.scanCron(first)
	if ctx.Err() != nil {
		return
	}
	d.scanSystemdUnits(first)
	if ctx.Err() != nil {
		return
	}
	d.scanAuthorizedKeys(first)
	if ctx.Err() != nil {
		return
	}
	d.scanShellStartupFiles(first)
	if ctx.Err() != nil {
		return
	}
	d.scanSudoers(first)

	if first {
		if err := markSeeded(d.db, database.BaselinePersistence); err != nil {
			logf("persistence", "failed to mark category seeded: %v", err)
		}
	}
}

// diffLineFile reads path (a config file whose individual non-comment
// lines are each an independent persistence entry, e.g. a crontab or
// sudoers file) and reports every line not already present in the
// baseline as "new_<kind>_entry". sourceLabel identifies the origin file
// in the reported Finding's Subject/Details.
func (d *PersistenceDetector) diffLineFile(path, kind string, firstScan bool) {
	f, err := os.Open(path)
	if err != nil {
		if !os.IsNotExist(err) {
			logf("persistence", "failed to open %s: %v", path, err)
		}
		return
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if !nonComment(line) {
			continue
		}
		key := kind + ":" + path + ":" + shortHash(line)
		_, err := d.db.GetHostBaseline(database.BaselinePersistence, key)
		if err == nil {
			continue // already known
		}
		if err != database.ErrNotFound {
			logf("persistence", "baseline lookup failed for %s: %v", key, err)
			continue
		}
		// Brand-new entry.
		if !firstScan {
			d.reporter.ReportHostFinding(Finding{
				Type:    database.IncidentPersistenceDetected,
				Change:  "new_" + kind + "_entry",
				Subject: path,
				Details: map[string]any{
					"source": path,
					"kind":   kind,
					"line":   truncate(strings.TrimSpace(line), 400),
				},
			})
		}
		if err := d.db.UpsertHostBaseline(database.BaselinePersistence, key, `{"seen":true}`); err != nil {
			logf("persistence", "failed to save baseline for %s: %v", key, err)
		}
	}
}

func (d *PersistenceDetector) scanCron(firstScan bool) {
	d.diffLineFile("/etc/crontab", "cron", firstScan)

	entries, err := os.ReadDir("/etc/cron.d")
	if err != nil {
		return // absent cron.d is entirely normal, not an error worth logging
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		d.diffLineFile(filepath.Join("/etc/cron.d", e.Name()), "cron", firstScan)
	}
}

// scanSystemdUnits treats the *appearance* of a new unit file under
// /etc/systemd/system as persistence-relevant (a new service or timer is a
// classic Linux persistence primitive), independent of FIM's own tracking
// of that same directory for generic content-integrity purposes -- FIM
// answers "did anything in this directory change", Persistence answers
// "is there a NEW service/timer that wasn't here before".
func (d *PersistenceDetector) scanSystemdUnits(firstScan bool) {
	entries, err := os.ReadDir("/etc/systemd/system")
	if err != nil {
		return
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasSuffix(name, ".service") && !strings.HasSuffix(name, ".timer") {
			continue
		}
		key := "systemd:" + name
		_, err := d.db.GetHostBaseline(database.BaselinePersistence, key)
		if err == nil {
			continue
		}
		if err != database.ErrNotFound {
			logf("persistence", "baseline lookup failed for %s: %v", key, err)
			continue
		}
		if !firstScan {
			d.reporter.ReportHostFinding(Finding{
				Type:    database.IncidentPersistenceDetected,
				Change:  "new_systemd_unit",
				Subject: name,
				Details: map[string]any{
					"unit": name,
					"path": filepath.Join("/etc/systemd/system", name),
				},
			})
		}
		if err := d.db.UpsertHostBaseline(database.BaselinePersistence, key, `{"seen":true}`); err != nil {
			logf("persistence", "failed to save baseline for %s: %v", key, err)
		}
	}
}

// scanAuthorizedKeys enumerates every local user's home directory (parsed
// from /etc/passwd, so this covers root and every real account without
// hardcoding paths) and diffs their ~/.ssh/authorized_keys file line by
// line -- a newly-appended public key is one of the most common real-world
// persistence techniques after a successful compromise.
func (d *PersistenceDetector) scanAuthorizedKeys(firstScan bool) {
	for _, home := range homeDirectories() {
		path := filepath.Join(home, ".ssh", "authorized_keys")
		d.diffLineFile(path, "authorized_keys", firstScan)
	}
}

func (d *PersistenceDetector) scanShellStartupFiles(firstScan bool) {
	for _, p := range thresholds.ShellStartupFiles {
		d.diffLineFile(p, "shell_startup", firstScan)
	}
	entries, err := os.ReadDir("/etc/profile.d")
	if err != nil {
		return
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		d.diffLineFile(filepath.Join("/etc/profile.d", e.Name()), "shell_startup", firstScan)
	}
}

func (d *PersistenceDetector) scanSudoers(firstScan bool) {
	d.diffLineFile("/etc/sudoers", "sudoers", firstScan)
	entries, err := os.ReadDir("/etc/sudoers.d")
	if err != nil {
		return
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		d.diffLineFile(filepath.Join("/etc/sudoers.d", e.Name()), "sudoers", firstScan)
	}
}

// homeDirectories parses /etc/passwd and returns every account's home
// directory field (column 6), used to locate each user's
// ~/.ssh/authorized_keys without hardcoding a path list.
func homeDirectories() []string {
	f, err := os.Open("/etc/passwd")
	if err != nil {
		return nil
	}
	defer f.Close()

	var homes []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if !nonComment(line) {
			continue
		}
		fields := strings.Split(line, ":")
		if len(fields) >= 6 && fields[5] != "" {
			homes = append(homes, fields[5])
		}
	}
	return homes
}
