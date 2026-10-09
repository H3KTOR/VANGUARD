package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/shirou/gopsutil/v3/disk"

	"vanguard/core/internal/backup"
)

// Check results. "warn" never fails the run; "fail" does (exit 1).
const (
	checkOK   = "ok"
	checkWarn = "warn"
	checkFail = "fail"
	checkSkip = "skipped"
)

type doctorCheck struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	Detail string `json:"detail"`
}

type doctorOptions struct {
	DBPath     string
	BackupDir  string
	EnvFile    string
	HTTPAddr   string
	AuthLog    string
	HealthURL  string // e.g. http://127.0.0.1:8080 ; empty = skip
	CheckUFW   bool
	UFWSudo    bool
	HTTPClient *http.Client
}

// runDoctorCmd implements `vanguard doctor`: a READ-ONLY diagnostic for
// installs, upgrades and troubleshooting. It never writes to the database,
// never changes file permissions, never touches the firewall (the ufw check is
// opt-in and only runs `ufw status`), and never prints a secret's value.
//
//	vanguard doctor [-db F] [-backup-dir D] [-env-file F] [-http-addr A] [-auth-log P]
//	                [-health-url URL] [-check-ufw [-ufw-sudo]] [-json]
//
// Exit status: 0 = no failed check (warnings allowed), 1 = at least one failed
// check. A passing doctor says the host looks sane; it does not prove the
// service is secure or that detection works.
func runDoctorCmd(args []string) {
	fs := flag.NewFlagSet("doctor", flag.ExitOnError)
	o := doctorOptions{}
	fs.StringVar(&o.DBPath, "db", envOr("VANGUARD_DB_PATH", "vanguard.db"), "SQLite database path")
	fs.StringVar(&o.BackupDir, "backup-dir", envOr("VANGUARD_BACKUP_DIR", ""), "backup directory (default <db dir>/backups)")
	fs.StringVar(&o.EnvFile, "env-file", "", "the systemd EnvironmentFile to check (permissions and JWT secret presence; values are never printed)")
	fs.StringVar(&o.HTTPAddr, "http-addr", envOr("VANGUARD_HTTP_ADDR", "127.0.0.1:8080"), "the listen address the service is (or will be) started with")
	fs.StringVar(&o.AuthLog, "auth-log", envOr("VANGUARD_AUTH_LOG", "/var/log/auth.log"), "auth log the service tails (empty = not used)")
	fs.StringVar(&o.HealthURL, "health-url", "", "base URL of a running instance to probe (GET /api/health only), e.g. http://127.0.0.1:8080")
	fs.BoolVar(&o.CheckUFW, "check-ufw", false, "also verify `ufw` is installed and answers `ufw status` (read-only)")
	fs.BoolVar(&o.UFWSudo, "ufw-sudo", false, "with -check-ufw: run it through `sudo -n`")
	asJSON := fs.Bool("json", false, "machine-readable output")
	_ = fs.Parse(args)

	checks := runDoctor(context.Background(), o)
	failed := false
	for _, c := range checks {
		if c.Status == checkFail {
			failed = true
		}
	}
	if *asJSON {
		printJSON(map[string]any{"checks": checks, "ok": !failed})
	} else {
		for _, c := range checks {
			fmt.Printf("[%-7s] %-18s %s\n", c.Status, c.Name, c.Detail)
		}
		if failed {
			fmt.Println("\nresult: FAILED (fix the [fail] lines before starting or upgrading)")
		} else {
			fmt.Println("\nresult: no failed checks (warnings, if any, are advice). This is a host sanity check, not proof of security.")
		}
	}
	if failed {
		os.Exit(1)
	}
}

func modeOf(path string) (os.FileMode, os.FileInfo, error) {
	st, err := os.Stat(path)
	if err != nil {
		return 0, nil, err
	}
	return st.Mode().Perm(), st, nil
}

// runDoctor performs every check and returns them in a stable order.
func runDoctor(ctx context.Context, o doctorOptions) []doctorCheck {
	var out []doctorCheck
	add := func(name, status, detail string) { out = append(out, doctorCheck{name, status, detail}) }
	posix := runtime.GOOS != "windows"

	b := currentBuildInfo()
	add("build", checkOK, fmt.Sprintf("vanguard %s, %s/%s, %s", b.Version, b.OS, b.Arch, b.GoVersion))
	if runtime.GOOS != "linux" {
		add("platform", checkWarn, "VANGUARD is Linux-first; host monitoring and firewall features are only meaningful on Linux ("+runtime.GOOS+" is development-only)")
	} else {
		add("platform", checkOK, "linux")
	}

	// --- database -------------------------------------------------------
	dbDir := filepath.Dir(o.DBPath)
	if st, err := os.Stat(dbDir); err != nil || !st.IsDir() {
		add("db_directory", checkFail, "the database directory does not exist or is not a directory; create it (owned by the service account) before starting")
	} else {
		add("db_directory", checkOK, "exists")
		if posix {
			m := st.Mode().Perm()
			switch {
			case m&0o002 != 0:
				add("db_dir_perms", checkFail, fmt.Sprintf("mode %04o is world-writable; any local user could replace the database or its sidecar files", m))
			case m&0o007 != 0 || m&0o020 != 0:
				add("db_dir_perms", checkWarn, fmt.Sprintf("mode %04o gives group/other access; 0700 is recommended", m))
			default:
				add("db_dir_perms", checkOK, fmt.Sprintf("mode %04o", m))
			}
		}
	}
	if _, err := os.Stat(o.DBPath); os.IsNotExist(err) {
		add("db_file", checkOK, "does not exist yet; it will be created (mode 0600) on first start")
	} else if err != nil {
		add("db_file", checkFail, "cannot stat the database file: "+err.Error())
	} else {
		if posix {
			m, _, _ := modeOf(o.DBPath)
			if m&0o077 != 0 {
				add("db_perms", checkWarn, fmt.Sprintf("mode %04o lets other accounts read incident data and password hashes; run `chmod 600` on it (and its -wal/-shm files) while the service is stopped", m))
			} else {
				add("db_perms", checkOK, fmt.Sprintf("mode %04o", m))
			}
		}
		info, err := backup.InspectLive(o.DBPath)
		switch {
		case err != nil:
			add("db_integrity", checkWarn, "could not inspect read-only (is the directory readable by this account?): "+shortErr(err))
		case info.Integrity != "ok":
			add("db_integrity", checkFail, "PRAGMA integrity_check: "+info.Integrity+"; restore a verified backup (docs/PHASE11.md)")
		default:
			add("db_integrity", checkOK, "integrity_check ok")
			compat, cerr := backup.CheckCompat(info)
			switch {
			case cerr != nil:
				add("db_schema", checkWarn, "could not compare the schema: "+shortErr(cerr))
			case !compat.Compatible:
				add("db_schema", checkFail, fmt.Sprintf("the database was written by a NEWER VANGUARD (unknown: %s); downgrade is unsupported - use a build at least that new, or restore an older backup", strings.Join(firstN(compat.Unknown, 3), ", ")))
			case len(compat.WillAdd) > 0:
				add("db_schema", checkWarn, fmt.Sprintf("%d schema addition(s) will be applied automatically at the next start (e.g. %s); create and verify a backup first", len(compat.WillAdd), strings.Join(firstN(compat.WillAdd, 2), ", ")))
			default:
				add("db_schema", checkOK, "matches this build")
			}
		}
	}

	// --- backups --------------------------------------------------------
	bdir := o.BackupDir
	if bdir == "" {
		bdir = defaultBackupDir(o.DBPath)
	}
	if st, err := os.Stat(bdir); os.IsNotExist(err) {
		add("backup_dir", checkWarn, "no backup directory yet; run `vanguard backup create` before upgrading")
	} else if err != nil || !st.IsDir() {
		add("backup_dir", checkFail, "the backup path exists but is not a usable directory")
	} else {
		if l, err := backup.List(bdir); err != nil {
			add("backup_dir", checkWarn, "cannot list backups: "+shortErr(err))
		} else if len(l) == 0 {
			add("backup_dir", checkWarn, "exists but contains no backups")
		} else {
			add("backup_dir", checkOK, fmt.Sprintf("%d backup(s); newest %s (run `vanguard backup verify` to validate it)", len(l), l[0].Name))
		}
		if posix && st.Mode().Perm()&0o007 != 0 {
			add("backup_perms", checkWarn, fmt.Sprintf("mode %04o lets other accounts read backups (they contain password hashes unless created with --exclude-users); 0700 is recommended", st.Mode().Perm()))
		}
	}
	if usage, err := disk.Usage(dbDir); err == nil {
		var size int64
		if st, err := os.Stat(o.DBPath); err == nil {
			size = st.Size()
		}
		if size > 0 && int64(usage.Free) < 2*size {
			add("disk_space", checkWarn, fmt.Sprintf("%d MiB free but the database is %d MiB; a backup needs about that much again", usage.Free>>20, size>>20))
		} else {
			add("disk_space", checkOK, fmt.Sprintf("%d MiB free", usage.Free>>20))
		}
	}

	// --- configuration and secrets ---------------------------------------
	if o.EnvFile == "" {
		add("env_file", checkSkip, "not checked (pass -env-file /etc/vanguard/vanguard.env)")
	} else {
		checkEnvFile(o.EnvFile, posix, add)
	}
	if w := bindWarning(o.HTTPAddr); w != "" {
		add("listen_address", checkWarn, o.HTTPAddr+": "+w+" (see docs/PHASE13.md)")
	} else {
		add("listen_address", checkOK, o.HTTPAddr+" (loopback only)")
	}

	// --- monitored log ----------------------------------------------------
	if strings.TrimSpace(o.AuthLog) == "" {
		add("auth_log", checkSkip, "auth log tailing is disabled")
	} else if f, err := os.Open(o.AuthLog); err != nil {
		add("auth_log", checkWarn, "cannot open the auth log as this account ("+shortErr(err)+"); the service account needs read access (on Debian/Ubuntu: membership of group adm). Without it SSH detection sees nothing")
	} else {
		f.Close()
		add("auth_log", checkOK, "readable")
	}

	// --- firewall (explicit opt-in, read-only) ----------------------------
	if !o.CheckUFW {
		add("ufw", checkSkip, "not checked (pass -check-ufw); doctor never changes firewall state")
	} else {
		args := []string{"status"}
		name := "ufw"
		if o.UFWSudo {
			name, args = "sudo", []string{"-n", "ufw", "status"}
		}
		if _, err := exec.LookPath(name); err != nil {
			add("ufw", checkFail, name+" not found in PATH")
		} else {
			cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
			outb, err := exec.CommandContext(cctx, name, args...).CombinedOutput()
			cancel()
			if err != nil {
				add("ufw", checkFail, "`"+name+" "+strings.Join(args, " ")+"` failed: "+shortErr(fmt.Errorf("%v: %s", err, strings.TrimSpace(string(outb)))))
			} else if strings.Contains(strings.ToLower(string(outb)), "inactive") {
				add("ufw", checkWarn, "ufw answers but is INACTIVE: bans would be recorded but not enforced")
			} else {
				add("ufw", checkOK, "ufw status answered (read-only check)")
			}
		}
	}

	// --- a running instance -----------------------------------------------
	if o.HealthURL == "" {
		add("health", checkSkip, "no -health-url given")
	} else {
		cl := o.HTTPClient
		if cl == nil {
			cl = &http.Client{Timeout: 3 * time.Second}
		}
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(o.HealthURL, "/")+"/api/health", nil)
		resp, err := cl.Do(req)
		if err != nil {
			add("health", checkFail, "no answer from "+o.HealthURL+": "+shortErr(err))
		} else {
			defer resp.Body.Close()
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
			var hb struct {
				Status string `json:"status"`
			}
			if resp.StatusCode == 200 && json.Unmarshal(body, &hb) == nil && hb.Status == "ok" {
				add("health", checkOK, "GET /api/health answered ok (this proves the HTTP server is up, not that detectors are working; see GET /api/health/runtime when signed in)")
			} else {
				add("health", checkFail, fmt.Sprintf("GET /api/health returned HTTP %d", resp.StatusCode))
			}
		}
	}
	return out
}

func checkEnvFile(path string, posix bool, add func(name, status, detail string)) {
	m, _, err := modeOf(path)
	if err != nil {
		add("env_file", checkFail, "cannot read "+path+": "+shortErr(err))
		return
	}
	if posix {
		switch {
		case m&0o004 != 0:
			add("env_file_perms", checkFail, fmt.Sprintf("mode %04o is world-readable but holds the JWT secret; chmod 600 and chown to the service account", m))
		case m&0o040 != 0 || m&0o003 != 0:
			add("env_file_perms", checkWarn, fmt.Sprintf("mode %04o is group-accessible; 0600 is recommended", m))
		default:
			add("env_file_perms", checkOK, fmt.Sprintf("mode %04o", m))
		}
	}
	f, err := os.Open(path)
	if err != nil {
		add("env_file", checkWarn, "cannot open the file to inspect its keys: "+shortErr(err))
		return
	}
	defer f.Close()
	secretLen := -1
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if k, v, ok := strings.Cut(line, "="); ok && strings.TrimSpace(k) == "VANGUARD_JWT_SECRET" {
			secretLen = len(strings.Trim(strings.TrimSpace(v), `"'`))
		}
	}
	switch {
	case secretLen < 0:
		add("jwt_secret", checkWarn, "VANGUARD_JWT_SECRET is not set in the file: a random secret is generated on every start and every session ends at each restart")
	case secretLen < minJWTSecretLen:
		add("jwt_secret", checkFail, fmt.Sprintf("VANGUARD_JWT_SECRET is %d characters; the daemon refuses secrets shorter than %d (use `openssl rand -hex 32`)", secretLen, minJWTSecretLen))
	default:
		add("jwt_secret", checkOK, fmt.Sprintf("present (%d characters; value not shown)", secretLen))
	}
}

func shortErr(err error) string {
	s := err.Error()
	if len(s) > 200 {
		s = s[:200]
	}
	return s
}

func firstN(s []string, n int) []string {
	if len(s) > n {
		return s[:n]
	}
	return s
}
