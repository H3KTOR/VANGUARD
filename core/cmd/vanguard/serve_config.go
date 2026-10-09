package main

import (
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	"vanguard/core/internal/hostsec"
	"vanguard/core/internal/thresholds"
)

// serveConfig holds every tunable for `vanguard serve`. Flags take
// precedence; a handful of security-sensitive values also fall back to
// environment variables so operators can avoid putting secrets on the
// process command line (visible via `ps`).
type serveConfig struct {
	DBPath  string
	Verbose bool

	HTTPAddr string

	AuthLogPath string
	WebLogPaths []string

	MetricsInterval  time.Duration
	MetricsRetention time.Duration
	DiskPath         string

	EnableHoneypot bool

	UseUFW  bool
	UFWSudo bool

	AdminIPs []string

	JWTSecret string
	JWTTTL    time.Duration

	StateMaxIdle time.Duration
	ReapInterval time.Duration

	ShutdownTimeout time.Duration

	// --- Host Security (Mega Expansion, Phase 1): FIM, Persistence,
	// Account, Privilege Escalation, SUID/SGID scanners. See
	// internal/hostsec/manager.go. ---
	EnableHostSecurity bool
	// EnableIntel turns local IOC matching on/off (Phase 6).
	EnableIntel bool
	// BackupDir is the directory API-created backups are written to.
	BackupDir     string
	FIMPaths      []string
	SUIDScanRoots []string
	// BinaryPaths (Mega Expansion, Phase 2, Feature 8: System Binary
	// Integrity). Kept separate from FIMPaths even though both feed the
	// same underlying pathBaselineWatcher engine, since they are
	// conceptually distinct operator-tunable lists (sensitive config vs.
	// security-critical executables) with independent defaults.
	BinaryPaths []string

	// SystemPosture (Mega Expansion, Phase 4): Configuration Posture,
	// Configuration Drift, Listening Service Drift, Package Drift.
	SystemPosture hostsec.SystemPostureConfig

	// TelegramBotToken / TelegramChatID enable real-time push alerts when
	// Autopilot bans an IP. Both env-var only (never a CLI flag) since
	// they're secrets that would otherwise be visible via `ps`. Either
	// being empty disables the notifier entirely (a no-op, not an error --
	// Telegram alerts are an optional enhancement, not a hard dependency).
	TelegramBotToken string
	TelegramChatID   string
}

// parseServeFlags parses `vanguard serve [flags]`. It never calls os.Exit
// itself on bad input beyond what flag.ExitOnError already does, so callers
// (and tests, if added later) get a predictable serveConfig back.
func parseServeFlags(args []string) serveConfig {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)

	dbPath := fs.String("db", envOr("VANGUARD_DB_PATH", "vanguard.db"), "Path to the SQLite database file")
	verbose := fs.Bool("verbose", false, "Enable verbose SQL logging (development only)")

	httpAddr := fs.String("http-addr", envOr("VANGUARD_HTTP_ADDR", ":8080"), "Address the REST API + dashboard listen on")

	authLog := fs.String("auth-log", envOr("VANGUARD_AUTH_LOG", "/var/log/auth.log"), "Path to the SSH/system auth log to tail (empty to disable)")
	webLogs := fs.String("web-log", envOr("VANGUARD_WEB_LOG", ""), "Comma-separated list of Nginx/Apache access log paths to tail")

	metricsInterval := fs.Duration("metrics-interval", 30*time.Second, "How often to sample system resource metrics")
	metricsRetention := fs.Duration("metrics-retention", 7*24*time.Hour, "How long to keep historical metric samples")
	diskPath := fs.String("disk-path", "/", "Filesystem path to report disk usage for")

	enableHoneypot := fs.Bool("honeypot", true, "Enable the decoy honeypot listeners (2222/33060/8081)")

	useUFW := fs.Bool("ufw", false, "Use the real `ufw` CLI to enforce bans (requires root/Linux). Defaults to an in-memory mock executor, safe for sandboxes/dev.")
	ufwSudo := fs.Bool("ufw-sudo", false, "Prepend `sudo` to every ufw command (only used with -ufw)")

	adminIPs := fs.String("admin-ip", envOr("VANGUARD_ADMIN_IPS", ""), "Comma-separated fail-safe admin IPs that Autopilot can NEVER ban")

	jwtSecret := fs.String("jwt-secret", envOr("VANGUARD_JWT_SECRET", ""), "HMAC secret used to sign dashboard session JWTs (falls back to VANGUARD_JWT_SECRET env var, then an ephemeral generated secret)")
	jwtTTL := fs.Duration("jwt-ttl", 24*time.Hour, "Dashboard session token lifetime")

	stateMaxIdle := fs.Duration("state-max-idle", 30*time.Minute, "How long per-IP in-memory detection state is kept with no activity before being reaped")
	reapInterval := fs.Duration("reap-interval", 1*time.Minute, "How often the Autopilot maintenance loop sweeps expired TTL bans and reaps idle detection state")

	shutdownTimeout := fs.Duration("shutdown-timeout", 15*time.Second, "Maximum time to let in-flight HTTP requests finish during graceful shutdown")

	enableHostSecurity := fs.Bool("hostsec", true, "Enable Host Security scanners (FIM, Persistence, Account, Privilege Escalation, SUID/SGID monitoring)")
	fimPaths := fs.String("fim-paths", envOr("VANGUARD_FIM_PATHS", ""), "Comma-separated list of additional sensitive files/directories for File Integrity Monitoring (appended to the built-in defaults)")
	suidRoots := fs.String("suid-roots", envOr("VANGUARD_SUID_ROOTS", ""), "Comma-separated list of additional directories to scan for SUID/SGID binaries (appended to the built-in defaults)")
	binaryPaths := fs.String("binary-paths", envOr("VANGUARD_BINARY_PATHS", ""), "Comma-separated list of additional security-critical binaries for System Binary Integrity monitoring (appended to the built-in defaults)")

	backupDir := fs.String("backup-dir", envOr("VANGUARD_BACKUP_DIR", ""), "Directory for backups created via the API/dashboard (default: <db dir>/backups)")
	enableIntel := fs.Bool("intel", true, "Enable local (offline) threat-intelligence IOC matching")
	systemPosture := fs.Bool("system-posture", true, "Enable Phase 4 System Posture detectors (configuration posture/drift, listening-service drift, package drift)")
	postureInterval := fs.Duration("posture-interval", envDuration("VANGUARD_POSTURE_INTERVAL"), "Override the scan interval of every Phase 4 detector (0 = per-detector defaults; minimum 1s)")
	posturePaths := fs.String("posture-paths", envOr("VANGUARD_POSTURE_PATHS", ""), "Comma-separated extra absolute paths for Configuration Posture (world-writable check)")
	driftPaths := fs.String("drift-paths", envOr("VANGUARD_DRIFT_PATHS", ""), "Comma-separated extra absolute paths for Configuration Drift")
	driftHashLimit := fs.Int64("drift-hash-limit", thresholds.ConfigDriftMaxHashBytes, "Max file size in bytes that Configuration Drift will hash (larger files are compared by metadata only)")
	driftFirstObs := fs.Bool("drift-report-first-observation", false, "Report a pre-existing monitored resource seen for the first time as drift instead of silently baselining it")
	expectedListeners := fs.String("expected-listeners", envOr("VANGUARD_EXPECTED_LISTENERS", ""), "Comma-separated allowed listeners as proto/addr/port[/process], e.g. tcp/0.0.0.0/22/sshd (proto and addr accept *)")
	ignoredListeners := fs.String("ignored-listeners", envOr("VANGUARD_IGNORED_LISTENERS", ""), "Comma-separated listeners excluded from Listening Service Drift (same format as -expected-listeners)")
	listenGrace := fs.Duration("listening-grace", thresholds.ListeningServiceGracePeriod, "Startup window during which listener changes are silently absorbed into the baseline")
	resolveProcs := fs.Bool("listening-resolve-processes", true, "Best-effort resolve the owning process name of listening sockets via /proc")
	ignoredPackages := fs.String("ignored-packages", envOr("VANGUARD_IGNORED_PACKAGES", ""), "Comma-separated package names Package Drift ignores (appended to defaults)")
	dpkgStatus := fs.String("dpkg-status", envOr("VANGUARD_DPKG_STATUS", "/var/lib/dpkg/status"), "Path of the dpkg status database read by Package Drift (read-only; absent file disables the detector gracefully)")
	watchedPackages := fs.String("watched-packages", envOr("VANGUARD_WATCHED_PACKAGES", ""), "Comma-separated security-sensitive package names (appended to defaults)")

	if err := fs.Parse(args); err != nil {
		os.Exit(1)
	}

	// Telegram alert credentials are intentionally env-var only (no CLI
	// flag): they're secrets, and flag values leak into `ps aux` output on
	// a shared/multi-tenant host in a way environment variables (readable
	// only via /proc/<pid>/environ, root-only by default) do not.
	telegramBotToken := strings.TrimSpace(os.Getenv("TELEGRAM_BOT_TOKEN"))
	telegramChatID := strings.TrimSpace(os.Getenv("TELEGRAM_CHAT_ID"))

	cfg := serveConfig{
		DBPath:           *dbPath,
		Verbose:          *verbose,
		HTTPAddr:         *httpAddr,
		AuthLogPath:      strings.TrimSpace(*authLog),
		WebLogPaths:      splitAndTrim(*webLogs),
		MetricsInterval:  *metricsInterval,
		MetricsRetention: *metricsRetention,
		DiskPath:         *diskPath,
		EnableHoneypot:   *enableHoneypot,
		UseUFW:           *useUFW,
		UFWSudo:          *ufwSudo,
		AdminIPs:         splitAndTrim(*adminIPs),
		JWTSecret:        *jwtSecret,
		JWTTTL:           *jwtTTL,
		StateMaxIdle:     *stateMaxIdle,
		ReapInterval:     *reapInterval,
		ShutdownTimeout:  *shutdownTimeout,
		TelegramBotToken: telegramBotToken,
		TelegramChatID:   telegramChatID,

		EnableHostSecurity: *enableHostSecurity,
		EnableIntel:        *enableIntel,
		BackupDir:          *backupDir,
		FIMPaths:           append(append([]string{}, thresholds.DefaultFIMPaths...), splitAndTrim(*fimPaths)...),
		SUIDScanRoots:      append(append([]string{}, thresholds.DefaultSUIDScanRoots...), splitAndTrim(*suidRoots)...),
		BinaryPaths:        append(append([]string{}, thresholds.DefaultSystemBinaryPaths...), splitAndTrim(*binaryPaths)...),
	}

	sp := hostsec.DefaultSystemPostureConfig()
	sp.Enabled = *systemPosture
	if *postureInterval < 0 {
		log.Printf("[serve] WARNING: negative -posture-interval %s ignored, using per-detector defaults", *postureInterval)
	} else {
		sp.ScanInterval = *postureInterval
	}
	sp.Posture.Paths = append(append([]string{}, sp.Posture.Paths...), splitAndTrim(*posturePaths)...)
	sp.Drift.Paths = append(append([]string{}, sp.Drift.Paths...), splitAndTrim(*driftPaths)...)
	if *driftHashLimit > 0 {
		sp.Drift.MaxHashBytes = *driftHashLimit
	}
	sp.Drift.ReportFirstObservation = *driftFirstObs
	sp.Listen.Expected = append(append([]thresholds.ExpectedListener{}, sp.Listen.Expected...), parseListenerSpecs(*expectedListeners)...)
	sp.Listen.Ignored = parseListenerSpecs(*ignoredListeners)
	if *listenGrace >= 0 {
		sp.Listen.GracePeriod = *listenGrace
	}
	sp.Listen.ResolveProcesses = *resolveProcs
	sp.Packages.Ignored = append(append([]string{}, sp.Packages.Ignored...), splitAndTrim(*ignoredPackages)...)
	sp.Packages.Watched = append(append([]string{}, sp.Packages.Watched...), splitAndTrim(*watchedPackages)...)
	if strings.TrimSpace(*dpkgStatus) != "" {
		sp.Packages.StatusPath = strings.TrimSpace(*dpkgStatus)
	}
	cfg.SystemPosture = sp

	if cfg.JWTSecret == "" {
		cfg.JWTSecret = generateEphemeralSecret()
		log.Println("[serve] WARNING: no -jwt-secret / VANGUARD_JWT_SECRET provided. Generated a random, " +
			"ephemeral secret for this process only -- every dashboard session will be invalidated on restart. " +
			"Set VANGUARD_JWT_SECRET for a stable production deployment.")
	}

	return cfg
}

// generateEphemeralSecret produces a cryptographically random 32-byte
// hex-encoded secret, used only when the operator hasn't configured one.
// Panics on failure since a broken crypto/rand source means the whole
// process's security model is unsound anyway.
func generateEphemeralSecret() string {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		panic(fmt.Sprintf("vanguard: failed to generate ephemeral JWT secret: %v", err))
	}
	return hex.EncodeToString(buf)
}

// envDuration parses a duration env var; unset or invalid yields 0
// (per-detector defaults), with the invalid case logged.
func envDuration(key string) time.Duration {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return 0
	}
	d, err := time.ParseDuration(v)
	if err != nil || d < 0 {
		log.Printf("[serve] WARNING: invalid %s=%q ignored", key, v)
		return 0
	}
	return d
}

// parseListenerSpecs parses "proto/addr/port[/process]" entries. Invalid
// entries are logged and skipped -- for an allowlist, skipping errs on
// the side of MORE alerts, never fewer.
func parseListenerSpecs(csv string) []thresholds.ExpectedListener {
	var out []thresholds.ExpectedListener
	for _, raw := range splitAndTrim(csv) {
		parts := strings.Split(raw, "/")
		if len(parts) < 3 || len(parts) > 4 {
			log.Printf("[serve] WARNING: invalid listener spec %q (want proto/addr/port[/process]), skipped", raw)
			continue
		}
		switch parts[0] {
		case "*", "tcp", "tcp6", "udp", "udp6":
		default:
			log.Printf("[serve] WARNING: invalid listener protocol in %q, skipped", raw)
			continue
		}
		port, err := strconv.Atoi(parts[2])
		if err != nil || port < 1 || port > 65535 || parts[1] == "" {
			log.Printf("[serve] WARNING: invalid listener address/port in %q, skipped", raw)
			continue
		}
		l := thresholds.ExpectedListener{Protocol: parts[0], AddressPattern: parts[1], Port: port}
		if len(parts) == 4 {
			l.ProcessNameHint = parts[3]
		}
		out = append(out, l)
	}
	return out
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func splitAndTrim(csv string) []string {
	if strings.TrimSpace(csv) == "" {
		return nil
	}
	parts := strings.Split(csv, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}
