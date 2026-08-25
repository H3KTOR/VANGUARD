package main

import (
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	"time"
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

	if err := fs.Parse(args); err != nil {
		os.Exit(1)
	}

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
	}

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
