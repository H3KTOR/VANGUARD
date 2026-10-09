package main

import (
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"vanguard/core/internal/firewall"
)

// minJWTSecretLen is the shortest operator-supplied signing secret accepted.
// (An absent secret is replaced by a random 32-byte one, with a warning.)
const minJWTSecretLen = 32

// validateSecurityConfig checks the settings the trust model depends on and
// returns the cleaned values. Startup must fail on a bad value here rather than
// run with a weaker posture than the operator believes they configured.
func validateSecurityConfig(cfg *serveConfig) error {
	if cfg.JWTSecret != "" && len(cfg.JWTSecret) < minJWTSecretLen {
		return fmt.Errorf("the JWT secret is too short (%d characters); use at least %d random characters, for example `openssl rand -hex 32`", len(cfg.JWTSecret), minJWTSecretLen)
	}

	// Admin addresses are the fail-safe "never ban / always keep reachable"
	// list. They are matched as exact single addresses, so a range or hostname
	// here would silently protect nothing.
	var admins []string
	for _, a := range cfg.AdminIPs {
		n, err := firewall.NormalizeIP(a)
		if err != nil {
			return fmt.Errorf("-admin-ip %q is not a single valid IP address", a)
		}
		admins = append(admins, n)
	}
	cfg.AdminIPs = admins

	for _, o := range cfg.AllowedOrigins {
		if o == "*" {
			return fmt.Errorf("-allowed-origins must list explicit origins; \"*\" is refused")
		}
		u, err := url.Parse(o)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.User != nil {
			return fmt.Errorf("-allowed-origins entry %q must look like https://host[:port]", o)
		}
	}
	for i, h := range cfg.AllowedHosts {
		cfg.AllowedHosts[i] = strings.ToLower(strings.TrimSpace(h))
		if cfg.AllowedHosts[i] == "" || strings.ContainsAny(cfg.AllowedHosts[i], "/ \t") {
			return fmt.Errorf("-allowed-hosts entry %q is not a host name", h)
		}
	}
	if _, _, err := net.SplitHostPort(cfg.HTTPAddr); err != nil {
		return fmt.Errorf("-http-addr %q is not host:port", cfg.HTTPAddr)
	}
	return nil
}

// bindWarning explains the exposure of a listen address, or "" when it is
// loopback-only.
func bindWarning(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return ""
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		return "the dashboard/API is listening on ALL network interfaces; anyone who can reach this port can try to log in. Prefer 127.0.0.1 with a TLS reverse proxy or an SSH tunnel, and firewall the port"
	}
	if ip := net.ParseIP(host); ip != nil && !ip.IsLoopback() {
		return "the dashboard/API is listening on a non-loopback address (" + host + "); traffic is plain HTTP"
	}
	if ip := net.ParseIP(host); ip == nil && host != "localhost" {
		return "the dashboard/API is listening on a host name (" + host + "); traffic is plain HTTP"
	}
	return ""
}

// validateStartupPaths fails fast, with a clear message, on file-system
// settings that would otherwise surface later as an obscure SQLite error.
// It does not create or change anything.
func validateStartupPaths(cfg *serveConfig) error {
	if cfg.DBPath == "" || cfg.DBPath == ":memory:" {
		return nil
	}
	if strings.ContainsAny(cfg.DBPath, "?#\x00") {
		return fmt.Errorf("-db %q contains a character that is not allowed in a database path", cfg.DBPath)
	}
	dir := filepath.Dir(cfg.DBPath)
	if st, err := os.Stat(dir); err != nil || !st.IsDir() {
		return fmt.Errorf("the database directory %q does not exist; create it (owned by the service account, mode 0700) or fix -db", dir)
	}
	if st, err := os.Stat(cfg.DBPath); err == nil && st.IsDir() {
		return fmt.Errorf("-db %q is a directory, not a database file", cfg.DBPath)
	}
	if cfg.BackupDir != "" {
		if st, err := os.Stat(cfg.BackupDir); err == nil && !st.IsDir() {
			return fmt.Errorf("-backup-dir %q exists and is not a directory", cfg.BackupDir)
		}
	}
	return nil
}
