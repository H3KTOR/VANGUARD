// dotenv.go implements a minimal, stdlib-only ".env" file loader for local
// development convenience. It deliberately does NOT pull in a third-party
// dotenv package -- VANGUARD's hard architectural constraint is a single,
// dependency-light Go binary, and a 15-line parser for "KEY=VALUE per
// line" more than covers what's needed here.
//
// In production, secrets are expected to come from systemd's
// EnvironmentFile= directive (see docs/vanguard.service /
// docs/install.md), which is the real, hardened equivalent of a `.env`
// file (root-owned, mode 0600, never touches the process command line).
// loadDotEnvFile is a convenience for `go run` / `./vanguard serve`
// invocations during local development where standing up a systemd unit
// isn't practical.
package main

import (
	"bufio"
	"log"
	"os"
	"strings"
)

// dotEnvPath is the file loadDotEnvFile looks for, relative to the
// process's current working directory. Kept as a var (not a const) so
// tests can point it elsewhere without touching the real filesystem.
var dotEnvPath = ".env"

// loadDotEnvFile reads dotEnvPath (if it exists) and applies every
// KEY=VALUE line to the process environment via os.Setenv, UNLESS that key
// is already set in the environment -- so a real deployment's actual env
// vars (or systemd's EnvironmentFile=) always take precedence over a
// stray .env file that happens to be present.
//
// Missing file: silently returns (this is the common case in production
// and must never be treated as an error). Malformed lines (no `=`, or a
// line starting with `#`) are skipped. Never returns an error: at worst,
// a broken .env file is simply ignored line-by-line, logged at a glance.
func loadDotEnvFile() {
	f, err := os.Open(dotEnvPath)
	if err != nil {
		return // no .env file present; nothing to do
	}
	defer f.Close()

	loaded := 0
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		// Strip a single layer of matching quotes, e.g. KEY="value with spaces".
		if len(value) >= 2 {
			if (value[0] == '"' && value[len(value)-1] == '"') || (value[0] == '\'' && value[len(value)-1] == '\'') {
				value = value[1 : len(value)-1]
			}
		}
		if key == "" {
			continue
		}
		if _, alreadySet := os.LookupEnv(key); alreadySet {
			continue // real environment always wins over .env
		}
		if err := os.Setenv(key, value); err != nil {
			log.Printf("[dotenv] failed to set %s from %s: %v", key, dotEnvPath, err)
			continue
		}
		loaded++
	}
	if loaded > 0 {
		log.Printf("[dotenv] loaded %d variable(s) from %s (development convenience; production should use systemd EnvironmentFile=)", loaded, dotEnvPath)
	}
}
