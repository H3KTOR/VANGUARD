package main

import (
	"strings"
	"testing"
)

func TestDefaultBindIsLoopback(t *testing.T) {
	t.Setenv("VANGUARD_HTTP_ADDR", "")
	cfg := parseServeFlags([]string{"-jwt-secret", strings.Repeat("s", 40)})
	if cfg.HTTPAddr != "127.0.0.1:8080" {
		t.Fatalf("the default must not expose the API on every interface, got %q", cfg.HTTPAddr)
	}
	if bindWarning(cfg.HTTPAddr) != "" {
		t.Fatal("a loopback bind needs no warning")
	}
}

func TestBindWarning(t *testing.T) {
	for addr, wantWarn := range map[string]bool{
		":8080": true, "0.0.0.0:8080": true, "[::]:8080": true, "192.168.1.5:8080": true, "myhost:8080": true,
		"127.0.0.1:8080": false, "[::1]:8080": false, "localhost:8080": false,
	} {
		if got := bindWarning(addr) != ""; got != wantWarn {
			t.Errorf("%s: warn=%v want %v", addr, got, wantWarn)
		}
	}
}

func TestValidateSecurityConfig(t *testing.T) {
	ok := func() serveConfig {
		return serveConfig{HTTPAddr: "127.0.0.1:8080", JWTSecret: strings.Repeat("k", 32), AdminIPs: []string{"203.0.113.5", " ::ffff:203.0.113.6 "}}
	}
	c := ok()
	if err := validateSecurityConfig(&c); err != nil {
		t.Fatal(err)
	}
	if c.AdminIPs[1] != "203.0.113.6" {
		t.Fatalf("admin IPs must be normalized, got %v", c.AdminIPs)
	}
	if c := (serveConfig{HTTPAddr: "127.0.0.1:8080"}); validateSecurityConfig(&c) != nil {
		t.Fatal("an absent secret is replaced later by a random one and is not an error here")
	}
	bad := map[string]func(*serveConfig){
		"short secret":          func(c *serveConfig) { c.JWTSecret = "short" },
		"admin range":           func(c *serveConfig) { c.AdminIPs = []string{"10.0.0.0/8"} },
		"admin hostname":        func(c *serveConfig) { c.AdminIPs = []string{"admin.example"} },
		"admin any":             func(c *serveConfig) { c.AdminIPs = []string{"any"} },
		"origin wildcard":       func(c *serveConfig) { c.AllowedOrigins = []string{"*"} },
		"origin without scheme": func(c *serveConfig) { c.AllowedOrigins = []string{"ops.example.test"} },
		"origin with path":      func(c *serveConfig) { c.AllowedOrigins = []string{"https://ops.example.test/app"} },
		"origin with creds":     func(c *serveConfig) { c.AllowedOrigins = []string{"https://u:p@ops.example.test"} },
		"origin ftp":            func(c *serveConfig) { c.AllowedOrigins = []string{"ftp://ops.example.test"} },
		"host with slash":       func(c *serveConfig) { c.AllowedHosts = []string{"a/b"} },
		"bind without port":     func(c *serveConfig) { c.HTTPAddr = "localhost" },
	}
	for name, mut := range bad {
		c := ok()
		mut(&c)
		if validateSecurityConfig(&c) == nil {
			t.Errorf("%s must be rejected at startup", name)
		}
	}
	good := ok()
	good.AllowedOrigins = []string{"https://ops.example.test", "http://localhost:5173"}
	good.AllowedHosts = []string{" Dash.Example.Test ", "*"}
	if err := validateSecurityConfig(&good); err != nil {
		t.Fatal(err)
	}
	if good.AllowedHosts[0] != "dash.example.test" {
		t.Fatalf("hosts should be trimmed and lower-cased: %v", good.AllowedHosts)
	}
}
