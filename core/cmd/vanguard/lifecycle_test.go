package main

import (
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// Repeated shutdown requests (signal plus an error path) must be harmless
// and must never hang or double-close the database.
func TestShutdownIsIdempotent(t *testing.T) {
	cfg := parseServeFlags([]string{
		"-db", filepath.Join(t.TempDir(), "s.db"),
		"-auth-log", "", "-honeypot=false", "-hostsec=false", "-intel=false",
		"-jwt-secret", "test-secret-test-secret-test-secret",
	})
	cfg.ShutdownTimeout = 2 * time.Second
	a, err := buildApp(cfg)
	if err != nil {
		t.Fatalf("buildApp: %v", err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); a.shutdown() }()
	}
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("concurrent shutdown calls hung")
	}
	a.shutdown() // and once more after completion
}

func TestHealthRegistryReflectsConfiguration(t *testing.T) {
	cfg := parseServeFlags([]string{"-auth-log", "", "-web-log", "/a.log,/b.log", "-jwt-secret", "x-x-x-x-x-x-x-x-x-x-x-x"})
	reg := newRuntimeRegistry(cfg)
	got := map[string]string{}
	for _, c := range reg.Snapshot() {
		got[c.Name] = string(c.State)
	}
	if got["log:auth"] != "disabled" {
		t.Errorf("a source disabled by configuration must be 'disabled': %v", got)
	}
	if got["log:web1"] != "not_yet_observed" || got["log:web2"] != "not_yet_observed" || got["maintenance"] != "not_yet_observed" {
		t.Errorf("nothing observed yet must not read as healthy: %v", got)
	}
}
