package firewall

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"vanguard/core/internal/database"
)

func TestNormalizeIP(t *testing.T) {
	good := map[string]string{
		"203.0.113.9":           "203.0.113.9",
		"  203.0.113.9 ":        "203.0.113.9",
		"::ffff:203.0.113.9":    "203.0.113.9",
		"203.0.113.9\n":         "203.0.113.9", // surrounding whitespace is dropped; the result is canonical
		"2001:DB8::1":           "2001:db8::1",
		"2001:0db8:0:0:0:0:0:1": "2001:db8::1",
	}
	for in, want := range good {
		if got, err := NormalizeIP(in); err != nil || got != want {
			t.Errorf("%q -> %q, %v (want %q)", in, got, err, want)
		}
	}
	for _, bad := range []string{
		"", "any", "anywhere", "0.0.0.0/0", "::/0", "10.0.0.0/8", "203.0.113.0/24", "0.0.0.0", "::", "224.0.0.1", "ff02::1",
		"example.com", "203.0.113.9 extra", "-h", "--force", "203.0.113.256", "fe80::1%eth0", string(make([]byte, 100)),
	} {
		if got, err := NormalizeIP(bad); err == nil {
			t.Errorf("%q must be refused, got %q", bad, got)
		}
	}
}

// A range or "any" must never reach the firewall executor and must never be
// able to step around the fail-safe whitelist.
func TestBan_RefusesRangesAndNeverCallsTheExecutor(t *testing.T) {
	a, db, exec := fileAutopilot(t, filepath.Join(t.TempDir(), "n.db"))
	for _, bad := range []string{"any", "0.0.0.0/0", "::/0", "127.0.0.0/8", "10.0.0.0/8", "--help", ""} {
		if err := a.Ban(context.Background(), bad, "x", time.Hour, nil, database.FirewallSourceManual); err == nil {
			t.Errorf("Ban(%q) must fail", bad)
		}
	}
	if len(exec.Blocked) != 0 {
		t.Fatalf("executor was called for an invalid target: %v", exec.Blocked)
	}
	for _, c := range exec.Calls {
		if c != "" && (len(c) >= 5 && c[:5] == "Block") {
			t.Fatalf("executor Block called: %v", exec.Calls)
		}
	}
	var n int64
	db.Model(&database.FirewallRule{}).Where("is_whitelisted = 0").Count(&n)
	if n != 0 {
		t.Fatalf("a rule was stored for an invalid target: %d", n)
	}
}

// The whitelist compares canonical forms: spelling a protected address
// differently must not step around it.
func TestBan_WhitelistProtectsEveryEquivalentSpelling(t *testing.T) {
	a, _, exec := fileAutopilot(t, filepath.Join(t.TempDir(), "w.db"))
	if err := a.Whitelist(context.Background(), "203.0.113.50", "admin"); err != nil {
		t.Fatal(err)
	}
	for _, spelled := range []string{"203.0.113.50", " 203.0.113.50 ", "::ffff:203.0.113.50"} {
		if err := a.Ban(context.Background(), spelled, "x", time.Hour, nil, database.FirewallSourceManual); err == nil {
			t.Errorf("Ban(%q) must be refused by the whitelist", spelled)
		}
	}
	if exec.Blocked["203.0.113.50"] {
		t.Fatal("a whitelisted address was blocked")
	}
}

func TestWhitelist_RefusesRanges(t *testing.T) {
	a, _, exec := fileAutopilot(t, filepath.Join(t.TempDir(), "wl.db"))
	if err := a.Whitelist(context.Background(), "0.0.0.0/0", "oops"); err == nil {
		t.Fatal("whitelisting a range must be refused")
	}
	if len(exec.Allowed) != 0 {
		t.Fatalf("executor Allow reached with an invalid target: %v", exec.Allowed)
	}
}

func TestPanicPreview_IgnoresUnparseableCallerAddress(t *testing.T) {
	a, _, _ := fileAutopilot(t, filepath.Join(t.TempDir(), "p.db"))
	p := a.PreviewPanicMode("not-an-ip, 0.0.0.0/0")
	for _, ip := range p.WillAllowIPs {
		if ip == "not-an-ip, 0.0.0.0/0" {
			t.Fatalf("garbage was added to the lockdown allow-list: %v", p.WillAllowIPs)
		}
	}
}

// Demo data must never become a real firewall rule after a restart, and a
// stored row that is a range ("0.0.0.0/0") must never be handed to the firewall.
func TestReconcile_SkipsSimulatedAndInvalidRows(t *testing.T) {
	a, db, exec := fileAutopilot(t, filepath.Join(t.TempDir(), "rc.db"))
	until := time.Now().UTC().Add(time.Hour)
	for _, r := range []database.FirewallRule{
		{IPAddress: "203.0.113.70", Source: database.FirewallSourceAutopilot, BannedAt: time.Now().UTC(), UnbanAt: &until},
		{IPAddress: "203.0.113.71", Source: database.FirewallSourceSimulator, BannedAt: time.Now().UTC(), UnbanAt: &until},
		{IPAddress: "0.0.0.0/0", Source: database.FirewallSourceManual, BannedAt: time.Now().UTC(), UnbanAt: &until},
		{IPAddress: "any", Source: database.FirewallSourceManual, BannedAt: time.Now().UTC(), UnbanAt: &until},
	} {
		r := r
		if err := db.CreateFirewallRule(&r); err != nil {
			t.Fatal(err)
		}
	}
	if err := a.ReconcileOnStartup(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !exec.Blocked["203.0.113.70"] {
		t.Fatal("a real ban must be re-applied")
	}
	for _, ip := range []string{"203.0.113.71", "0.0.0.0/0", "any"} {
		if exec.Blocked[ip] {
			t.Fatalf("%q must not be applied to the firewall on startup", ip)
		}
	}
}
