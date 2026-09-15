package detection

import (
	"testing"

	"vanguard/core/internal/thresholds"
)

// restoreExpectedHosts temporarily sets thresholds.ExpectedHosts to hosts
// for the duration of the test, restoring the original value on cleanup.
// thresholds.ExpectedHosts is a package-level var (an intentional,
// documented operator-configuration knob -- see its doc comment), so
// tests that exercise hostMatchesExpected must not leak mutations across
// tests; t.Cleanup guarantees restoration even if the test fails.
func restoreExpectedHosts(t *testing.T, hosts []string) {
	t.Helper()
	original := thresholds.ExpectedHosts
	thresholds.ExpectedHosts = hosts
	t.Cleanup(func() { thresholds.ExpectedHosts = original })
}

func TestHostLooksLikeIPLiteral(t *testing.T) {
	cases := map[string]bool{
		"192.168.1.1":      true,
		"192.168.1.1:8080": true,
		"[::1]":            true,
		"[::1]:8080":       true,
		"203.0.113.5":      true,
		"example.com":      false,
		"example.com:8080": false,
		"":                 false,
		"api.internal":     false,
	}
	for host, want := range cases {
		if got := hostLooksLikeIPLiteral(host); got != want {
			t.Errorf("hostLooksLikeIPLiteral(%q) = %v, want %v", host, got, want)
		}
	}
}

func TestHostIsLoopbackOrPrivate(t *testing.T) {
	cases := map[string]bool{
		"127.0.0.1":            true,
		"127.0.0.1:8080":       true,
		"localhost":            true,
		"localhost:3000":       true,
		"::1":                  true,
		"[::1]":                true,
		"192.168.1.1":          true,
		"10.0.0.5":             true,
		"172.16.0.1":           true,
		"169.254.1.1":          true,
		"203.0.113.5":          false, // public TEST-NET-3, not private
		"example.com":          false,
		"shop.example.com:443": false,
		"":                     false,
	}
	for host, want := range cases {
		if got := hostIsLoopbackOrPrivate(host); got != want {
			t.Errorf("hostIsLoopbackOrPrivate(%q) = %v, want %v", host, got, want)
		}
	}
}

func TestHostMatchesExpected_EmptyAllowlist_InapplicableNeverSuspicious(t *testing.T) {
	restoreExpectedHosts(t, nil)
	applicable, matches := hostMatchesExpected("anything.example.com")
	if applicable {
		t.Fatalf("expected inapplicable (false) when ExpectedHosts is empty, got applicable=true")
	}
	if matches {
		t.Fatalf("expected matches=false when inapplicable")
	}
}

func TestHostMatchesExpected_ConfiguredAllowlist_MatchAndMismatch(t *testing.T) {
	restoreExpectedHosts(t, []string{"shop.example.com", "api.example.com"})

	applicable, matches := hostMatchesExpected("shop.example.com")
	if !applicable || !matches {
		t.Fatalf("expected an exact allowlist match, got applicable=%v matches=%v", applicable, matches)
	}

	applicable, matches = hostMatchesExpected("SHOP.EXAMPLE.COM")
	if !applicable || !matches {
		t.Fatalf("expected a case-insensitive allowlist match, got applicable=%v matches=%v", applicable, matches)
	}

	applicable, matches = hostMatchesExpected("shop.example.com:443")
	if !applicable || !matches {
		t.Fatalf("expected a port-stripped allowlist match, got applicable=%v matches=%v", applicable, matches)
	}

	applicable, matches = hostMatchesExpected("evil.example.com")
	if !applicable {
		t.Fatalf("expected applicable=true once ExpectedHosts is configured")
	}
	if matches {
		t.Fatalf("expected matches=false for a host not in the allowlist")
	}
}

func TestHostNameOnly(t *testing.T) {
	cases := map[string]string{
		"example.com":      "example.com",
		"example.com:8080": "example.com",
		"[::1]":            "::1",
		"[::1]:8080":       "::1",
		"127.0.0.1":        "127.0.0.1",
		"127.0.0.1:80":     "127.0.0.1",
		"":                 "",
	}
	for host, want := range cases {
		if got := hostNameOnly(host); got != want {
			t.Errorf("hostNameOnly(%q) = %q, want %q", host, got, want)
		}
	}
}
