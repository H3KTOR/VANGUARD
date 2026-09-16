package detection

import "testing"

func TestIsCallbackShapedHostname_RandomLongLabel_Matches(t *testing.T) {
	cases := []string{
		"a1b2c3d4e5f6g7h8.oast.fun",
		"9f8h7j6k5l4m3n2b1v0c.interact.sh",
		"a1b2c3d4e5f6g7h8i9j0.attacker-controlled.example",
	}
	for _, host := range cases {
		if !isCallbackShapedHostname(host) {
			t.Errorf("expected %q to be recognized as callback-shaped", host)
		}
	}
}

func TestIsCallbackShapedHostname_OrdinaryHostnames_NoMatch(t *testing.T) {
	cases := []string{
		"www.example.com",
		"api.example.com",
		"cdn.static.example.com",
		"customer-support-portal.example.com", // long but hyphenated/readable
		"abcdefghijklmnopqrst.example.com",    // long but pure-alphabetic
		"1234567890123456.example.com",        // long but pure-digit
		"aaaaaaaaaaaaaaa1.example.com",        // low character diversity
		"short1.example.com",                  // below min length
	}
	for _, host := range cases {
		if isCallbackShapedHostname(host) {
			t.Errorf("expected %q to NOT be recognized as callback-shaped", host)
		}
	}
}

func TestIsCallbackShapedHostname_SingleLabel_NoMatch(t *testing.T) {
	if isCallbackShapedHostname("a1b2c3d4e5f6g7h8") {
		t.Fatalf("expected a single-label (no dot) token to never match -- not even hostname-shaped")
	}
}

func TestHasKnownOASTProviderSuffix(t *testing.T) {
	if !hasKnownOASTProviderSuffix("a1b2c3d4.oast.fun") {
		t.Errorf("expected known suffix .oast.fun to match")
	}
	if !hasKnownOASTProviderSuffix("A1B2C3D4.BURPCOLLABORATOR.NET") {
		t.Errorf("expected case-insensitive match against .burpcollaborator.net")
	}
	if hasKnownOASTProviderSuffix("a1b2c3d4.example.com") {
		t.Errorf("expected ordinary domain to NOT match a known OAST provider suffix")
	}
}

func TestIsOASTIndicator_MatchInPathAndQuery(t *testing.T) {
	matched, reinforced, hostname := isOASTIndicator("/fetch?url=http://a1b2c3d4e5f6g7h8.oast.fun/callback")
	if !matched || !reinforced {
		t.Fatalf("expected a known-suffix callback hostname to match AND reinforce, got matched=%v reinforced=%v", matched, reinforced)
	}
	if hostname != "a1b2c3d4e5f6g7h8.oast.fun" {
		t.Fatalf("expected matched hostname a1b2c3d4e5f6g7h8.oast.fun, got %q", hostname)
	}
}

func TestIsOASTIndicator_RandomHostnameWithoutKnownSuffix_MatchesUnreinforced(t *testing.T) {
	matched, reinforced, hostname := isOASTIndicator("/fetch?url=http://a1b2c3d4e5f6g7h8i9j0.attacker-controlled.example/x")
	if !matched {
		t.Fatalf("expected a random-looking hostname to match on the primary heuristic alone")
	}
	if reinforced {
		t.Fatalf("expected NO suffix reinforcement for a non-provider domain")
	}
	if hostname == "" {
		t.Fatalf("expected a non-empty matched hostname")
	}
}

func TestIsOASTIndicator_OrdinaryRequest_NoMatch(t *testing.T) {
	cases := []string{
		"/products?category=shoes&sort=price",
		"/api/v1/users/12345",
		"/fetch?url=http://api.example.com/data",
		"",
	}
	for _, path := range cases {
		if matched, _, _ := isOASTIndicator(path); matched {
			t.Errorf("expected ordinary path %q to NOT match OAST indicator", path)
		}
	}
}

func TestIsOASTIndicator_ShortSuffixOnlyHostname_NoMatchOnSuffixAlone(t *testing.T) {
	// A short, non-random leftmost label must NOT match purely because
	// the domain happens to share a known-suffix-looking name -- the
	// primary heuristic (length + randomness) is required regardless of
	// the suffix list, per the phase's "must not rely on the list alone"
	// requirement.
	matched, _, _ := isOASTIndicator("/ping?host=www.burpcollaborator.net")
	if matched {
		t.Fatalf("expected a short/non-random leftmost label to NOT match even with a known-suffix domain")
	}
}
