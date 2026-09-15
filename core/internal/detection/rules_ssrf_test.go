package detection

import "testing"

func TestIsSSRFIndicator_PrivateIPInQuery(t *testing.T) {
	matched, meta, target := isSSRFIndicator("/fetch?url=http://10.0.0.1/admin")
	if !matched || meta {
		t.Fatalf("expected private-IP match without metadata escalation, got matched=%v meta=%v", matched, meta)
	}
	if target != "10.0.0.1" {
		t.Fatalf("expected matched target 10.0.0.1, got %q", target)
	}
}

func TestIsSSRFIndicator_MetadataEndpoint_Escalates(t *testing.T) {
	matched, meta, target := isSSRFIndicator("/fetch?url=http://169.254.169.254/latest/meta-data/")
	if !matched || !meta {
		t.Fatalf("expected metadata escalation, got matched=%v meta=%v", matched, meta)
	}
	if target != "169.254.169.254" {
		t.Fatalf("expected matched target 169.254.169.254, got %q", target)
	}
}

func TestIsSSRFIndicator_Loopback(t *testing.T) {
	if matched, meta, _ := isSSRFIndicator("/proxy?target=127.0.0.1:9200"); !matched || meta {
		t.Fatalf("expected loopback match without escalation, got matched=%v meta=%v", matched, meta)
	}
	if matched, _, _ := isSSRFIndicator("/proxy?target=localhost:9200"); !matched {
		t.Fatalf("expected 'localhost' hostname to match")
	}
	if matched, _, _ := isSSRFIndicator("/proxy?target=[::1]:9200"); !matched {
		t.Fatalf("expected '::1' IPv6 loopback shorthand to match")
	}
}

func TestIsSSRFIndicator_PublicIP_NoMatch(t *testing.T) {
	if matched, _, _ := isSSRFIndicator("/fetch?url=http://8.8.8.8/"); matched {
		t.Fatalf("expected public IP 8.8.8.8 to NOT match")
	}
}

func TestIsSSRFIndicator_OrdinaryDecimalValues_NoFalsePositive(t *testing.T) {
	cases := []string{
		"/page?price=19.99",
		"/v1.2.3/resource",
		"/api/products?id=42",
		"/download?version=2.5.1",
	}
	for _, path := range cases {
		if matched, _, target := isSSRFIndicator(path); matched {
			t.Errorf("expected NO match for ordinary decimal-shaped path %q, got target=%q", path, target)
		}
	}
}

func TestIsSSRFIndicator_EmptyPath_NoMatch(t *testing.T) {
	if matched, _, _ := isSSRFIndicator(""); matched {
		t.Fatalf("expected empty path to never match")
	}
}

func TestIsSSRFIndicator_PercentEncodedTarget(t *testing.T) {
	// "%31%30%2e%30%2e%30%2e%31" percent-decodes to "10.0.0.1".
	matched, _, target := isSSRFIndicator("/fetch?url=http://%31%30%2e%30%2e%30%2e%31/admin")
	if !matched {
		t.Fatalf("expected percent-encoded private-IP target to be caught after decoding")
	}
	if target != "10.0.0.1" {
		t.Fatalf("expected decoded matched target 10.0.0.1, got %q", target)
	}
}

func TestIsSSRFIndicator_MalformedEncoding_NoPanic(t *testing.T) {
	// Malformed percent-encoding must not panic; url.QueryUnescape errors
	// are simply ignored and only the raw form is checked.
	matched, _, _ := isSSRFIndicator("/fetch?url=%zz%gg-not-valid-encoding")
	if matched {
		t.Fatalf("expected malformed-encoding-only path with no reserved target to not match")
	}
}

func TestIsSSRFIndicator_OutOfRangeOctets_NoFalsePositive(t *testing.T) {
	// Regex-shaped like an IPv4 address but with an invalid octet --
	// net.ParseIP must reject it, so this must not match.
	if matched, _, target := isSSRFIndicator("/api?ids=999.888.777.666"); matched {
		t.Errorf("expected out-of-range octet token to NOT parse as a valid IP, got target=%q", target)
	}
}
