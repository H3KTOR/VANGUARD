package intel

import (
	"strings"
	"testing"

	"vanguard/core/internal/database"
)

func TestNormalize_Table(t *testing.T) {
	long := strings.Repeat("a", 64) + ".example.com"
	cases := []struct {
		name string
		typ  database.IOCType
		in   string
		want string // "" => must be rejected
	}{
		// ip
		{"v4", database.IOCIP, "203.0.113.7", "203.0.113.7"},
		{"v4 spaces", database.IOCIP, "  203.0.113.7 ", "203.0.113.7"},
		{"v6 canonical", database.IOCIP, "2001:DB8:0:0:0:0:0:1", "2001:db8::1"},
		{"v4-mapped v6 unmapped", database.IOCIP, "::ffff:203.0.113.7", "203.0.113.7"},
		{"v4 with port rejected", database.IOCIP, "203.0.113.7:80", ""},
		{"v4 cidr rejected", database.IOCIP, "203.0.113.0/24", ""},
		{"v4 leading zeros rejected", database.IOCIP, "203.000.113.007", ""},
		{"zone rejected", database.IOCIP, "fe80::1%eth0", ""},
		{"loopback rejected", database.IOCIP, "127.0.0.1", ""},
		{"v6 loopback rejected", database.IOCIP, "::1", ""},
		{"unspecified rejected", database.IOCIP, "0.0.0.0", ""},
		{"multicast rejected", database.IOCIP, "224.0.0.1", ""},
		{"garbage", database.IOCIP, "not-an-ip", ""},
		// domain
		{"domain lower", database.IOCDomain, "Evil.Example.COM", "evil.example.com"},
		{"domain trailing dot", database.IOCDomain, "evil.example.com.", "evil.example.com"},
		{"domain double dot", database.IOCDomain, "evil..example.com", ""},
		{"domain single label", database.IOCDomain, "localhost", ""},
		{"domain ip-like", database.IOCDomain, "203.0.113.7", ""},
		{"domain unicode rejected", database.IOCDomain, "bücher.example", ""},
		{"domain punycode ok", database.IOCDomain, "xn--bcher-kva.example", "xn--bcher-kva.example"},
		{"domain label too long", database.IOCDomain, long, ""},
		{"domain leading hyphen", database.IOCDomain, "-bad.example.com", ""},
		{"domain with path", database.IOCDomain, "evil.example.com/x", ""},
		{"domain wildcard rejected", database.IOCDomain, "*.example.com", ""},
		// sha256
		{"sha upper", database.IOCSHA256, strings.ToUpper(strings.Repeat("ab", 32)), strings.Repeat("ab", 32)},
		{"sha short", database.IOCSHA256, strings.Repeat("ab", 31), ""},
		{"sha non-hex", database.IOCSHA256, strings.Repeat("zz", 32), ""},
		// url
		{"url basic", database.IOCURL, "HTTP://Evil.Example.com/Path?q=1#frag", "http://evil.example.com/Path?q=1"},
		{"url default port dropped", database.IOCURL, "https://evil.example.com:443/a", "https://evil.example.com/a"},
		{"url custom port kept", database.IOCURL, "http://evil.example.com:8080/a", "http://evil.example.com:8080/a"},
		{"url empty path", database.IOCURL, "http://evil.example.com", "http://evil.example.com/"},
		{"url userinfo rejected", database.IOCURL, "http://user:pass@evil.example.com/", ""},
		{"url ftp rejected", database.IOCURL, "ftp://evil.example.com/", ""},
		{"url javascript rejected", database.IOCURL, "javascript:alert(1)", ""},
		{"url ip host", database.IOCURL, "http://203.0.113.7/x", "http://203.0.113.7/x"},
		{"url v6 host", database.IOCURL, "http://[2001:db8::1]:8080/x", "http://[2001:db8::1]:8080/x"},
		{"url no host", database.IOCURL, "http:///x", ""},
		{"url bad host", database.IOCURL, "http://bad_host!/x", ""},
		// generic
		{"empty", database.IOCIP, "   ", ""},
		{"control char", database.IOCDomain, "evil\n.example.com", ""},
		{"unknown type", database.IOCType("file_path"), "/etc/passwd", ""},
		{"oversized", database.IOCURL, "http://a.example.com/" + strings.Repeat("x", 3000), ""},
	}
	for _, c := range cases {
		got, err := Normalize(c.typ, c.in)
		if c.want == "" {
			if err == nil {
				t.Errorf("%s: %q should be rejected, got %q", c.name, c.in, got)
			}
			continue
		}
		if err != nil || got != c.want {
			t.Errorf("%s: Normalize(%q) = %q, %v; want %q", c.name, c.in, got, err, c.want)
		}
	}
}

func TestNormalize_Idempotent(t *testing.T) {
	for _, c := range []struct {
		t database.IOCType
		v string
	}{
		{database.IOCIP, "::ffff:1.2.3.4"}, {database.IOCDomain, "A.B.C."}, {database.IOCURL, "HTTPS://X.example.com:443/a?b=1#c"},
		{database.IOCSHA256, strings.Repeat("AB", 32)},
	} {
		once, err := Normalize(c.t, c.v)
		if err != nil {
			t.Fatal(err)
		}
		twice, err := Normalize(c.t, once)
		if err != nil || twice != once {
			t.Errorf("not idempotent: %q -> %q -> %q (%v)", c.v, once, twice, err)
		}
	}
}

func TestObservedHelpers(t *testing.T) {
	if v, ok := NormalizeObservedIP("::ffff:203.0.113.7"); !ok || v != "203.0.113.7" {
		t.Errorf("observed mapped v4: %q %v", v, ok)
	}
	if v, ok := NormalizeObservedIP("127.0.0.1"); !ok || v != "127.0.0.1" {
		t.Errorf("observed loopback must still parse (just never match): %q %v", v, ok)
	}
	if _, ok := NormalizeObservedIP("junk"); ok {
		t.Error("junk must not parse")
	}
	if h, ok := ObservedHost("Evil.Example.com:8080"); !ok || h != "evil.example.com" {
		t.Errorf("host: %q %v", h, ok)
	}
	if h, ok := ObservedHost("[2001:db8::1]:8080"); !ok || h != "2001:db8::1" {
		t.Errorf("v6 host: %q %v", h, ok)
	}
	if _, ok := ObservedHost(""); ok {
		t.Error("empty host is not observable")
	}
	if k, ok := ObservedURLKey("Evil.Example.com:80", "/a?b=1"); !ok || k != "evil.example.com/a?b=1" {
		t.Errorf("url key: %q %v", k, ok)
	}
	if _, ok := ObservedURLKey("", "/a"); ok {
		t.Error("no Host => URL not observable")
	}
	n, _ := Normalize(database.IOCURL, "https://evil.example.com/a?b=1")
	if URLMatchKey(n) != "evil.example.com/a?b=1" {
		t.Errorf("match key: %q", URLMatchKey(n))
	}
}
