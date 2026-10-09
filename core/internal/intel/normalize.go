// Package intel implements VANGUARD's local, offline threat-intelligence
// layer (Phase 6): indicator normalization, bounded import of a versioned
// feed format, and an exact-match engine over a lock-free snapshot.
//
// Imported data is inert: it is parsed, validated and stored as text. It
// is never executed, never fetched, and never used as configuration.
package intel

import (
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"strings"

	"vanguard/core/internal/database"
)

// Normalize validates raw and returns the canonical stored form for the
// given indicator type. Two raw values denote the same indicator iff their
// normalized forms are equal.
//
//	ip     canonical netip text; IPv4-mapped IPv6 (::ffff:a.b.c.d) is
//	       unmapped to plain IPv4; zones are rejected; unspecified,
//	       multicast and loopback addresses are rejected (an "indicator"
//	       that matches the host itself would be a self-inflicted alarm)
//	domain lowercase ASCII, one trailing dot removed, LDH labels (1-63),
//	       total <=253, at least two labels; non-ASCII must be punycode
//	url    http/https only; host lowercased with default port dropped;
//	       fragment dropped; userinfo REJECTED (it can carry credentials);
//	       path and query kept byte-exact; <=2048 chars
//	sha256 64 hex chars, lowercased
func Normalize(t database.IOCType, raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", errors.New("empty value")
	}
	if len(raw) > database.MaxIOCValueLen {
		return "", fmt.Errorf("value longer than %d bytes", database.MaxIOCValueLen)
	}
	for _, r := range raw {
		if r < 0x20 || r == 0x7f {
			return "", errors.New("control character in value")
		}
	}
	switch t {
	case database.IOCIP:
		return normalizeIP(raw)
	case database.IOCDomain:
		return normalizeDomain(raw)
	case database.IOCURL:
		return normalizeURL(raw)
	case database.IOCSHA256:
		return normalizeSHA256(raw)
	}
	return "", fmt.Errorf("unsupported indicator type %q", t)
}

// NormalizeObservedIP canonicalizes an address seen in logs so it can be
// compared with stored IP indicators. ok=false for anything unparsable.
func NormalizeObservedIP(raw string) (string, bool) {
	v, err := normalizeIPLoose(strings.TrimSpace(raw), false)
	return v, err == nil
}

func normalizeIP(raw string) (string, error) { return normalizeIPLoose(raw, true) }

func normalizeIPLoose(raw string, strictRanges bool) (string, error) {
	a, err := netip.ParseAddr(raw)
	if err != nil {
		return "", fmt.Errorf("invalid IP address %q", truncateForErr(raw))
	}
	if a.Zone() != "" {
		return "", errors.New("IPv6 zones are not allowed")
	}
	a = a.Unmap()
	if strictRanges && (a.IsUnspecified() || a.IsMulticast() || a.IsLoopback()) {
		return "", errors.New("unspecified, multicast and loopback addresses are not valid indicators")
	}
	return a.String(), nil
}

func normalizeDomain(raw string) (string, error) {
	d := strings.ToLower(raw)
	d = strings.TrimSuffix(d, ".")
	return validateHost(d)
}

// validateHost enforces LDH labels on an already-lowercased host.
func validateHost(d string) (string, error) {
	if d == "" || len(d) > 253 {
		return "", errors.New("invalid domain length")
	}
	if _, err := netip.ParseAddr(d); err == nil {
		return "", errors.New("an IP address is not a domain; use type ip")
	}
	labels := strings.Split(d, ".")
	if len(labels) < 2 {
		return "", errors.New("domain needs at least two labels")
	}
	for _, l := range labels {
		if l == "" || len(l) > 63 {
			return "", errors.New("invalid domain label length")
		}
		if l[0] == '-' || l[len(l)-1] == '-' {
			return "", errors.New("domain label may not start or end with '-'")
		}
		for i := 0; i < len(l); i++ {
			c := l[i]
			ok := (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_'
			if !ok {
				return "", errors.New("domain must be ASCII letters, digits, '-' (use punycode for IDN)")
			}
		}
	}
	return d, nil
}

func normalizeSHA256(raw string) (string, error) {
	h := strings.ToLower(raw)
	if len(h) != 64 {
		return "", errors.New("sha256 must be 64 hex characters")
	}
	for i := 0; i < len(h); i++ {
		c := h[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return "", errors.New("sha256 must be hexadecimal")
		}
	}
	return h, nil
}

func normalizeURL(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", errors.New("unparsable URL")
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return "", errors.New("only http and https URLs are supported")
	}
	if u.User != nil {
		return "", errors.New("URLs with userinfo (credentials) are rejected")
	}
	host := strings.ToLower(strings.TrimSuffix(u.Hostname(), "."))
	if host == "" {
		return "", errors.New("URL has no host")
	}
	if a, perr := netip.ParseAddr(host); perr == nil {
		host = a.Unmap().String()
		if a.Zone() != "" {
			return "", errors.New("IPv6 zones are not allowed")
		}
	} else if _, derr := validateHost(host); derr != nil {
		return "", fmt.Errorf("URL host: %v", derr)
	}
	port := u.Port()
	if (scheme == "http" && port == "80") || (scheme == "https" && port == "443") {
		port = ""
	}
	hostport := host
	if strings.Contains(host, ":") {
		hostport = "[" + host + "]"
	}
	if port != "" {
		hostport += ":" + port
	}
	path := u.EscapedPath()
	if path == "" {
		path = "/"
	}
	out := scheme + "://" + hostport + path
	if u.RawQuery != "" {
		out += "?" + u.RawQuery
	}
	if len(out) > database.MaxIOCValueLen {
		return "", errors.New("normalized URL too long")
	}
	return out, nil
}

// URLMatchKey derives the scheme-less key used to match an indicator URL
// against an observed request: access logs record neither scheme nor
// (by default) host, so matching is on host[:port]+path[?query].
func URLMatchKey(normalizedURL string) string {
	if i := strings.Index(normalizedURL, "://"); i >= 0 {
		return normalizedURL[i+3:]
	}
	return normalizedURL
}

// ObservedURLKey builds the comparable key for an observed request from
// the logged Host header and request target. Returns ok=false when the log
// source does not record Host (the request is then simply not observable
// for URL/domain matching -- never "clean").
func ObservedURLKey(host, target string) (key string, ok bool) {
	h := strings.ToLower(strings.TrimSpace(host))
	if h == "" || target == "" || target[0] != '/' {
		return "", false
	}
	// Drop default ports so "example.com:80" equals the indicator
	// "http://example.com/..." after URLMatchKey (which also drops them).
	h = strings.TrimSuffix(h, ".")
	if strings.HasSuffix(h, ":80") || strings.HasSuffix(h, ":443") {
		h = h[:strings.LastIndexByte(h, ':')]
	}
	// Strip a fragment (never sent, but be safe) and keep path+query as logged.
	if i := strings.IndexByte(target, '#'); i >= 0 {
		target = target[:i]
	}
	return h + target, true
}

// ObservedHost normalizes a logged Host header for exact domain matching
// (port stripped, lowercase, trailing dot removed).
func ObservedHost(host string) (string, bool) {
	h := strings.ToLower(strings.TrimSpace(host))
	if h == "" {
		return "", false
	}
	if strings.HasPrefix(h, "[") { // [::1]:8080
		if i := strings.Index(h, "]"); i > 0 {
			h = h[1:i]
		}
	} else if i := strings.LastIndexByte(h, ':'); i >= 0 && strings.Count(h, ":") == 1 {
		h = h[:i]
	}
	h = strings.TrimSuffix(h, ".")
	if h == "" || len(h) > 253 {
		return "", false
	}
	return h, true
}

func truncateForErr(s string) string {
	if len(s) > 64 {
		return s[:64] + "..."
	}
	return s
}
