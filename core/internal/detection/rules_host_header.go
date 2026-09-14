package detection

import (
	"net"
	"strings"

	"vanguard/core/internal/thresholds"
)

// ---------------------------------------------------------------------------
// Host Header / Virtual Host Abuse (Phase 3, feature 10).
//
// Only runs when ev.Host is non-empty -- the stock Nginx/Apache "combined"
// access-log format does NOT log the Host header at all (see
// parser_web.go), so most deployments will simply never populate this
// field, and an empty Host must never itself be treated as suspicious
// (see Event.Host's doc comment in events.go). Three independent signals,
// none of which requires ExpectedHosts to be configured:
//
//  1. hostLooksLikeIPLiteral: the client sent a raw IP address (or
//     bracketed IPv6 literal) as Host instead of a hostname -- unusual
//     for legitimate browser/API traffic, common for a scanner probing
//     by IP directly.
//  2. hostIsLoopbackOrPrivate: the Host value itself names a loopback or
//     RFC1918 address -- suggests an attempt to reach an internal vhost
//     or bypass a reverse-proxy's routing.
//  3. Host enumeration: many DISTINCT Host values from one source IP in
//     a short window (virtual-host probing), independent of whether any
//     single value looked suspicious.
//
// A fourth check (does Host match thresholds.ExpectedHosts) only runs
// when an operator has actually configured that allowlist -- otherwise
// it is silently skipped, per ExpectedHosts' doc comment.
// ---------------------------------------------------------------------------

// hostNameOnly strips an optional trailing ":port" from host (handling
// both plain "host:port" and bracketed IPv6 "[::1]:port" forms via the
// standard library) and returns just the host/address portion.
func hostNameOnly(host string) string {
	if h, _, err := net.SplitHostPort(host); err == nil {
		return h
	}
	// No port suffix present (net.SplitHostPort failed) -- still need to
	// strip a bare bracket pair around an unported IPv6 literal, e.g.
	// "[::1]" (no port at all).
	return strings.TrimPrefix(strings.TrimSuffix(host, "]"), "[")
}

// hostLooksLikeIPLiteral reports whether host names a raw IP address
// rather than a hostname.
func hostLooksLikeIPLiteral(host string) bool {
	return net.ParseIP(hostNameOnly(host)) != nil
}

// hostIsLoopbackOrPrivate reports whether host names a loopback,
// RFC1918, or link-local private address (or the literal "localhost").
func hostIsLoopbackOrPrivate(host string) bool {
	h := hostNameOnly(host)
	if strings.EqualFold(h, "localhost") {
		return true
	}
	ip := net.ParseIP(h)
	if ip == nil {
		return false
	}
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast()
}

// hostMatchesExpected reports whether host matches one of
// thresholds.ExpectedHosts exactly (case-insensitive, port-stripped). If
// ExpectedHosts is empty, this check is considered inapplicable
// (applicable=false) and callers must skip it -- "no configured
// allowlist" must never itself be treated as suspicious.
func hostMatchesExpected(host string) (applicable bool, matches bool) {
	if len(thresholds.ExpectedHosts) == 0 {
		return false, false
	}
	h := strings.ToLower(hostNameOnly(host))
	for _, expected := range thresholds.ExpectedHosts {
		if strings.ToLower(expected) == h {
			return true, true
		}
	}
	return true, false
}
