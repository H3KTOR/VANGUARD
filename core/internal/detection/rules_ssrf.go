package detection

import (
	"net"
	"net/url"
	"regexp"
	"strings"

	"vanguard/core/internal/thresholds"
)

// ---------------------------------------------------------------------------
// SSRF Indicators (Phase 3, feature 8).
//
// VANGUARD's ONLY visibility here is the request's path/query string as it
// appears in the access log line -- request bodies are never logged, so a
// body-based SSRF payload (e.g. a JSON field naming an internal URL) is
// simply invisible to this detector. That limitation is real and is
// restated in the incident evidence, never silently assumed away (see
// IncidentSSRFIndicator's doc comment in internal/database/models.go).
//
// Deliberately NOT naive substring matching against raw text (the
// mega-prompt's own "contextual scoring, not naive substring-only"
// requirement): a blind search for "10." or "192.168." inside a path
// would false-positive constantly on ordinary decimal values (prices,
// version numbers, coordinates, ...). Instead:
//
//  1. ipv4TokenRe extracts only strings SHAPED like a complete dotted-quad
//     IPv4 address (four dot-separated 1-3 digit groups) -- a decimal like
//     "10.99" or a two-segment version "10.4" can never match, since it
//     lacks the full four-octet shape.
//  2. Each candidate token is validated with net.ParseIP (rejects
//     out-of-range octets a naive regex alone would accept, e.g.
//     "999.1.1.1"), then classified with the standard library's own
//     IsLoopback/IsPrivate/IsLinkLocalUnicast -- the exact same
//     battle-tested logic Feature 10 (Host Header Abuse) already uses via
//     hostIsLoopbackOrPrivate, applied here to IPv4 tokens found inside a
//     path/query rather than to a Host header value.
//  3. A small, explicit set of non-IP-literal reserved hostnames
//     (localhost, metadata.google.internal) and the IPv6 loopback
//     shorthand (::1) are checked separately, since they are not
//     dotted-quad IPv4 tokens the regex above can find.
//  4. The path/query is checked BOTH in its raw (as-logged) form and after
//     a best-effort url.QueryUnescape, so a percent-encoded target (e.g.
//     "%31%30%2e%30%2e%30%2e%31" for "10.0.0.1") is still caught, without
//     requiring a full URL-parser round-trip that could itself panic or
//     silently swallow a malformed-but-still-evidential value.
//
// A single matching request is enough to raise a (conservative,
// MEDIUM-base) incident -- unlike the sustained-rate detectors elsewhere
// in this phase, one instance of "a client asked this app to fetch an
// internal/reserved address" is itself worth a look, though VANGUARD
// still cannot confirm the backend actually issued the resulting request.
// A hit against a cloud-metadata endpoint specifically (the highest-value,
// zero-legitimate-use-case target) escalates the score, exactly as an
// IP-literal/loopback Host escalates Feature 10.
// ---------------------------------------------------------------------------

// ipv4TokenRe matches strings shaped like a complete IPv4 dotted-quad
// address: four 1-3 digit groups separated by dots, bounded so it doesn't
// match a fragment of a longer decimal run (e.g. it will not match the
// "1.2.3" prefix of "1.2.3.4.5" as a 4-octet token starting at position 0,
// since the trailing ".5" would make the boundary check fail; it will
// instead match "2.3.4.5"). Deliberately does NOT validate octet ranges
// itself (regex range-checking on 3-digit groups is unreadable) -- that is
// net.ParseIP's job immediately after extraction.
var ipv4TokenRe = regexp.MustCompile(`(?:[0-9]{1,3}\.){3}[0-9]{1,3}`)

// ssrfReservedHostnames are non-IP-literal target strings that always
// indicate a reserved/internal destination, checked as case-insensitive
// substrings since they cannot be found by the IPv4 regex above.
var ssrfReservedHostnames = []string{"localhost", "metadata.google.internal"}

// isSSRFIndicator inspects ev.Path (which, per WebLogParser, already
// includes any query string logged as part of the request-line target)
// for a reference to a loopback, private, link-local, or cloud-metadata
// address. Returns matched (any reserved-target reference found),
// metadataHit (specifically a cloud-metadata endpoint -- the escalation
// trigger), and matchedTarget (the specific value found, for incident
// evidence).
func isSSRFIndicator(path string) (matched bool, metadataHit bool, matchedTarget string) {
	if path == "" {
		return false, false, ""
	}

	candidates := []string{path}
	if decoded, err := url.QueryUnescape(path); err == nil && decoded != path {
		candidates = append(candidates, decoded)
	}

	for _, candidate := range candidates {
		lower := strings.ToLower(candidate)

		// Explicit non-IP-literal reserved hostnames.
		for _, name := range ssrfReservedHostnames {
			if strings.Contains(lower, name) {
				if isSSRFMetadataTarget(name) {
					return true, true, name
				}
				matched = true
				if matchedTarget == "" {
					matchedTarget = name
				}
			}
		}
		// IPv6 loopback shorthand -- checked as a literal substring (not
		// via net.ParseIP token extraction, since "::1" can appear in
		// bracketed-URL form amid other punctuation the IPv4 regex above
		// does not attempt to parse).
		if strings.Contains(candidate, "::1") {
			matched = true
			if matchedTarget == "" {
				matchedTarget = "::1"
			}
		}

		for _, tok := range ipv4TokenRe.FindAllString(candidate, -1) {
			ip := net.ParseIP(tok)
			if ip == nil {
				continue // regex-shaped but not a valid IPv4 (e.g. octet > 255)
			}
			if !ip.IsLoopback() && !ip.IsPrivate() && !ip.IsLinkLocalUnicast() {
				continue
			}
			if isSSRFMetadataTarget(tok) {
				return true, true, tok
			}
			matched = true
			if matchedTarget == "" {
				matchedTarget = tok
			}
		}
	}

	return matched, false, matchedTarget
}

// isSSRFMetadataTarget reports whether target (an IP literal or hostname
// already known to be reserved/private) is specifically one of the
// highest-confidence cloud-metadata endpoints that escalate the incident.
func isSSRFMetadataTarget(target string) bool {
	lower := strings.ToLower(target)
	for _, endpoint := range thresholds.SSRFMetadataEndpoints {
		if lower == strings.ToLower(endpoint) {
			return true
		}
	}
	return false
}
