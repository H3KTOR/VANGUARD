package detection

import (
	"regexp"
	"strings"

	"vanguard/core/internal/thresholds"
)

// ---------------------------------------------------------------------------
// OAST / Out-of-Band Interaction Indicators (Phase 3, feature 9).
//
// VANGUARD has no DNS resolver log and no outbound packet capture, so it
// can NEVER prove an out-of-band interaction actually completed -- it can
// only observe that an attacker-supplied, callback-shaped hostname
// appeared somewhere in a request's path/query string (the payload for a
// blind SSRF/XXE/RCE probe commonly embeds a Burp Collaborator / OAST
// provider domain so the attacker gets an out-of-band signal when the
// vulnerable code resolves or fetches it). That limitation is restated in
// every finding's Details, never silently assumed away.
//
// Primary signal: isCallbackShapedHostname -- a hostname-shaped token
// whose LEFTMOST DNS label is long (>= thresholds.OASTMinHostnameLabelLength)
// AND looks random (a healthy mix of letters and digits, not a normal
// dictionary-shaped subdomain like "www"/"api"/"static"). Per this
// phase's explicit instruction, detection must NOT rely on
// thresholds.KnownOASTProviderSuffixes as the sole mechanism -- that list
// is used only as a secondary REINFORCEMENT signal that upgrades an
// already-qualifying hostname's confidence, and is never itself
// sufficient to match a hostname whose leftmost label fails the
// length/randomness heuristic (e.g. "www.burpcollaborator.net" alone,
// with a short non-random leftmost label, must NOT match).
// ---------------------------------------------------------------------------

// hostnameTokenRe extracts hostname-shaped tokens (labels of
// letters/digits/hyphens separated by dots, at least two labels) from
// arbitrary path/query text, so a callback domain embedded anywhere in a
// request target (e.g. "?url=http://a1b2c3d4e5f6g7h8.oast.fun/x") can be
// found without a full URL parse.
var hostnameTokenRe = regexp.MustCompile(`[A-Za-z0-9][A-Za-z0-9-]*(?:\.[A-Za-z0-9][A-Za-z0-9-]*)+`)

// isOASTIndicator inspects path for a callback-shaped external hostname.
// Returns matched, a reinforced flag (the qualifying hostname additionally
// matched a thresholds.KnownOASTProviderSuffixes entry, raising
// confidence but never required for a match), and the matched hostname
// for incident evidence.
func isOASTIndicator(path string) (matched bool, reinforced bool, hostname string) {
	if path == "" {
		return false, false, ""
	}
	for _, tok := range hostnameTokenRe.FindAllString(path, -1) {
		if isCallbackShapedHostname(tok) {
			r := hasKnownOASTProviderSuffix(tok)
			// Prefer returning a reinforced match if any candidate token
			// qualifies for reinforcement, but don't lose an earlier
			// unreinforced match if none do.
			if r {
				return true, true, tok
			}
			if !matched {
				matched, hostname = true, tok
			}
		}
	}
	return matched, false, hostname
}

// isCallbackShapedHostname reports whether host's leftmost DNS label is
// long enough and random-looking enough to be a plausible OAST/callback
// token, rather than an ordinary hostname (www, api, cdn, static, ...).
func isCallbackShapedHostname(host string) bool {
	labels := strings.Split(host, ".")
	if len(labels) < 2 {
		return false // not even hostname-shaped
	}
	leftmost := labels[0]
	if len(leftmost) < thresholds.OASTMinHostnameLabelLength {
		return false
	}
	return looksRandom(leftmost)
}

// looksRandom applies a small set of cheap, explainable heuristics to
// distinguish a random-looking token (typical of an auto-generated OAST
// subdomain, e.g. "a1b2c3d4e5f6g7h8") from an ordinary long-but-readable
// hostname label (e.g. "customer-support-portal"). Deliberately NOT a
// full entropy/statistical model -- per the mega-prompt's "no heavy
// computation in the hot path" rule, this stays O(n) single-pass with no
// external dependency.
func looksRandom(s string) bool {
	lower := strings.ToLower(s)

	hasDigit := false
	hasAlpha := false
	hyphens := 0
	for _, c := range lower {
		switch {
		case c >= '0' && c <= '9':
			hasDigit = true
		case c >= 'a' && c <= 'z':
			hasAlpha = true
		case c == '-':
			hyphens++
		}
	}

	// A normal readable hostname label is typically all-alphabetic (or
	// alphabetic with hyphens, like "customer-support-portal") and rarely
	// mixes in digits throughout. A random OAST token is typically
	// alphanumeric (both letters AND digits present) with NO word
	// separators (hyphens) at all -- hyphenated labels are excluded from
	// "random" regardless of digit presence, since real hostnames
	// commonly use hyphens as word separators (e.g. "api-v2-prod").
	if hyphens > 0 {
		return false
	}
	if !hasDigit || !hasAlpha {
		// Pure-digit or pure-alphabetic long labels are more often
		// legitimate (a long alphabetic word, or a long numeric ID) than
		// the specific alphanumeric-mix shape OAST tools generate.
		return false
	}

	// Distinct-character-ratio check: a truly random token uses a wide
	// variety of characters; a label that happens to mix letters/digits
	// but is mostly repeated/patterned characters (e.g.
	// "aaaaaaaaaaaaaaaa1") is less convincing. Require at least roughly
	// half the label's characters to be distinct.
	distinct := make(map[rune]struct{}, len(lower))
	for _, c := range lower {
		distinct[c] = struct{}{}
	}
	return len(distinct)*2 >= len(lower)
}

// hasKnownOASTProviderSuffix reports whether host ends in one of
// thresholds.KnownOASTProviderSuffixes (case-insensitive). Used ONLY as a
// secondary reinforcement signal on top of an already-qualifying
// isCallbackShapedHostname match -- never as the sole detection
// mechanism.
func hasKnownOASTProviderSuffix(host string) bool {
	lower := strings.ToLower(host)
	for _, suffix := range thresholds.KnownOASTProviderSuffixes {
		if strings.HasSuffix(lower, strings.ToLower(suffix)) {
			return true
		}
	}
	return false
}
