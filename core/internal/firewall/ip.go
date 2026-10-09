package firewall

import (
	"errors"
	"net/netip"
	"strings"
)

// ErrInvalidIP is returned when a response action is asked to act on anything
// other than one ordinary unicast IP address.
var ErrInvalidIP = errors.New("not a valid single IP address (ranges, CIDRs, hostnames, 'any' and unspecified/multicast addresses are refused)")

// NormalizeIP returns the canonical form of a single unicast IP address.
//
// Why this exists: block/allow targets were passed straight to `ufw`, and the
// fail-safe whitelist compares by exact string. So "0.0.0.0/0", "10.0.0.0/8"
// or "any" would have reached the firewall as one rule (locking out everyone,
// including the administrator) while sailing past the whitelist, which only
// protects an address spelled exactly like the entry. Response safeguards must
// operate on one canonical address, so everything is normalized here: IPv4-
// mapped IPv6 is unmapped, text is trimmed, zones are refused.
func NormalizeIP(s string) (string, error) {
	s = strings.TrimSpace(s)
	if s == "" || len(s) > 45 {
		return "", ErrInvalidIP
	}
	a, err := netip.ParseAddr(s)
	if err != nil || a.Zone() != "" {
		return "", ErrInvalidIP
	}
	a = a.Unmap()
	if !a.IsValid() || a.IsUnspecified() || a.IsMulticast() {
		return "", ErrInvalidIP
	}
	return a.String(), nil
}
