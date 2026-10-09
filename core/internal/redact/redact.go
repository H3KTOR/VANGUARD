// Package redact removes secrets from structured metadata and free text
// before it is shown, exported or logged. It is deliberately conservative
// and heuristic: it cannot recognise every secret, so it complements (and
// never replaces) not collecting secrets in the first place.
package redact

import (
	"regexp"
	"strings"
)

const (
	// Mask replaces a redacted value.
	Mask = "[REDACTED]"
	// MaxText bounds the text the regular expressions ever see.
	MaxText  = 64 * 1024
	maxDepth = 8
)

var sensitiveKeyFragments = []string{
	"password", "passwd", "secret", "token", "cookie", "authorization",
	"api_key", "apikey", "private_key", "credential", "session_id",
}

// IsSensitiveKey reports whether a metadata key names a secret.
func IsSensitiveKey(k string) bool {
	lk := strings.ToLower(k)
	for _, f := range sensitiveKeyFragments {
		if strings.Contains(lk, f) {
			return true
		}
	}
	return false
}

var (
	kvRE = regexp.MustCompile(`(?i)\b(password|passwd|pwd|secret|token|api[_-]?key|apikey|authorization|cookie|session[_-]?id|access[_-]?key|private[_-]?key)(["']?\s*[=:]\s*["']?)([^\s"'&;,]+)`)
	// "Authorization: Bearer abc" style: the value is two words.
	bearerRE = regexp.MustCompile(`(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=\-]{6,}`)
	pemRE    = regexp.MustCompile(`(?s)-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?(-----END [A-Z0-9 ]*PRIVATE KEY-----|$)`)
	awsRE    = regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`)
)

// Text redacts secrets in free text (analyst notes, log fragments).
func Text(s string) string {
	if len(s) > MaxText {
		s = s[:MaxText] + "...(truncated)"
	}
	s = pemRE.ReplaceAllString(s, "[REDACTED PRIVATE KEY]")
	s = bearerRE.ReplaceAllString(s, "$1 "+Mask)
	s = kvRE.ReplaceAllString(s, "${1}${2}"+Mask)
	s = awsRE.ReplaceAllString(s, Mask)
	return s
}

// Value returns a deep copy of a decoded-JSON-shaped value (maps, slices,
// scalars) with sensitive keys masked and every string passed through
// Text. Nesting deeper than a fixed limit is cut off.
func Value(v any) any { return value(v, 0) }

func value(v any, depth int) any {
	if depth > maxDepth {
		return "[TRUNCATED: nesting too deep]"
	}
	switch x := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, val := range x {
			if IsSensitiveKey(k) {
				out[k] = Mask
				continue
			}
			out[k] = value(val, depth+1)
		}
		return out
	case []any:
		out := make([]any, len(x))
		for i, val := range x {
			out[i] = value(val, depth+1)
		}
		return out
	case string:
		return Text(x)
	default:
		return v
	}
}
