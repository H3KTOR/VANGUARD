package detection

// Phase 5, Milestone 1: incident evidence hygiene.
//
// Every incident created through createIncident() passes its metadata
// through prepareEvidence(), which (a) stamps detector provenance and an
// observed-vs-correlated marker, (b) redacts values stored under
// secret-looking keys, and (c) bounds the serialized size. The metadata
// schema itself is unchanged: all of this is additive keys inside the
// existing JSON blob, so older incidents and API consumers are unaffected.

import (
	"encoding/json"

	"vanguard/core/internal/database"
	redactpkg "vanguard/core/internal/redact"
)

const (
	// RuleRevision is bumped when a detector's matching semantics change
	// in a way that makes older incidents non-comparable.
	RuleRevision = 1

	// MaxEvidenceBytes bounds the serialized metadata persisted per
	// incident.
	MaxEvidenceBytes = 16 * 1024

	maxEvidenceDepth  = 6
	maxEvidenceString = 1024
	redactedValue     = "[REDACTED]"
)

// sensitiveKeyFragments: any metadata key containing one of these
// (case-insensitive) has its value replaced. Key-name based by design: a
// secret embedded inside a free-text value is NOT detected (documented
// limitation).
var sensitiveKeyFragments = []string{
	"password", "passwd", "secret", "token", "cookie", "authorization",
	"api_key", "apikey", "private_key", "credential", "session_id",
}

// correlatedTypes are incident types inferred by combining several
// observations rather than observed directly in one log line / scan.
var correlatedTypes = map[database.IncidentType]bool{
	database.IncidentAttackChain:              true,
	database.IncidentWebAttackChain:           true,
	database.IncidentHighConfidenceCompromise: true,
}

// limitationFor returns a short, honest statement of what the detector
// can and cannot establish. Empty for types without a specific note.
func limitationFor(t database.IncidentType) string {
	switch t {
	case database.IncidentSSHBruteForce, database.IncidentFailedThenSuccess:
		return "inferred from auth.log lines only; attribution is the logged source address"
	case database.IncidentPortScan, database.IncidentHoneypotTrigger:
		return "based on decoy-port connections; cannot see traffic to real services"
	case database.IncidentWebDirScan, database.IncidentPathTraversal, database.IncidentSQLiXSS,
		database.IncidentHTTPFlood, database.IncidentWebScanner, database.IncidentWebShellIndicator,
		database.IncidentSSRFIndicator, database.IncidentOASTIndicator, database.IncidentHostHeaderAnomaly,
		database.IncidentHTTPProtocolAnomaly, database.IncidentRequestSmugglingIndicator,
		database.IncidentAPIAbuse, database.IncidentPasswordSpraying, database.IncidentCredentialStuffing:
		return "inferred from access-log fields only (no request body, no response content); an indicator, not proof of successful exploitation"
	case database.IncidentAttackChain, database.IncidentWebAttackChain:
		return "correlation of separate indicators from one source within a time window; suggests coordinated activity, does not prove compromise"
	case database.IncidentHighConfidenceCompromise:
		return "process + file/network correlation using best-effort /proc data; strong indicator, not a forensic conclusion"
	case database.IncidentFIMChange, database.IncidentPersistenceDetected, database.IncidentPrivilegeEscalation,
		database.IncidentAccountChange, database.IncidentSUIDSGIDAnomaly, database.IncidentSystemBinaryIntegrity,
		database.IncidentConfigurationDrift, database.IncidentConfigurationPosture,
		database.IncidentListeningServiceDrift, database.IncidentPackageDrift:
		return "periodic scan: changes that appear and revert between scans are not observable, and the actor is not identified; a change is not proof of malice"
	case database.IncidentIOCMatch:
		return "exact match of an observed value against a locally imported indicator: it shows a feed lists the value, not that the host is compromised, who the actor is, or that the indicator is still accurate; shared infrastructure (CDN, proxy, NAT) can make address matches misleading"
	case database.IncidentSuspiciousProcess:
		return "best-effort /proc heuristic; short-lived processes can be missed"
	}
	return ""
}

// evidenceKind classifies how the incident's claim was established.
func evidenceKind(t database.IncidentType) string {
	if correlatedTypes[t] {
		return "correlated"
	}
	return "observed"
}

func isSensitiveKey(k string) bool { return redactpkg.IsSensitiveKey(k) }

// redact returns a deep-copied value with secret-keyed entries replaced
// and long strings truncated. Depth-limited so hostile nesting cannot
// cause deep recursion.
func redact(v any, depth int) any {
	if depth > maxEvidenceDepth {
		return "[TRUNCATED: nesting too deep]"
	}
	switch x := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, val := range x {
			if isSensitiveKey(k) {
				out[k] = redactedValue
				continue
			}
			out[k] = redact(val, depth+1)
		}
		return out
	case []any:
		out := make([]any, len(x))
		for i, val := range x {
			out[i] = redact(val, depth+1)
		}
		return out
	case []string:
		out := make([]any, len(x))
		for i, val := range x {
			out[i] = truncateString(val)
		}
		return out
	case string:
		return truncateString(x)
	default:
		return v
	}
}

func truncateString(s string) string {
	if len(s) <= maxEvidenceString {
		return s
	}
	return s[:maxEvidenceString] + "...(truncated)"
}

// prepareEvidence returns the final JSON metadata for an incident.
func prepareEvidence(itype database.IncidentType, meta map[string]any) string {
	// Round-trip through JSON first so typed values (structs such as
	// risk.Breakdown, maps with non-string keys) become plain
	// map/slice/scalar trees that redact() can walk.
	plain := map[string]any{}
	if b, err := json.Marshal(meta); err == nil {
		_ = json.Unmarshal(b, &plain)
	}
	clean := redact(plain, 0).(map[string]any)

	prov := map[string]any{
		"rule_id":       string(itype),
		"rule_revision": RuleRevision,
		"evidence_kind": evidenceKind(itype),
	}
	if lim := limitationFor(itype); lim != "" {
		prov["limitations"] = lim
	}
	clean["provenance"] = prov

	b, err := json.Marshal(clean)
	if err != nil {
		return `{"provenance":{"rule_id":"` + string(itype) + `"},"evidence_error":"unserializable"}`
	}
	if len(b) <= MaxEvidenceBytes {
		return string(b)
	}

	// Oversized: keep the explanatory essentials and small scalars, drop
	// the rest, and say so explicitly.
	slim := map[string]any{
		"provenance":          prov,
		"evidence_truncated":  true,
		"original_size_bytes": len(b),
	}
	if sb, ok := clean["score_breakdown"]; ok {
		slim["score_breakdown"] = sb
	}
	for k, v := range clean {
		if _, kept := slim[k]; kept {
			continue
		}
		switch s := v.(type) {
		case string:
			if len(s) <= 256 {
				slim[k] = s
			}
		case float64, bool:
			slim[k] = s
		}
	}
	b, err = json.Marshal(slim)
	if err != nil || len(b) > MaxEvidenceBytes {
		return `{"evidence_truncated":true,"provenance":{"rule_id":"` + string(itype) + `"}}`
	}
	return string(b)
}
