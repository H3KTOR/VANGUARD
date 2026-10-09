package detection

import (
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"vanguard/core/internal/database"
	"vanguard/core/internal/hostsec"
)

func metaOf(t *testing.T, inc *database.Incident) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(inc.Metadata), &m); err != nil {
		t.Fatalf("metadata is not valid JSON: %v (%q)", err, inc.Metadata)
	}
	return m
}

func TestEvidence_ProvenanceOnLogDrivenIncident(t *testing.T) {
	e, db := testEngine(t)
	e.IngestWebLogLine(`203.0.113.50 - - [23/Aug/2026:14:03:00 +0000] "GET /../../etc/passwd HTTP/1.1" 403 0 "-" "curl/8.0"`)
	m := metaOf(t, lastIncident(t, db))
	prov, ok := m["provenance"].(map[string]any)
	if !ok {
		t.Fatalf("missing provenance: %v", m)
	}
	if prov["rule_id"] != "path_traversal" || prov["evidence_kind"] != "observed" || prov["rule_revision"] != float64(RuleRevision) {
		t.Errorf("bad provenance: %v", prov)
	}
	if lim, _ := prov["limitations"].(string); !strings.Contains(lim, "not proof") {
		t.Errorf("web detector must state it is an indicator, not proof: %q", lim)
	}
	if _, ok := m["score_breakdown"]; !ok {
		t.Error("score_breakdown must be preserved")
	}
}

func TestEvidence_CorrelatedTypesAreMarkedNotObserved(t *testing.T) {
	for _, typ := range []database.IncidentType{database.IncidentAttackChain, database.IncidentWebAttackChain, database.IncidentHighConfidenceCompromise} {
		var m map[string]any
		_ = json.Unmarshal([]byte(prepareEvidence(typ, map[string]any{"x": 1})), &m)
		if m["provenance"].(map[string]any)["evidence_kind"] != "correlated" {
			t.Errorf("%s must be marked correlated", typ)
		}
	}
}

func TestEvidence_SecretsRedactedBenignFieldsKept(t *testing.T) {
	out := prepareEvidence(database.IncidentConfigurationDrift, map[string]any{
		"resource":       "/etc/app.conf",
		"Password":       "hunter2",
		"auth_token":     "abc",
		"nested":         map[string]any{"Cookie": "sid=1", "port": 22},
		"list":           []any{map[string]any{"api_key": "k"}},
		"session_id":     "s",
		"changed_fields": []string{"content"},
	})
	for _, leaked := range []string{"hunter2", "sid=1", `"abc"`, `"k"`} {
		if strings.Contains(out, leaked) {
			t.Fatalf("secret %q leaked into evidence: %s", leaked, out)
		}
	}
	if !strings.Contains(out, "/etc/app.conf") || !strings.Contains(out, `"port":22`) || !strings.Contains(out, "content") {
		t.Fatalf("benign fields were damaged: %s", out)
	}
}

func TestEvidence_OversizedIsBoundedAndSaysSo(t *testing.T) {
	huge := strings.Repeat("A", 200*1024)
	items := make([]any, 5000)
	for i := range items {
		items[i] = fmt.Sprintf("entry-%d-%s", i, strings.Repeat("x", 50))
	}
	out := prepareEvidence(database.IncidentPortScan, map[string]any{
		"blob": huge, "list": items, "path": "/short", "score_breakdown": map[string]any{"total": 42},
	})
	if len(out) > MaxEvidenceBytes {
		t.Fatalf("evidence not bounded: %d bytes", len(out))
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(out), &m); err != nil {
		t.Fatalf("bounded evidence must remain valid JSON: %v", err)
	}
	if m["evidence_truncated"] != true {
		t.Error("truncation must be explicit")
	}
	if m["path"] != "/short" || m["score_breakdown"] == nil || m["provenance"] == nil {
		t.Errorf("essentials lost: %v", m)
	}
}

func TestEvidence_NilAndUnserializableDoNotCrash(t *testing.T) {
	if out := prepareEvidence(database.IncidentPortScan, nil); !strings.Contains(out, "provenance") {
		t.Errorf("nil meta: %s", out)
	}
	ch := make(chan int)
	if out := prepareEvidence(database.IncidentPortScan, map[string]any{"bad": ch}); !strings.Contains(out, "provenance") {
		t.Errorf("unserializable meta: %s", out)
	}
}

func TestEvidence_HostFindingSecretNeverPersisted(t *testing.T) {
	e, db := testEngine(t)
	e.ReportHostFinding(hostsec.Finding{
		Type: database.IncidentConfigurationDrift, Change: "modified", Subject: "s1",
		Details: map[string]any{"resource": "/etc/x", "password": "pw-secret-value"},
	})
	inc := lastIncident(t, db)
	if strings.Contains(inc.Metadata, "pw-secret-value") {
		t.Fatalf("secret persisted: %s", inc.Metadata)
	}
}

func TestDedupe_BoundedAndReaped(t *testing.T) {
	d := newDedupeWindow(50 * time.Millisecond)
	for i := 0; i < MaxDedupeEntries+500; i++ {
		d.allow(fmt.Sprintf("10.0.%d.%d", i/250, i%250), database.IncidentPortScan)
	}
	if d.Len() > MaxDedupeEntries {
		t.Fatalf("dedupe map exceeded bound: %d", d.Len())
	}
	time.Sleep(80 * time.Millisecond)
	if n := d.Reap(time.Now()); n == 0 || d.Len() != 0 {
		t.Fatalf("expired entries not reaped: removed=%d remaining=%d", n, d.Len())
	}
}

func TestDedupe_SuppressesWithinCooldownAllowsAfter(t *testing.T) {
	d := newDedupeWindow(40 * time.Millisecond)
	if !d.allow("1.1.1.1", database.IncidentPortScan) {
		t.Fatal("first must pass")
	}
	if d.allow("1.1.1.1", database.IncidentPortScan) {
		t.Fatal("repeat inside cooldown must be suppressed")
	}
	if !d.allow("2.2.2.2", database.IncidentPortScan) || !d.allow("1.1.1.1", database.IncidentSSHBruteForce) {
		t.Fatal("different ip / type are independent")
	}
	time.Sleep(60 * time.Millisecond)
	if !d.allow("1.1.1.1", database.IncidentPortScan) {
		t.Fatal("recurrence after cooldown must be allowed (not permanently suppressed)")
	}
}

func TestDedupe_ConcurrentAllowRaceFree(t *testing.T) {
	d := newDedupeWindow(time.Minute)
	var wg sync.WaitGroup
	var mu sync.Mutex
	passed := 0
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if d.allow("9.9.9.9", database.IncidentHTTPFlood) {
				mu.Lock()
				passed++
				mu.Unlock()
			}
			d.Reap(time.Now())
		}()
	}
	wg.Wait()
	if passed != 1 {
		t.Fatalf("exactly one concurrent caller may pass the cooldown, got %d", passed)
	}
}

// --- Detection regression corpus: positives, benign lookalikes, isolation ---

func webLine(ip, path string, status int) string {
	return fmt.Sprintf(`%s - - [23/Aug/2026:14:03:00 +0000] "GET %s HTTP/1.1" %d 10 "-" "Mozilla/5.0"`, ip, path, status)
}

func TestCorpus_WebSignatures(t *testing.T) {
	cases := []struct {
		name string
		path string
		want database.IncidentType // "" => no incident expected
	}{
		{"traversal dotdot", "/../../etc/passwd", database.IncidentPathTraversal},
		{"traversal encoded", "/files/%2e%2e/%2e%2e/etc/shadow", database.IncidentPathTraversal},
		{"traversal double-encoded", "/files/%252e%252e/%252e%252e/boot.ini", database.IncidentPathTraversal},
		{"sqli union percent-encoded", "/item?id=1%20union%20select%201,2", database.IncidentSQLiXSS},
		{"sqli union plus-encoded", "/item?id=1+union+select+1", database.IncidentSQLiXSS},
		{"xss encoded tag", "/search?q=%3Cscript%3Ealert(1)%3C/script%3E", database.IncidentSQLiXSS},
		{"xss script", "/search?q=<script>alert(1)</script>", database.IncidentSQLiXSS},
		{"benign: malformed percent escape", "/search?q=100%+cotton", ""},
		{"benign: ordinary page", "/products/shoes", ""},
		{"benign: word 'select' in slug", "/blog/how-to-select-a-laptop", ""},
		{"benign: dots in filename", "/assets/app.min.v1.2.js", ""},
		{"benign: query with percent-encoded space", "/search?q=red%20shoes", ""},
	}
	for i, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			e, db := testEngine(t)
			ip := fmt.Sprintf("198.51.100.%d", i+1)
			e.IngestWebLogLine(webLine(ip, c.path, 200))
			got := countIncidents(t, db)
			if c.want == "" {
				if got != 0 {
					t.Fatalf("benign lookalike produced %d incident(s): %s", got, lastIncident(t, db).Type)
				}
				return
			}
			// Other lenient single-signal rules (e.g. web-shell path hints)
			// may legitimately co-fire; the contract here is that the
			// intended detector fired.
			incs, _ := db.ListIncidents(database.IncidentFilter{Limit: 50})
			found := false
			for _, inc := range incs {
				if inc.Type == c.want {
					found = true
				}
			}
			if !found {
				t.Fatalf("want a %s incident, got %d incident(s) of other types", c.want, got)
			}
		})
	}
}

func TestCorpus_MalformedInputIgnored(t *testing.T) {
	e, db := testEngine(t)
	for _, l := range []string{"", "garbage", `"GET / HTTP/1.1"`, strings.Repeat("A", 300000), "\x00\x01\x02", `1.2.3.4 - - [bad date] "GET /../../etc/passwd HTTP/1.1" 200 1`} {
		e.IngestWebLogLine(l)
		e.IngestAuthLogLine(l)
	}
	if got := countIncidents(t, db); got > 1 {
		t.Fatalf("malformed input must not fabricate incidents, got %d", got)
	}
}

func TestCorpus_PerIPIsolation(t *testing.T) {
	e, db := testEngine(t)
	// Two different sources each stay below the web-dir-scan threshold;
	// combined they would exceed it, so any cross-IP pooling is a bug.
	half := 5
	for i := 0; i < half; i++ {
		e.IngestWebLogLine(webLine("203.0.113.101", fmt.Sprintf("/wp-admin/x%d", i), 404))
		e.IngestWebLogLine(webLine("203.0.113.102", fmt.Sprintf("/wp-admin/y%d", i), 404))
	}
	if got := countIncidents(t, db); got != 0 {
		t.Fatalf("events from different sources were pooled: %d incident(s)", got)
	}
}

func TestCorpus_DuplicateObservationsDoNotMultiplyIncidents(t *testing.T) {
	e, db := testEngine(t)
	for i := 0; i < 20; i++ {
		e.IngestWebLogLine(webLine("203.0.113.77", "/../../etc/passwd", 403))
	}
	if got := countIncidents(t, db); got != 1 {
		t.Fatalf("repeated identical observations within cooldown produced %d incidents", got)
	}
}
