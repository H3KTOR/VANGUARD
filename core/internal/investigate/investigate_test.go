package investigate

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"vanguard/core/internal/database"
	"vanguard/core/internal/firewall"
)

var t0 = time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)

func fileDB(t *testing.T) (*database.DB, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "inv.db")
	db, err := database.Open(database.Config{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { closeDB(db) })
	return db, path
}

func closeDB(db *database.DB) {
	if s, err := db.DB.DB(); err == nil {
		s.Close()
	}
}

func mkInc(t *testing.T, db *database.DB, typ database.IncidentType, ip string, at time.Time, meta string) *database.Incident {
	t.Helper()
	inc := &database.Incident{Type: typ, SourceIP: ip, RiskScore: 50, DetectedAt: at, Metadata: meta}
	if err := db.CreateIncident(inc); err != nil {
		t.Fatal(err)
	}
	return inc
}

func ev(t *testing.T, db *database.DB, id uint, kind, outcome string, at time.Time) {
	t.Helper()
	if err := db.AddIncidentEvent(database.IncidentEvent{IncidentID: id, Kind: kind, Outcome: outcome, Actor: "autopilot", At: at}); err != nil {
		t.Fatal(err)
	}
}

func match(t *testing.T, db *database.DB, iocID, incID uint, kind string, at time.Time, ctxVal string) {
	t.Helper()
	if err := db.RecordIOCMatch(&database.IOCMatch{IOCID: iocID, IncidentID: incID, MatchedAt: at, IOCType: database.IOCIP, Source: "s", Field: "source_ip", Context: ctxVal, SourceIP: "203.0.113.1", Kind: kind}); err != nil {
		t.Fatal(err)
	}
}

func refs(es []Entry) []string {
	var out []string
	for _, e := range es {
		out = append(out, e.Ref)
	}
	return out
}

const provMeta = `{"provenance":{"rule_id":"port_scan","rule_revision":1,"evidence_kind":"observed","limitations":"based on decoy-port connections"}}`

func TestTimeline_OrderTieBreakAndUTC(t *testing.T) {
	db, _ := fileDB(t)
	inc := mkInc(t, db, database.IncidentPortScan, "203.0.113.1", t0, provMeta)
	loc := time.FixedZone("UTC+3", 3*3600)
	// all four land on the same instant, written in different zones
	same := t0.Add(time.Minute)
	ev(t, db, inc.ID, database.EventVerification, "verified", same.In(loc))
	ev(t, db, inc.ID, database.EventResponse, "succeeded", same.In(loc))
	match(t, db, 7, inc.ID, "direct", same, "203.0.113.1")
	// and one strictly earlier than detection (clock skew / late write)
	ev(t, db, inc.ID, database.EventResponse, "not_eligible", t0.Add(-time.Hour))

	tl, err := BuildTimeline(db, inc, 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	var kinds []string
	for _, e := range tl.Entries {
		if !e.At.Equal(e.At.UTC()) || e.At.Location() != time.UTC {
			t.Fatalf("entry not normalized to UTC: %v", e.At)
		}
		kinds = append(kinds, e.Kind+":"+e.Provenance)
	}
	want := []string{
		"response:response",     // t0-1h
		"detection:observed",    // t0
		"ioc_match:observed",    // same instant, rank 1
		"response:response",     // same instant, rank 2
		"verification:response", // same instant, rank 3
	}
	if strings.Join(kinds, ",") != strings.Join(want, ",") {
		t.Fatalf("order = %v\nwant    %v", kinds, want)
	}
	// determinism: identical on repeat
	tl2, _ := BuildTimeline(db, inc, 0, 100)
	if strings.Join(refs(tl.Entries), ",") != strings.Join(refs(tl2.Entries), ",") {
		t.Fatal("timeline is not deterministic")
	}
}

func TestTimeline_NoFabricationAndHonestGaps(t *testing.T) {
	db, _ := fileDB(t)
	legacy := mkInc(t, db, database.IncidentSSHBruteForce, "203.0.113.2", t0, "") // pre-provenance, empty metadata
	tl, err := BuildTimeline(db, legacy, 0, 50)
	if err != nil {
		t.Fatal(err)
	}
	if len(tl.Entries) != 1 || tl.Entries[0].Kind != "detection" {
		t.Fatalf("only the persisted detection may appear, got %v", refs(tl.Entries))
	}
	gaps := strings.Join(tl.DataGaps, " | ")
	for _, want := range []string{"predates evidence provenance", "Raw events and log lines are not retained", "Scanner-health history is not persisted", "absence of a retained record"} {
		if !strings.Contains(gaps, want) {
			t.Errorf("missing data gap %q in %q", want, gaps)
		}
	}
	chain := mkInc(t, db, database.IncidentAttackChain, "203.0.113.3", t0, provMeta)
	tl, _ = BuildTimeline(db, chain, 0, 50)
	if tl.Entries[0].Provenance != ProvCorrelated || !strings.Contains(strings.Join(tl.DataGaps, " "), "constituent observations") {
		t.Fatalf("correlated incident must be labelled and its missing constituents disclosed: %+v %v", tl.Entries[0], tl.DataGaps)
	}
	host := mkInc(t, db, database.IncidentFIMChange, database.HostLocalIP, t0, provMeta)
	tl, _ = BuildTimeline(db, host, 0, 50)
	if !strings.Contains(strings.Join(tl.DataGaps, " "), "Host-local finding") {
		t.Fatal("host-local sentinel must be disclosed")
	}
}

func TestTimeline_PaginationBounds(t *testing.T) {
	db, _ := fileDB(t)
	inc := mkInc(t, db, database.IncidentPortScan, "203.0.113.4", t0, provMeta)
	for i := 0; i < 30; i++ {
		ev(t, db, inc.ID, database.EventResponse, "succeeded", t0.Add(time.Duration(i+1)*time.Second))
	}
	all, _ := BuildTimeline(db, inc, 0, 200)
	if all.Total != 31 || len(all.Entries) != 31 {
		t.Fatalf("total=%d len=%d", all.Total, len(all.Entries))
	}
	p1, _ := BuildTimeline(db, inc, 0, 10)
	p2, _ := BuildTimeline(db, inc, 10, 10)
	if len(p1.Entries) != 10 || len(p2.Entries) != 10 || p1.Entries[9].Ref == p2.Entries[0].Ref {
		t.Fatal("pages must be disjoint and sized")
	}
	if strings.Join(refs(append(append([]Entry{}, p1.Entries...), p2.Entries...)), ",") != strings.Join(refs(all.Entries[:20]), ",") {
		t.Fatal("pagination must be a stable slice of the full order")
	}
	far, _ := BuildTimeline(db, inc, 5000, 10)
	if len(far.Entries) != 0 || far.Total != 31 {
		t.Fatalf("offset past end: %+v", far)
	}
	huge, _ := BuildTimeline(db, inc, -5, 100000)
	if huge.Limit > MaxTimelinePage || huge.Offset != 0 {
		t.Fatalf("limits not clamped: %+v", huge)
	}
}

func TestTimeline_PerSourceCapIsDisclosed(t *testing.T) {
	db, _ := fileDB(t)
	inc := mkInc(t, db, database.IncidentPortScan, "203.0.113.5", t0, provMeta)
	for i := 0; i < perSourceCap+20; i++ {
		match(t, db, uint(i+1), inc.ID, "direct", t0.Add(time.Duration(i)*time.Second), "203.0.113.5")
	}
	tl, _ := BuildTimeline(db, inc, 0, 200)
	if !strings.Contains(strings.Join(tl.DataGaps, " "), "indicator matches") {
		t.Fatalf("truncation must be disclosed: %v", tl.DataGaps)
	}
}

func TestTimeline_VerificationFailureAndAnalystActionVisible(t *testing.T) {
	db, _ := fileDB(t)
	exec := firewall.NewMockExecutor()
	exec.NoEffect = true
	ap := firewall.NewAutopilot(db, exec, firewall.DefaultConfig())
	inc := &database.Incident{Type: database.IncidentSSHBruteForce, SourceIP: "203.0.113.6", RiskScore: 80, DetectedAt: t0}
	_ = db.CreateIncident(inc)
	_ = ap.HandleIncident(context.Background(), inc)
	_, _ = db.TransitionIncident(inc.ID, database.StatusInvestigating, "analyst@x", "looking")
	tl, _ := BuildTimeline(db, inc, 0, 100)
	var sawFail, sawAnalyst, sawRule bool
	for _, e := range tl.Entries {
		if e.Kind == "verification" && e.Summary == "Verification failed" {
			sawFail = true
		}
		if e.Kind == "status_change" && e.Provenance == ProvAnalyst {
			sawAnalyst = true
		}
		if e.Kind == "ban_rule" {
			sawRule = true
			if !strings.Contains(e.Summary, "scheduled, not an observed event") {
				t.Error("ban expiry must be described as scheduled")
			}
		}
	}
	if !sawFail || !sawAnalyst || !sawRule {
		t.Fatalf("fail=%v analyst=%v rule=%v entries=%v", sawFail, sawAnalyst, sawRule, refs(tl.Entries))
	}
}

func TestGraph_OnlyExplicitReferences(t *testing.T) {
	db, _ := fileDB(t)
	a := mkInc(t, db, database.IncidentPortScan, "203.0.113.10", t0, provMeta)
	b := mkInc(t, db, database.IncidentWebDirScan, "203.0.113.11", t0.Add(time.Second), provMeta) // shares indicator 1
	c := mkInc(t, db, database.IncidentSQLiXSS, "203.0.113.10", t0.Add(2*time.Second), provMeta)  // same IP, same moment, NO shared indicator
	d := mkInc(t, db, database.IncidentHTTPFlood, "203.0.113.12", t0, provMeta)                   // nothing in common
	_, _, _ = c, d, b
	match(t, db, 1, a.ID, "direct", t0, "203.0.113.10")
	match(t, db, 1, a.ID, "direct", t0.Add(time.Second), "203.0.113.10") // duplicate reference
	match(t, db, 1, b.ID, "enrichment", t0, "203.0.113.10")
	match(t, db, 2, a.ID, "enrichment", t0, "evil.example.com")

	g, err := BuildGraph(db, a)
	if err != nil {
		t.Fatal(err)
	}
	rel := map[string]int{}
	nodes := map[string]bool{}
	for _, n := range g.Nodes {
		nodes[n.ID] = true
	}
	for _, e := range g.Edges {
		rel[e.Relation]++
		if e.Ref == "" || e.Meaning == "" {
			t.Errorf("every edge needs a stored reference and a meaning: %+v", e)
		}
		if !nodes[e.From] || !nodes[e.To] {
			t.Errorf("dangling edge %+v", e)
		}
	}
	if rel["matched"] != 1 || rel["matched_context"] != 1 || rel["shares_indicator"] != 1 {
		t.Fatalf("edges = %v", rel)
	}
	if nodes[fmt.Sprintf("incident:%d", c.ID)] || nodes[fmt.Sprintf("incident:%d", d.ID)] {
		t.Fatal("incidents joined only by IP/time proximity must NOT appear")
	}
	for _, e := range g.Edges {
		if e.Relation == "shares_indicator" && !strings.Contains(e.Meaning, "does not establish the same actor") {
			t.Error("shares_indicator must disclaim same-actor")
		}
	}
}

func TestGraph_ResponseRuleAndFanOutBound(t *testing.T) {
	db, _ := fileDB(t)
	a := mkInc(t, db, database.IncidentPortScan, "203.0.113.20", t0, provMeta)
	idp := a.ID
	_ = db.CreateFirewallRule(&database.FirewallRule{IPAddress: "203.0.113.20", Source: database.FirewallSourceAutopilot, IsActive: true, IncidentID: &idp, BannedAt: t0})
	for i := 0; i < 80; i++ {
		o := mkInc(t, db, database.IncidentWebDirScan, fmt.Sprintf("198.51.100.%d", i+1), t0, provMeta)
		match(t, db, 1, o.ID, "direct", t0, "x")
	}
	match(t, db, 1, a.ID, "direct", t0, "x")
	g, _ := BuildGraph(db, a)
	if len(g.Nodes) > maxGraphNodes {
		t.Fatalf("node cap exceeded: %d", len(g.Nodes))
	}
	if !g.Truncated {
		t.Error("truncation must be flagged")
	}
	var resp bool
	for _, e := range g.Edges {
		if e.Relation == "triggered_response" {
			resp = true
		}
	}
	if !resp {
		t.Fatal("response edge missing")
	}
}

func TestQuery_FiltersBoundsAndWindow(t *testing.T) {
	db, _ := fileDB(t)
	now := t0.Add(48 * time.Hour)
	recent := mkInc(t, db, database.IncidentPortScan, "203.0.113.30", now.Add(-time.Hour), provMeta)
	old := mkInc(t, db, database.IncidentPortScan, "203.0.113.31", now.Add(-90*24*time.Hour), provMeta)
	chain := mkInc(t, db, database.IncidentAttackChain, "203.0.113.30", now.Add(-2*time.Hour), provMeta)
	ev(t, db, recent.ID, database.EventResponse, "succeeded", now)
	ev(t, db, recent.ID, database.EventVerification, "failed", now)
	match(t, db, 5, chain.ID, "direct", now, "203.0.113.30")

	// default window excludes the 90-day-old incident and says so
	r, _ := Query(db, Filter{}, now)
	if !r.WindowDefaulted || r.Count != 2 {
		t.Fatalf("default window: %+v", r)
	}
	// an explicit id scopes the query beyond the default window
	r, _ = Query(db, Filter{ID: old.ID}, now)
	if r.WindowDefaulted || r.Count != 1 {
		t.Fatalf("id scope: %+v", r)
	}
	yes := true
	cases := map[string]struct {
		f    Filter
		want int
	}{
		"rule":                {Filter{Rule: database.IncidentPortScan}, 1},
		"rule injection":      {Filter{Rule: "port_scan' OR '1'='1"}, 0},
		"ip":                  {Filter{SourceIP: "203.0.113.30"}, 2},
		"evidence correlated": {Filter{EvidenceKind: "correlated"}, 1},
		"evidence observed":   {Filter{EvidenceKind: "observed"}, 1},
		"ioc id":              {Filter{IOCID: 5}, 1},
		"ioc id other":        {Filter{IOCID: 6}, 0},
		"has ioc":             {Filter{HasIOCMatch: &yes}, 1},
		"response succeeded":  {Filter{ResponseOutcome: "succeeded"}, 1},
		"verification failed": {Filter{VerificationOutcome: "failed"}, 1},
		"verification ok":     {Filter{VerificationOutcome: "verified"}, 0},
	}
	for name, c := range cases {
		got, err := Query(db, c.f, now)
		if err != nil || got.Count != c.want {
			t.Errorf("%s: count=%d err=%v want %d", name, got.Count, err, c.want)
		}
	}
	lo, hi := 60, 40
	if g, _ := Query(db, Filter{RiskMin: &lo}, now); g.Count != 0 {
		t.Error("risk_min above every score should return nothing")
	}
	if g, _ := Query(db, Filter{RiskMax: &hi}, now); g.Count != 0 {
		t.Error("risk_max below every score should return nothing")
	}
	// empty result is explained, never null
	e, _ := Query(db, Filter{ID: 424242}, now)
	if e.Incidents == nil || len(e.RetentionNotes) == 0 || !strings.Contains(e.RetentionNotes[0], "not that nothing happened") {
		t.Fatalf("empty result must carry retention notes: %+v", e)
	}
	// pagination clamps
	for i := 0; i < 5; i++ {
		mkInc(t, db, database.IncidentHTTPFlood, "203.0.113.40", now.Add(-time.Duration(i)*time.Minute), provMeta)
	}
	p, _ := Query(db, Filter{SourceIP: "203.0.113.40", Limit: 2}, now)
	p2, _ := Query(db, Filter{SourceIP: "203.0.113.40", Limit: 2, Offset: 2}, now)
	if p.Count != 2 || p2.Count != 2 || p.Incidents[0].ID == p2.Incidents[0].ID {
		t.Fatalf("pagination: %v %v", p.Count, p2.Count)
	}
	if h, _ := Query(db, Filter{SourceIP: "203.0.113.40", Limit: 99999, Offset: 99999999}, now); h.Limit > MaxQueryLimit || h.Offset > MaxQueryOffset {
		t.Fatalf("not clamped: %+v", h)
	}
}

func TestExport_RedactionRoundTripAndDeterminism(t *testing.T) {
	db, _ := fileDB(t)
	meta := `{"provenance":{"rule_id":"configuration_drift","evidence_kind":"observed"},"resource":"/etc/app.conf","nested":{"Password":"hunter2","note":"token=abc123xyz leaked in text"},"list":[{"api_key":"k-secret"}]}`
	inc := mkInc(t, db, database.IncidentConfigurationDrift, database.HostLocalIP, t0, meta)
	other := mkInc(t, db, database.IncidentPortScan, "203.0.113.50", t0, provMeta) // unrelated: must not be exported
	_ = other
	if _, err := db.AddIncidentNote(inc.ID, "analyst@example.com", "Checked. The admin pasted password=Sup3rSecret and Authorization: Bearer abcdefghijkl into the ticket."); err != nil {
		t.Fatal(err)
	}
	b1, ex, err := BuildExport(db, inc, t0)
	if err != nil {
		t.Fatal(err)
	}
	b2, _, _ := BuildExport(db, inc, t0)
	if string(b1) != string(b2) {
		t.Fatal("export is not deterministic")
	}
	for _, leak := range []string{"hunter2", "abc123xyz", "k-secret", "Sup3rSecret", "abcdefghijkl"} {
		if strings.Contains(string(b1), leak) {
			t.Errorf("secret %q leaked into export", leak)
		}
	}
	if strings.Contains(string(b1), "203.0.113.50") {
		t.Error("unrelated incident leaked into export")
	}
	// round trip
	var back Export
	if err := json.Unmarshal(b1, &back); err != nil {
		t.Fatalf("export is not valid JSON: %v", err)
	}
	if back.Format != ExportFormat || back.Version != ExportVersion || back.Incident["id"] != float64(inc.ID) || len(back.Timeline) != len(ex.Timeline) {
		t.Fatalf("round trip mismatch: %+v", back.Incident)
	}
	if !strings.Contains(back.Disclaimer, "not cryptographically signed") {
		t.Error("export must disclaim integrity")
	}
	if len(back.Notes) != 1 || back.Notes[0].Author != "analyst@example.com" || !strings.Contains(back.Notes[0].Text, "Checked.") {
		t.Errorf("notes: %+v", back.Notes)
	}
	md := back.Incident["metadata"].(map[string]any)
	if md["resource"] != "/etc/app.conf" {
		t.Error("benign metadata must survive redaction")
	}
}

func TestExport_SizeLimitEnforced(t *testing.T) {
	db, _ := fileDB(t)
	var sb strings.Builder
	sb.WriteString(`{"provenance":{"rule_id":"port_scan"}`)
	for i := 0; i < 60; i++ { // 60 values x 60 KiB (each under the per-value redaction cap) = ~3.6 MB
		fmt.Fprintf(&sb, `,"k%d":"%s"`, i, strings.Repeat("A", 60*1024))
	}
	sb.WriteString("}")
	huge := sb.String()
	inc := mkInc(t, db, database.IncidentPortScan, "203.0.113.60", t0, huge)
	for i := 0; i < 150; i++ {
		ev(t, db, inc.ID, database.EventResponse, "succeeded", t0.Add(time.Duration(i)*time.Second))
	}
	b, ex, err := BuildExport(db, inc, t0)
	if err != nil {
		t.Fatal(err)
	}
	if len(b) > MaxExportBytes {
		t.Fatalf("export %d bytes exceeds the %d cap", len(b), MaxExportBytes)
	}
	if !ex.Truncated || !strings.Contains(strings.Join(ex.DataGaps, " "), "size limit") && !strings.Contains(string(b), "too large for export") {
		t.Fatalf("truncation must be explicit: truncated=%v gaps=%v", ex.Truncated, ex.DataGaps)
	}
	if !json.Valid(b) {
		t.Fatal("truncated export must still be valid JSON")
	}
}

func TestNotes_AuthorLimitsAuditSoftDeleteAndIsolation(t *testing.T) {
	db, _ := fileDB(t)
	inc := mkInc(t, db, database.IncidentPortScan, "203.0.113.70", t0, provMeta)
	before := inc.Metadata
	riskBefore := inc.RiskScore

	if _, err := db.AddIncidentNote(inc.ID, "  ", "x"); err != database.ErrNoAuthor {
		t.Errorf("no author must be refused (never fabricated): %v", err)
	}
	if _, err := db.AddIncidentNote(inc.ID, "a@x", "   "); err != database.ErrNoteEmpty {
		t.Errorf("empty: %v", err)
	}
	if _, err := db.AddIncidentNote(inc.ID, "a@x", strings.Repeat("é", database.MaxNoteLen+1)); err != database.ErrNoteTooLong {
		t.Errorf("too long: %v", err)
	}
	if _, err := db.AddIncidentNote(99999, "a@x", "hi"); err == nil {
		t.Error("unknown incident must fail")
	}
	n, err := db.AddIncidentNote(inc.ID, "a@x", "line1\nline2\x00\x1b[31m<script>alert(1)</script>")
	if err != nil || strings.ContainsAny(n.Text, "\x00\x1b") || !strings.Contains(n.Text, "line1\nline2") {
		t.Fatalf("sanitize: %+v %v", n, err)
	}
	if _, err := db.UpdateIncidentNote(inc.ID, n.ID, "b@x", "revised-text-xyz"); err != nil {
		t.Fatal(err)
	}
	if err := db.DeleteIncidentNote(inc.ID, n.ID, "b@x"); err != nil {
		t.Fatal(err)
	}
	if live, _ := db.ListIncidentNotes(inc.ID); len(live) != 0 {
		t.Fatal("deleted note must be hidden")
	}
	var raw database.IncidentNote
	if err := db.First(&raw, n.ID).Error; err != nil || !raw.Deleted || raw.EditedBy != "b@x" || raw.DeletedBy != "b@x" {
		t.Fatalf("soft delete must keep the row and who/when: %+v %v", raw, err)
	}
	evs, _ := db.ListIncidentEvents(inc.ID)
	var outcomes []string
	for _, e := range evs {
		if e.Kind == database.EventNote {
			outcomes = append(outcomes, e.Outcome)
			if strings.Contains(e.Detail, "line1") || strings.Contains(e.Detail, "revised-text-xyz") {
				t.Errorf("audit event must not copy note text: %q", e.Detail)
			}
		}
	}
	if strings.Join(outcomes, ",") != "created,edited,deleted" {
		t.Fatalf("audit trail: %v", outcomes)
	}
	// notes never touch detector evidence or risk
	cur, _ := db.GetIncident(inc.ID)
	if cur.Metadata != before || cur.RiskScore != riskBefore || cur.Status != database.StatusOpen {
		t.Fatal("notes must not alter evidence, risk or status")
	}
	// per-incident cap counts live notes only
	for i := 0; i < database.MaxNotesPerIncident; i++ {
		if _, err := db.AddIncidentNote(inc.ID, "a@x", "n"); err != nil {
			t.Fatalf("note %d: %v", i, err)
		}
	}
	if _, err := db.AddIncidentNote(inc.ID, "a@x", "one too many"); err != database.ErrNoteLimit {
		t.Fatalf("cap: %v", err)
	}
}

func TestRestartAndLegacyDatabase(t *testing.T) {
	db, path := fileDB(t)
	inc := mkInc(t, db, database.IncidentPortScan, "203.0.113.80", t0, provMeta)
	_, _ = db.AddIncidentNote(inc.ID, "a@x", "persist me")
	ev(t, db, inc.ID, database.EventResponse, "failed", t0)
	closeDB(db)

	db2, err := database.Open(database.Config{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	defer closeDB(db2)
	tl, _ := BuildTimeline(db2, inc, 0, 100)
	var note, resp bool
	for _, e := range tl.Entries {
		note = note || e.Kind == "note"
		resp = resp || (e.Kind == "response" && e.Summary == "Response failed")
	}
	if !note || !resp {
		t.Fatalf("history lost across restart: %v", refs(tl.Entries))
	}

	// Legacy: a database created before Phase 7 has no incident_notes table.
	_ = db2.Migrator().DropTable(&database.IncidentNote{})
	closeDB(db2)
	db3, err := database.Open(database.Config{Path: path})
	if err != nil {
		t.Fatalf("legacy open: %v", err)
	}
	defer closeDB(db3)
	tl, err = BuildTimeline(db3, inc, 0, 100)
	if err != nil || tl.Total < 2 {
		t.Fatalf("legacy timeline: %v %v", err, tl)
	}
	if _, err := db3.AddIncidentNote(inc.ID, "a@x", "works after migration"); err != nil {
		t.Fatal(err)
	}
}
