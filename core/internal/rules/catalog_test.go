package rules

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"vanguard/core/internal/database"
	"vanguard/core/internal/risk"
	"vanguard/core/internal/tuning"
)

func baseCtx() Context {
	return Context{Tuning: tuning.Defaults(), HostSecurity: true, SystemPosture: true, Intel: true, Honeypot: true, MinRiskToBan: 60, AutopilotActive: true}
}

// The inventory must cover EVERY incident type declared in the code, so a
// new detector cannot be added without appearing here.
func TestInventoryCoversEveryDeclaredIncidentType(t *testing.T) {
	src, err := os.ReadFile(filepath.Join("..", "database", "models.go"))
	if err != nil {
		t.Fatal(err)
	}
	re := regexp.MustCompile(`Incident\w+\s+IncidentType\s*=\s*"([a-z_0-9]+)"`)
	declared := map[string]bool{}
	for _, m := range re.FindAllStringSubmatch(string(src), -1) {
		declared[m[1]] = true
	}
	if len(declared) < 30 {
		t.Fatalf("parsed only %d incident types; the pattern is stale", len(declared))
	}
	have := map[string]Rule{}
	for _, r := range Build(baseCtx()) {
		if _, dup := have[r.ID]; dup {
			t.Errorf("duplicate rule id %s", r.ID)
		}
		have[r.ID] = r
	}
	for id := range declared {
		if _, ok := have[id]; !ok {
			t.Errorf("incident type %q has no inventory entry", id)
		}
	}
	for id := range have {
		if !declared[id] {
			t.Errorf("inventory lists %q which is not a declared incident type", id)
		}
	}
}

func TestInventoryIsGroundedInTheImplementation(t *testing.T) {
	for _, r := range Build(baseCtx()) {
		if r.BaseSeverity != risk.BaseSeverity[database.IncidentType(r.ID)] || r.BaseSeverity == 0 {
			t.Errorf("%s base severity %d does not match the scoring table", r.ID, r.BaseSeverity)
		}
		if r.Description == "" || r.Category == "" || len(r.Prerequisites) == 0 {
			t.Errorf("%s is missing description/category/prerequisites", r.ID)
		}
		if r.CanDisable {
			t.Errorf("%s claims it can be disabled individually, which no code path supports", r.ID)
		}
		wantKind := "observed"
		if database.IsCorrelatedType(database.IncidentType(r.ID)) {
			wantKind = "correlated"
		}
		if r.EvidenceKind != wantKind {
			t.Errorf("%s evidence kind %s", r.ID, r.EvidenceKind)
		}
		if strings.TrimSpace(r.AutoResponse.Note) == "" {
			t.Errorf("%s has no automated-response statement", r.ID)
		}
		for _, s := range r.Settings {
			if s.Source == "" {
				t.Errorf("%s/%s has unknown provenance presented as known", r.ID, s.Name)
			}
		}
	}
}

func TestSettingsProvenanceAndTunability(t *testing.T) {
	c := baseCtx()
	byID := map[string]Rule{}
	for _, r := range Build(c) {
		byID[r.ID] = r
	}
	ssh := byID["ssh_bruteforce"]
	var tunable, fixed int
	for _, s := range ssh.Settings {
		if s.Tunable {
			tunable++
			if s.Source != "compiled default" {
				t.Errorf("revision 0 must report compiled default, got %q", s.Source)
			}
		} else {
			fixed++
		}
	}
	if tunable != 1 || fixed != 1 {
		t.Fatalf("ssh settings: %+v", ssh.Settings)
	}
	c.Tuning.SSHBruteForceMinAttempts, c.TuningRevision = 7, 3
	for _, r := range Build(c) {
		if r.ID == "ssh_bruteforce" {
			s := r.Settings[0]
			if s.Value != 7 || s.Source != "operator tuning revision 3" {
				t.Fatalf("effective value/provenance wrong: %+v", s)
			}
		}
		if r.ID == "attack_chain" {
			for _, s := range r.Settings {
				if s.Tunable || s.Source != "compiled default" {
					t.Errorf("untunable settings must say compiled default: %+v", s)
				}
			}
		}
	}
}

func TestEnabledStateReflectsStartupFlags(t *testing.T) {
	c := baseCtx()
	c.HostSecurity, c.Intel, c.Honeypot = false, false, false
	for _, r := range Build(c) {
		switch r.ID {
		case "fim_change", "config_drift", "ioc_match", "honeypot_trigger":
			if r.Enabled || r.DisabledBy == "" {
				t.Errorf("%s must be reported disabled with the controlling flag", r.ID)
			}
		case "ssh_bruteforce", "http_flood":
			if !r.Enabled {
				t.Errorf("%s is log-driven and must stay enabled", r.ID)
			}
		}
	}
}

func TestAutomatedResponseStatementsAreHonest(t *testing.T) {
	byID := map[string]Rule{}
	for _, r := range Build(baseCtx()) {
		byID[r.ID] = r
	}
	if byID["ioc_match"].AutoResponse.Possible || byID["fim_change"].AutoResponse.Possible || byID["configuration_drift"].AutoResponse.Possible {
		t.Error("IOC-only and host-local rules can never be auto-blocked")
	}
	if !byID["ssh_bruteforce"].AutoResponse.Possible || !byID["honeypot_trigger"].AutoResponse.Possible {
		t.Error("high-severity network rules can reach the threshold in principle")
	}
	if !strings.Contains(byID["ssh_bruteforce"].AutoResponse.Note, "in principle") {
		t.Error("must be framed as an upper bound, not a prediction")
	}
	c := baseCtx()
	c.AutopilotActive = false
	for _, r := range Build(c) {
		if r.AutoResponse.Possible {
			t.Errorf("%s: nothing is auto-blocked while Autopilot is disabled", r.ID)
		}
	}
}

func TestGuidanceIsDescriptiveAndEvidenceGated(t *testing.T) {
	db, err := database.Open(database.Config{Path: filepath.Join(t.TempDir(), "g.db")})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { s, _ := db.DB.DB(); s.Close() }()
	now := time.Now().UTC()
	mk := func(typ database.IncidentType, n, fp int) {
		for i := 0; i < n; i++ {
			st := database.StatusOpen
			if i < fp {
				st = database.StatusFalsePositive
			}
			inc := &database.Incident{Type: typ, SourceIP: "203.0.113.1", RiskScore: 50, DetectedAt: now.Add(-time.Hour), Status: st}
			if err := db.CreateIncident(inc); err != nil {
				t.Fatal(err)
			}
		}
	}
	mk(database.IncidentSSHBruteForce, 30, 20) // lots of analyst false positives
	mk(database.IncidentPortScan, 30, 2)       // healthy
	mk(database.IncidentHTTPFlood, 5, 5)       // too little data
	gs, err := BuildGuidance(db, tuning.Defaults(), now)
	if err != nil {
		t.Fatal(err)
	}
	by := map[string]Guidance{}
	for _, g := range gs {
		by[g.RuleID] = g
	}
	if !strings.Contains(by["ssh_bruteforce"].Recommendation, "review this threshold") || !strings.Contains(by["ssh_bruteforce"].Recommendation, "Suggestion only") {
		t.Errorf("%q", by["ssh_bruteforce"].Recommendation)
	}
	if !strings.Contains(by["port_scan"].Recommendation, "No tuning suggested") {
		t.Errorf("%q", by["port_scan"].Recommendation)
	}
	if !strings.Contains(by["http_flood"].Recommendation, "Insufficient evidence") {
		t.Errorf("5 incidents is not enough to suggest anything: %q", by["http_flood"].Recommendation)
	}
	for _, g := range gs {
		if strings.Contains(strings.ToLower(g.Recommendation), "precision") || strings.Contains(g.Recommendation, "%") {
			t.Errorf("no accuracy metrics may be claimed: %q", g.Recommendation)
		}
		if !strings.Contains(g.Basis, "not precision, recall") {
			t.Error("basis must disclaim accuracy metrics")
		}
	}
}
