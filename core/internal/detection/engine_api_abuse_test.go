package detection

import (
	"fmt"
	"testing"
	"time"

	"vanguard/core/internal/database"
	"vanguard/core/internal/thresholds"
)

func TestAPIAbuse_HighDiversityHighFailureRatio_CreatesIncident(t *testing.T) {
	e, db := testEngine(t)
	ip := "203.0.113.220"
	base := time.Now().UTC()

	n := thresholds.APIAbuseMinDistinctPaths + 5
	for i := 0; i < n; i++ {
		ts := base.Add(time.Duration(i) * time.Millisecond)
		line := formatWebLine(ip, ts, fmt.Sprintf("/api/resource%d", i), 404, "python-requests/2.28")
		e.IngestWebLogLine(line)
	}

	incidents, _ := db.ListIncidents(database.IncidentFilter{SourceIP: ip})
	found := false
	for _, inc := range incidents {
		if inc.Type == database.IncidentAPIAbuse {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected a %s incident, got types: %+v", database.IncidentAPIAbuse, incidentTypes(incidents))
	}
}

func TestAPIAbuse_HighVolumeAllSuccessful_NoIncident(t *testing.T) {
	// False-positive control: a legitimate client (e.g. an SPA's initial
	// load, or a health-check dashboard) hitting many distinct, VALID
	// endpoints must never trigger this.
	e, db := testEngine(t)
	ip := "203.0.113.221"
	base := time.Now().UTC()

	n := thresholds.APIAbuseMinDistinctPaths + 10
	for i := 0; i < n; i++ {
		ts := base.Add(time.Duration(i) * time.Millisecond)
		line := formatWebLine(ip, ts, fmt.Sprintf("/api/resource%d", i), 200, "MyApp/1.0")
		e.IngestWebLogLine(line)
	}

	incidents, _ := db.ListIncidents(database.IncidentFilter{SourceIP: ip})
	for _, inc := range incidents {
		if inc.Type == database.IncidentAPIAbuse {
			t.Fatalf("did not expect an API-abuse incident from a fully-successful high-diversity client")
		}
	}
}

func TestAPIAbuse_LowDiversityHighFailureRatio_NoIncident(t *testing.T) {
	// A repeated 404 against ONE path is ruleWebDirScan's job, not API
	// Abuse -- must not double-fire this rule.
	e, db := testEngine(t)
	ip := "203.0.113.222"
	base := time.Now().UTC()

	for i := 0; i < thresholds.APIAbuseMinDistinctPaths+5; i++ {
		ts := base.Add(time.Duration(i) * time.Millisecond)
		line := formatWebLine(ip, ts, "/api/single-endpoint", 404, "curl/8.0")
		e.IngestWebLogLine(line)
	}

	incidents, _ := db.ListIncidents(database.IncidentFilter{SourceIP: ip})
	for _, inc := range incidents {
		if inc.Type == database.IncidentAPIAbuse {
			t.Fatalf("did not expect an API-abuse incident from low path diversity (single endpoint)")
		}
	}
}

func TestAPIAbuse_BelowDistinctPathThreshold_NoIncident(t *testing.T) {
	e, db := testEngine(t)
	ip := "203.0.113.223"
	base := time.Now().UTC()

	for i := 0; i < thresholds.APIAbuseMinDistinctPaths-1; i++ {
		ts := base.Add(time.Duration(i) * time.Millisecond)
		line := formatWebLine(ip, ts, fmt.Sprintf("/api/resource%d", i), 404, "curl/8.0")
		e.IngestWebLogLine(line)
	}

	incidents, _ := db.ListIncidents(database.IncidentFilter{SourceIP: ip})
	for _, inc := range incidents {
		if inc.Type == database.IncidentAPIAbuse {
			t.Fatalf("did not expect an API-abuse incident below the distinct-path threshold")
		}
	}
}

func TestAPIAbuse_WindowExpiry_OldPathsDoNotCount(t *testing.T) {
	e, db := testEngine(t)
	ip := "203.0.113.224"
	base := time.Now().UTC()

	for i := 0; i < thresholds.APIAbuseMinDistinctPaths-1; i++ {
		line := formatWebLine(ip, base, fmt.Sprintf("/api/old%d", i), 404, "curl/8.0")
		e.IngestWebLogLine(line)
	}
	later := base.Add(thresholds.APIAbuseWindow + time.Second)
	e.IngestWebLogLine(formatWebLine(ip, later, "/api/new", 404, "curl/8.0"))

	incidents, _ := db.ListIncidents(database.IncidentFilter{SourceIP: ip})
	for _, inc := range incidents {
		if inc.Type == database.IncidentAPIAbuse {
			t.Fatalf("did not expect an incident: the old-path batch should have expired out of the window")
		}
	}
}

func TestAPIAbuse_PerIPIsolation(t *testing.T) {
	e, db := testEngine(t)
	base := time.Now().UTC()
	ipA := "203.0.113.225"
	ipB := "203.0.113.226"

	half := thresholds.APIAbuseMinDistinctPaths - 1
	for i := 0; i < half; i++ {
		e.IngestWebLogLine(formatWebLine(ipA, base.Add(time.Duration(i)*time.Millisecond), fmt.Sprintf("/api/a%d", i), 404, "curl"))
	}
	for i := 0; i < half; i++ {
		e.IngestWebLogLine(formatWebLine(ipB, base.Add(time.Duration(i)*time.Millisecond), fmt.Sprintf("/api/b%d", i), 404, "curl"))
	}

	for _, ip := range []string{ipA, ipB} {
		incidents, _ := db.ListIncidents(database.IncidentFilter{SourceIP: ip})
		for _, inc := range incidents {
			if inc.Type == database.IncidentAPIAbuse {
				t.Fatalf("did not expect an API-abuse incident on %s below its own per-IP threshold", ip)
			}
		}
	}
}

func TestAPIAbuse_DedupeSuppressesRepeatIncidents(t *testing.T) {
	e, db := testEngine(t)
	ip := "203.0.113.227"
	base := time.Now().UTC()

	n := thresholds.APIAbuseMinDistinctPaths + 5
	for i := 0; i < n; i++ {
		ts := base.Add(time.Duration(i) * time.Millisecond)
		e.IngestWebLogLine(formatWebLine(ip, ts, fmt.Sprintf("/api/resource%d", i), 404, "curl"))
	}
	firstCount := countIncidentsOfType(t, db, database.IncidentAPIAbuse)
	if firstCount != 1 {
		t.Fatalf("expected exactly 1 incident, got %d", firstCount)
	}

	e.IngestWebLogLine(formatWebLine(ip, base.Add(time.Duration(n+1)*time.Millisecond), "/api/onemore", 404, "curl"))
	secondCount := countIncidentsOfType(t, db, database.IncidentAPIAbuse)
	if secondCount != 1 {
		t.Fatalf("expected dedupe to suppress a duplicate incident, got %d total", secondCount)
	}
}

func TestAPIAbuse_NormalBrowsingTraffic_NoIncident(t *testing.T) {
	// False-positive control: a normal user browsing a handful of pages,
	// all successful, must never trigger this.
	e, db := testEngine(t)
	ip := "203.0.113.228"
	base := time.Now().UTC()

	pages := []string{"/", "/about", "/contact", "/products", "/blog"}
	for i, p := range pages {
		e.IngestWebLogLine(formatWebLine(ip, base.Add(time.Duration(i)*time.Second), p, 200, "Mozilla/5.0"))
	}

	incidents, _ := db.ListIncidents(database.IncidentFilter{SourceIP: ip})
	for _, inc := range incidents {
		if inc.Type == database.IncidentAPIAbuse {
			t.Fatalf("did not expect an API-abuse incident from normal browsing traffic")
		}
	}
}
