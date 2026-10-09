package api

import (
	"net/http"
	"net/url"
	"sort"
	"strings"
	"testing"

	"vanguard/core/internal/database"
)

type access int

const (
	public    access = iota // no credentials needed
	anyUser                 // any authenticated, active account
	adminOnly               // an authenticated admin
)

// routeTable is the authoritative inventory of the HTTP surface. A route that
// exists but is not listed here fails TestRouteInventoryIsComplete, so adding
// an endpoint forces its authorization expectation to be written down (and
// docs/PHASE13.md to be updated).
//
//	who:     the minimum credential required
//	mutates: changes server or database state
var routeTable = map[string]struct {
	who     access
	mutates bool
}{
	"GET /api/health":                      {public, false},
	"POST /api/auth/login":                 {public, false}, // writes last_login only
	"POST /api/auth/register":              {public, true},  // bootstrap, then admin-only (checked in the handler)
	"GET /api/auth/me":                     {anyUser, false},
	"POST /api/auth/logout":                {anyUser, true},
	"GET /api/auth/sessions":               {anyUser, false},
	"POST /api/auth/sessions/revoke-all":   {anyUser, true},
	"POST /api/users/:id/revoke-sessions":  {adminOnly, true},
	"GET /api/dashboard/summary":           {anyUser, false},
	"GET /api/incidents":                   {anyUser, false},
	"GET /api/incidents/:id":               {anyUser, false},
	"PUT /api/incidents/:id/status":        {anyUser, true}, // analyst triage; audited in incident_events
	"GET /api/incidents/:id/events":        {anyUser, false},
	"GET /api/incidents/:id/timeline":      {anyUser, false},
	"GET /api/incidents/:id/graph":         {anyUser, false},
	"GET /api/incidents/:id/export":        {anyUser, false},
	"GET /api/incidents/:id/notes":         {anyUser, false},
	"POST /api/incidents/:id/notes":        {anyUser, true},
	"PUT /api/incidents/:id/notes/:nid":    {anyUser, true},
	"DELETE /api/incidents/:id/notes/:nid": {anyUser, true},
	"GET /api/incidents/:id/response-plan": {anyUser, false}, // preview only; never executes
	"POST /api/incidents/:id/block":        {adminOnly, true},
	"GET /api/investigate/incidents":       {anyUser, false},
	"GET /api/detectors/status":            {anyUser, false},
	"GET /api/health/runtime":              {anyUser, false},
	"GET /api/backup":                      {adminOnly, false},
	"POST /api/backup":                     {adminOnly, true},
	"GET /api/backup/:name/verify":         {adminOnly, false},
	"GET /api/retention":                   {adminOnly, false},
	"GET /api/audit/admin":                 {adminOnly, false},
	"GET /api/audit/integrity":             {adminOnly, false},
	"GET /api/rules":                       {anyUser, false},
	"GET /api/rules/tuning":                {anyUser, false},
	"POST /api/rules/tuning/preview":       {anyUser, false}, // never mutates
	"PUT /api/rules/tuning":                {adminOnly, true},
	"POST /api/rules/tuning/rollback":      {adminOnly, true},
	"GET /api/rules/guidance":              {anyUser, false},
	"GET /api/intel/status":                {anyUser, false},
	"GET /api/intel/iocs":                  {anyUser, false},
	"GET /api/intel/iocs/:id":              {anyUser, false},
	"PUT /api/intel/iocs/:id":              {adminOnly, true},
	"DELETE /api/intel/iocs/:id":           {adminOnly, true},
	"POST /api/intel/import":               {adminOnly, true},
	"GET /api/intel/imports":               {anyUser, false},
	"GET /api/hunt/matches":                {anyUser, false},
	"GET /api/firewall/rules":              {anyUser, false},
	"POST /api/firewall/block":             {adminOnly, true},
	"POST /api/firewall/unban/:id":         {adminOnly, true},
	"POST /api/firewall/whitelist":         {adminOnly, true},
	"GET /api/firewall/status":             {anyUser, false},
	"GET /api/metrics/latest":              {anyUser, false},
	"GET /api/metrics/history":             {anyUser, false},
	"GET /api/simulate/scenarios":          {anyUser, false},
	"POST /api/simulate/:scenario":         {adminOnly, true},
	"GET /api/panic/preview":               {anyUser, false}, // preview only; never mutates
	"POST /api/panic/enter":                {adminOnly, true},
	"POST /api/panic/exit":                 {adminOnly, true},
	"GET /api/panic/status":                {anyUser, false},
}

func registered(env *secEnv) map[string]bool {
	out := map[string]bool{}
	for _, r := range env.e.Routes() {
		if strings.HasPrefix(r.Path, "/api") && !strings.HasPrefix(r.Method, "echo_") && r.Method != "echo_route_not_found" {
			out[r.Method+" "+r.Path] = true
		}
	}
	return out
}

func TestRouteInventoryIsComplete(t *testing.T) {
	env := newSecEnv(t, nil)
	reg := registered(env)
	var missing, stale []string
	for k := range reg {
		if _, ok := routeTable[k]; !ok {
			missing = append(missing, k)
		}
	}
	for k := range routeTable {
		if !reg[k] {
			stale = append(stale, k)
		}
	}
	sort.Strings(missing)
	sort.Strings(stale)
	if len(missing) > 0 {
		t.Errorf("routes with no documented authorization expectation (add them to routeTable and docs/PHASE13.md): %v", missing)
	}
	if len(stale) > 0 {
		t.Errorf("routeTable lists routes that do not exist: %v", stale)
	}
}

var paramValues = map[string]string{":id": "1", ":nid": "1", ":name": "vanguard-backup-20260101T000000Z", ":scenario": "ssh-bruteforce"}

func concretePath(p string) string {
	for k, v := range paramValues {
		p = strings.ReplaceAll(p, k, v)
	}
	return p
}

func bodyFor(method string) []byte {
	if method == "POST" || method == "PUT" {
		return []byte(`{}`)
	}
	return nil
}

func TestEveryProtectedRoute_RequiresAuthentication(t *testing.T) {
	env := newSecEnv(t, nil)
	for key, spec := range routeTable {
		if spec.who == public {
			continue
		}
		parts := strings.SplitN(key, " ", 2)
		p := concretePath(parts[1])
		for name, tok := range map[string]string{"none": "", "garbage": "x.y.z"} {
			code, _, _ := env.do(req{method: parts[0], path: p, token: tok, body: bodyFor(parts[0])})
			if code != http.StatusUnauthorized {
				t.Errorf("%s with %s token: want 401, got %d", key, name, code)
			}
		}
	}
}

func TestEveryAdminRoute_RefusesViewers_AndChangesNothing(t *testing.T) {
	env := newSecEnv(t, func(s *Server) { s.BackupDir = t.TempDir() })
	state := func() map[string]int64 {
		return map[string]int64{
			"incidents": env.count(&database.Incident{}, ""), "firewall": env.count(&database.FirewallRule{}, ""),
			"iocs": env.count(&database.IOC{}, ""), "audit": env.count(&database.AdminAudit{}, ""),
			"backups": env.count(&database.BackupAudit{}, ""), "users": env.count(&database.User{}, ""),
			"tuning": env.count(&database.RuleTuningRevision{}, ""),
		}
	}
	before := state()
	for key, spec := range routeTable {
		if spec.who != adminOnly {
			continue
		}
		parts := strings.SplitN(key, " ", 2)
		code, _, _ := env.do(req{method: parts[0], path: concretePath(parts[1]), token: env.viewer, body: bodyFor(parts[0])})
		if code != http.StatusForbidden {
			t.Errorf("%s as a viewer: want 403, got %d", key, code)
		}
	}
	after := state()
	for k, v := range before {
		if after[k] != v {
			t.Errorf("a refused admin request changed %s: %d -> %d", k, v, after[k])
		}
	}
	if env.exec.Lockdown || len(env.exec.Blocked) != 0 {
		t.Fatalf("the firewall was touched by a refused request")
	}
}

func TestEveryMutatingRoute_RefusesForeignOrigins(t *testing.T) {
	env := newSecEnv(t, func(s *Server) { s.BackupDir = t.TempDir() })
	for key, spec := range routeTable {
		if !spec.mutates {
			continue
		}
		parts := strings.SplitN(key, " ", 2)
		tok := env.admin
		if spec.who == public {
			tok = ""
		}
		code, _, _ := env.do(req{method: parts[0], path: concretePath(parts[1]), token: tok, body: bodyFor(parts[0]), origin: "https://evil.example"})
		if code != http.StatusForbidden {
			t.Errorf("%s with a foreign Origin: want 403, got %d", key, code)
		}
	}
}

// Hostile path parameters and garbage bodies must produce client errors, never
// a server error, on every route an admin can reach.
func TestEveryRoute_SurvivesHostileInput(t *testing.T) {
	env := newSecEnv(t, func(s *Server) { s.BackupDir = t.TempDir() })
	hostile := []string{"abc", "0", "-1", "99999999999999999999", "%00", "..%2f..%2fetc%2fpasswd", "1;DROP TABLE incidents", strings.Repeat("9", 2000)}
	bodies := [][]byte{nil, []byte(`{}`), []byte(`[]`), []byte(`null`), []byte(`{"ip":123,"duration_minutes":"x","confirmed":"yes"}`), []byte("\x00\xff\xfe"), []byte(`{"a":`)}
	for key := range routeTable {
		parts := strings.SplitN(key, " ", 2)
		switch parts[1] {
		case "/api/panic/enter", "/api/intel/import", "/api/backup", "/api/auth/register", "/api/auth/login":
			continue // exercised with valid-shaped input elsewhere; skipped here to avoid side effects on the shared fixture
		}
		for _, h := range hostile {
			p := parts[1]
			for k := range paramValues {
				p = strings.ReplaceAll(p, k, url.PathEscape(h))
			}
			for _, b := range bodies {
				code, _, _ := env.do(req{method: parts[0], path: p, token: env.admin, body: b})
				if code >= 500 && code != http.StatusServiceUnavailable {
					t.Errorf("%s path=%q body=%q -> %d (server error on hostile input)", key, h, b, code)
				}
			}
		}
	}
}
