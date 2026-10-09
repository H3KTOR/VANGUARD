package api

import (
	"bytes"
	"net/http"
	"strings"
	"testing"
	"time"

	"vanguard/core/internal/database"
	"vanguard/core/internal/intel"
)

// ---------------------------------------------------------------------------
// Browser / network boundary
// ---------------------------------------------------------------------------

func TestHostHeader_RejectsUnknownNames_AllowsLoopbackIPsAndConfigured(t *testing.T) {
	env := newSecEnv(t, func(s *Server) { s.Security.AllowedHosts = []string{"Dash.Example.Test"} })
	for host, want := range map[string]int{
		"evil.example":        http.StatusForbidden, // DNS-rebinding style name
		"evil.example:8080":   http.StatusForbidden,
		"127.0.0.1:8080":      200,
		"localhost":           200,
		"localhost:8080":      200,
		"[::1]:8080":          200,
		"10.1.2.3":            200,
		"dash.example.test":   200, // configured, case-insensitive
		"dash.example.test:1": 200,
		"":                    http.StatusForbidden,
	} {
		code, _, _ := env.do(req{method: "GET", path: "/api/health", host: host, headers: nil})
		if host == "" {
			continue // httptest cannot send an empty Host; covered by hostAllowed below
		}
		if code != want {
			t.Errorf("Host %q: got %d want %d", host, code, want)
		}
	}
	if env.srv.hostAllowed("") {
		t.Error("an empty Host must be refused")
	}
	if env.srv.sec.hostRejected.Load() == 0 {
		t.Error("rejections must be counted")
	}
	open := newSecEnv(t, func(s *Server) { s.Security.AllowedHosts = []string{"*"} })
	if code, _, _ := open.do(req{method: "GET", path: "/api/health", host: "anything.example"}); code != 200 {
		t.Errorf("explicit * disables the check, got %d", code)
	}
}

func TestCORS_NoWildcard_ExplicitAllowListOnly(t *testing.T) {
	env := newSecEnv(t, nil)
	_, _, h := env.do(req{method: "GET", path: "/api/health", origin: "https://evil.example"})
	if h.Get("Access-Control-Allow-Origin") != "" {
		t.Fatalf("no CORS grant may be issued by default, got %q", h.Get("Access-Control-Allow-Origin"))
	}
	env2 := newSecEnv(t, func(s *Server) { s.Security.AllowedOrigins = []string{"https://ops.example.test"} })
	_, _, h = env2.do(req{method: "GET", path: "/api/health", origin: "https://ops.example.test"})
	if h.Get("Access-Control-Allow-Origin") != "https://ops.example.test" {
		t.Fatalf("configured origin should be echoed exactly, got %q", h.Get("Access-Control-Allow-Origin"))
	}
	_, _, h = env2.do(req{method: "GET", path: "/api/health", origin: "https://evil.example"})
	if h.Get("Access-Control-Allow-Origin") != "" {
		t.Fatalf("unlisted origin must not be granted, got %q", h.Get("Access-Control-Allow-Origin"))
	}
}

func TestCrossOriginWrites_AreRefusedAndChangeNothing(t *testing.T) {
	env := newSecEnv(t, func(s *Server) { s.Security.AllowedOrigins = []string{"https://ops.example.test"} })
	body := jsonBody(map[string]any{"ip": "203.0.113.44"})
	before := env.count(&database.FirewallRule{}, "")
	if code, _, _ := env.do(req{method: "POST", path: "/api/firewall/block", token: env.admin, body: body, origin: "https://evil.example"}); code != http.StatusForbidden {
		t.Fatalf("foreign origin: %d", code)
	}
	if env.count(&database.FirewallRule{}, "") != before || env.exec.Blocked["203.0.113.44"] {
		t.Fatal("a refused cross-origin request changed state")
	}
	// same origin (Origin host equals Host) and configured origin pass; no Origin (curl) passes
	for name, o := range map[string]string{"same-origin": "http://127.0.0.1:8080", "configured": "https://ops.example.test", "none": ""} {
		ip := map[string]string{"same-origin": "203.0.113.45", "configured": "203.0.113.46", "none": "203.0.113.47"}[name]
		if code, _, _ := env.do(req{method: "POST", path: "/api/firewall/block", token: env.admin, body: jsonBody(map[string]any{"ip": ip}), origin: o}); code != 200 {
			t.Errorf("%s: %d", name, code)
		}
	}
	if env.srv.sec.originRejected.Load() != 1 {
		t.Errorf("origin rejections: %d", env.srv.sec.originRejected.Load())
	}
}

func TestSecurityHeaders(t *testing.T) {
	env := newSecEnv(t, nil)
	_, _, h := env.do(req{method: "GET", path: "/api/health"})
	if h.Get("X-Content-Type-Options") != "nosniff" || h.Get("X-Frame-Options") != "DENY" || h.Get("Referrer-Policy") != "no-referrer" || h.Get("Cache-Control") != "no-store" {
		t.Fatalf("headers: %v", h)
	}
}

func TestBodyLimits(t *testing.T) {
	env := newSecEnv(t, nil)
	big := bytes.Repeat([]byte("a"), MaxBodyBytes+1)
	creds := append([]byte(`{"email":"x@example.test","password":"`), big...)
	creds = append(creds, []byte(`"}`)...)
	if code, _, _ := env.do(req{method: "POST", path: "/api/auth/login", body: creds}); code != http.StatusRequestEntityTooLarge {
		t.Fatalf("declared oversize body: %d", code)
	}
	// undeclared length (chunked) bodies are cut off by the reader limit
	before := env.count(&database.FirewallRule{}, "")
	chunked := append([]byte(`{"ip":"203.0.113.50","reason":"`), bytes.Repeat([]byte("r"), MaxBodyBytes+10)...)
	chunked = append(chunked, []byte(`"}`)...)
	code, _, _ := env.do(req{method: "POST", path: "/api/firewall/block", token: env.admin, body: chunked, chunked: true})
	if code < 400 || code >= 500 {
		t.Fatalf("oversize chunked body should be a 4xx, got %d", code)
	}
	if env.count(&database.FirewallRule{}, "") != before {
		t.Fatal("an oversize body changed state")
	}
	// the import route has its own, larger bound
	feed := bytes.Repeat([]byte("x"), intel.MaxImportBytes+importBodySlack+1)
	if code, _, _ := env.do(req{method: "POST", path: "/api/intel/import", token: env.admin, body: feed}); code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversize import: %d", code)
	}
	small := []byte("not a feed")
	if code, _, _ := env.do(req{method: "POST", path: "/api/intel/import", token: env.admin, body: small}); code == http.StatusRequestEntityTooLarge {
		t.Fatalf("a small import body must not be rejected for size: %d", code)
	}
}

// ---------------------------------------------------------------------------
// Response safeguards
// ---------------------------------------------------------------------------

func TestManualBlock_RefusesRangesAndNeverTouchesFirewall(t *testing.T) {
	env := newSecEnv(t, nil)
	for _, ip := range []string{"any", "0.0.0.0/0", "::/0", "10.0.0.0/8", "203.0.113.0/24", "", "example.com", "-h", "0.0.0.0", "203.0.113.999"} {
		code, _, _ := env.do(req{method: "POST", path: "/api/firewall/block", token: env.admin, body: jsonBody(map[string]any{"ip": ip})})
		if code != http.StatusBadRequest {
			t.Errorf("ip %q: want 400, got %d", ip, code)
		}
	}
	if len(env.exec.Blocked) != 0 || env.count(&database.FirewallRule{}, "is_whitelisted = 0") != 0 {
		t.Fatalf("a refused target reached the firewall layer: %v", env.exec.Blocked)
	}
	for _, d := range []int{-1, maxBanMinutes + 1, 1 << 40} {
		code, _, _ := env.do(req{method: "POST", path: "/api/firewall/block", token: env.admin, body: jsonBody(map[string]any{"ip": "203.0.113.60", "duration_minutes": d})})
		if code != http.StatusBadRequest {
			t.Errorf("duration %d: want 400, got %d", d, code)
		}
	}
	// the boundary values are accepted
	for i, d := range []int{1, maxBanMinutes} {
		ip := []string{"203.0.113.61", "203.0.113.62"}[i]
		if code, _, _ := env.do(req{method: "POST", path: "/api/firewall/block", token: env.admin, body: jsonBody(map[string]any{"ip": ip, "duration_minutes": d})}); code != 200 {
			t.Errorf("duration %d should be accepted, got %d", d, code)
		}
	}
	if code, _, _ := env.do(req{method: "POST", path: "/api/firewall/block", token: env.admin, body: []byte(`{"ip":`)}); code != http.StatusBadRequest {
		t.Errorf("malformed JSON: %d", code)
	}
}

func TestManualBlock_WhitelistStillWins_AndOutcomeIsAudited(t *testing.T) {
	env := newSecEnv(t, nil)
	if code, _, _ := env.do(req{method: "POST", path: "/api/firewall/whitelist", token: env.admin, body: jsonBody(map[string]any{"ip": "203.0.113.70", "reason": "ops\nwith newline"})}); code != 200 {
		t.Fatalf("whitelist: %d", code)
	}
	if a := env.lastAudit("firewall.whitelist"); a == nil || a.Result != auditOK || a.Target != "203.0.113.70" || a.Actor != "admin@example.test" {
		t.Fatalf("whitelist audit: %+v", a)
	}
	var wl database.FirewallRule
	env.db.Where("ip_address = ? AND is_whitelisted = 1", "203.0.113.70").First(&wl)
	if strings.ContainsAny(wl.Reason, "\n\r") {
		t.Fatalf("control characters must not reach stored reasons: %q", wl.Reason)
	}
	// every spelling of the protected address is refused, nothing is blocked, and the refusal is audited
	for _, spelled := range []string{"203.0.113.70", " 203.0.113.70 ", "::ffff:203.0.113.70"} {
		code, _, _ := env.do(req{method: "POST", path: "/api/firewall/block", token: env.admin, body: jsonBody(map[string]any{"ip": spelled})})
		if code != http.StatusConflict {
			t.Errorf("%q: want 409, got %d", spelled, code)
		}
	}
	if env.exec.Blocked["203.0.113.70"] {
		t.Fatal("the whitelist was bypassed")
	}
	if a := env.lastAudit("firewall.block"); a == nil || a.Result != auditRefused {
		t.Fatalf("refusal must be audited as refused: %+v", a)
	}
	// a range cannot be whitelisted either
	if code, _, _ := env.do(req{method: "POST", path: "/api/firewall/whitelist", token: env.admin, body: jsonBody(map[string]any{"ip": "0.0.0.0/0"})}); code != http.StatusBadRequest {
		t.Fatalf("range whitelist: %d", code)
	}
}

func TestReasons_AreBoundedAndSanitized(t *testing.T) {
	env := newSecEnv(t, nil)
	long := strings.Repeat("é", 500) + "\x00\x1b[31m\nINJECTED"
	if code, _, _ := env.do(req{method: "POST", path: "/api/firewall/block", token: env.admin, body: jsonBody(map[string]any{"ip": "203.0.113.80", "reason": long})}); code != 200 {
		t.Fatal(code)
	}
	var r database.FirewallRule
	env.db.Where("ip_address = ?", "203.0.113.80").First(&r)
	if len(r.Reason) > maxReasonLength+len(" by admin@example.test") || strings.ContainsAny(r.Reason, "\x00\x1b\n\r") {
		t.Fatalf("reason not bounded/sanitized (%d bytes): %q", len(r.Reason), r.Reason)
	}
	if got := cleanReason("ab\xc3", 3); got != "ab" && got != "ab\xc3" {
		t.Fatalf("unexpected cut: %q", got)
	}
}

func TestPanicMode_UsesThePeerAddressNotForwardedHeaders(t *testing.T) {
	env := newSecEnv(t, nil)
	_, body, _ := env.do(req{method: "GET", path: "/api/panic/preview", token: env.admin, remote: "198.51.100.7:4444",
		headers: map[string]string{"X-Forwarded-For": "203.0.113.99", "X-Real-IP": "203.0.113.98"}})
	b, _ := jsonBodyString(body)
	if strings.Contains(b, "203.0.113.99") || strings.Contains(b, "203.0.113.98") {
		t.Fatalf("a forged header reached the lockdown allow-list: %s", b)
	}
	if !strings.Contains(b, "198.51.100.7") {
		t.Fatalf("the real peer should be kept reachable: %s", b)
	}
	// entering requires confirmation, and the audit records the outcome
	if code, _, _ := env.do(req{method: "POST", path: "/api/panic/enter", token: env.admin, body: jsonBody(map[string]any{"reason": "x"})}); code != http.StatusBadRequest {
		t.Fatalf("unconfirmed panic mode: %d", code)
	}
	if env.exec.Lockdown {
		t.Fatal("lockdown applied without confirmation")
	}
	if code, _, _ := env.do(req{method: "POST", path: "/api/panic/enter", token: env.admin, body: jsonBody(map[string]any{"reason": "drill\nline2", "confirmed": true})}); code != 200 {
		t.Fatalf("confirmed panic mode: %d", code)
	}
	if a := env.lastAudit("panic.enter"); a == nil || a.Result != auditOK {
		t.Fatalf("panic.enter audit: %+v", a)
	}
	if code, _, _ := env.do(req{method: "POST", path: "/api/panic/exit", token: env.admin}); code != 200 {
		t.Fatalf("exit: %d", code)
	}
	if a := env.lastAudit("panic.exit"); a == nil || a.Result != auditOK {
		t.Fatalf("panic.exit audit: %+v", a)
	}
}

func jsonBodyString(v any) (string, error) { b := jsonBody(v); return string(b), nil }

func TestSimulate_BoundsTargetAndConcurrency(t *testing.T) {
	env := newSecEnv(t, nil)
	cases := map[string]map[string]any{
		"attempts too many": {"attempt_count": maxSimAttempts + 1},
		"negative attempts": {"attempt_count": -1},
		"window too long":   {"window_seconds": maxSimWindowSeconds + 1},
		"ban too long":      {"ban_minutes": maxBanMinutes + 1},
		"ip is a range":     {"ip": "0.0.0.0/0"},
		"ip is garbage":     {"ip": "not an ip"},
	}
	for name, b := range cases {
		if code, _, _ := env.do(req{method: "POST", path: "/api/simulate/ssh-bruteforce", token: env.admin, body: jsonBody(b)}); code != http.StatusBadRequest {
			t.Errorf("%s: want 400, got %d", name, code)
		}
	}
	if env.count(&database.Incident{}, "") != 0 || env.count(&database.FirewallRule{}, "is_whitelisted = 0") != 0 {
		t.Fatal("a refused simulation wrote data")
	}
	if code, _, _ := env.do(req{method: "POST", path: "/api/simulate/ssh-bruteforce", token: env.admin, body: []byte(`{"unknown_field":1}`)}); code != http.StatusBadRequest {
		t.Errorf("unknown fields are rejected: %d", code)
	}
	// boundary values pass (dry run, so nothing is written)
	if code, _, _ := env.do(req{method: "POST", path: "/api/simulate/ssh-bruteforce", token: env.admin, body: jsonBody(map[string]any{"attempt_count": maxSimAttempts, "window_seconds": maxSimWindowSeconds, "dry_run": true})}); code != 200 {
		t.Errorf("boundary values: %d", code)
	}
	// an in-progress simulation makes a second one wait
	release, _, ok := env.srv.simGate.enter()
	if !ok {
		t.Fatal("gate should be free")
	}
	code, _, hdr := env.do(req{method: "POST", path: "/api/simulate/ssh-bruteforce", token: env.admin, body: jsonBody(map[string]any{"dry_run": true})})
	release()
	if code != http.StatusTooManyRequests || hdr.Get("Retry-After") == "" {
		t.Fatalf("concurrent simulation: %d", code)
	}
	if a := env.lastAudit("simulate.run"); a == nil {
		t.Fatal("simulation must be audited")
	}
	if env.srv.sec.opLimited.Load() == 0 {
		t.Fatal("limit hits must be counted")
	}
}

func TestExpensiveOperations_GatedAndNothingStartsWhenRefused(t *testing.T) {
	env := newSecEnv(t, func(s *Server) { s.BackupDir = t.TempDir() })
	rel, _, _ := env.srv.backupGate.enter()
	code, _, hdr := env.do(req{method: "POST", path: "/api/backup", token: env.admin, body: jsonBody(map[string]any{"label": "x"})})
	rel()
	if code != http.StatusTooManyRequests || hdr.Get("Retry-After") == "" {
		t.Fatalf("backup while another is running: %d", code)
	}
	if env.count(&database.BackupAudit{}, "") != 0 {
		t.Fatal("a refused backup left a trace as if it had run")
	}
	rel, _, _ = env.srv.importGate.enter()
	code, _, _ = env.do(req{method: "POST", path: "/api/intel/import", token: env.admin, body: []byte("feed")})
	rel()
	if code != http.StatusTooManyRequests {
		t.Fatalf("import while another is running: %d", code)
	}
	if env.count(&database.IOCImport{}, "") != 0 {
		t.Fatal("a refused import was recorded as an import")
	}
	// with the gates free both work again
	if code, _, _ := env.do(req{method: "POST", path: "/api/backup", token: env.admin, body: jsonBody(map[string]any{"label": "x"})}); code != 201 {
		t.Fatalf("backup after release: %d", code)
	}
}

// ---------------------------------------------------------------------------
// Input validation
// ---------------------------------------------------------------------------

func TestListFilters_MalformedIsA400_BoundariesAreAccepted(t *testing.T) {
	env := newSecEnv(t, nil)
	bad := []string{
		"/api/incidents?status=bogus", "/api/incidents?severity=EXTREME", "/api/incidents?ip=not-an-ip", "/api/incidents?since_hours=abc",
		"/api/incidents?since_hours=-1", "/api/incidents?since_hours=99999", "/api/incidents?limit=0", "/api/incidents?limit=501",
		"/api/incidents?limit=abc", "/api/incidents?offset=-1", "/api/incidents?offset=10001", "/api/incidents?offset=99999999999999999999",
		"/api/incidents?type=a%27%3BDROP", "/api/firewall/rules?active=maybe", "/api/firewall/rules?limit=501", "/api/firewall/rules?offset=-5",
		"/api/metrics/history?hours=0", "/api/metrics/history?hours=169", "/api/metrics/history?hours=x",
		"/api/hunt/matches?limit=201", "/api/hunt/matches?ip=bogus", "/api/investigate/incidents?limit=999999",
		"/api/incidents/abc/timeline", "/api/incidents/1/timeline?limit=0", "/api/incidents/1/timeline?offset=-1",
	}
	for _, p := range bad {
		if code, _, _ := env.do(req{method: "GET", path: p, token: env.viewer}); code != http.StatusBadRequest && code != http.StatusNotFound {
			t.Errorf("%s: want 400, got %d", p, code)
		}
	}
	good := []string{
		"/api/incidents?limit=500&offset=10000&since_hours=8760", "/api/incidents?limit=1&offset=0", "/api/incidents?severity=high&status=open",
		"/api/incidents?ip=2001:db8::1", "/api/firewall/rules?active=true&limit=500&offset=10000", "/api/metrics/history?hours=168", "/api/metrics/history?hours=1",
	}
	for _, p := range good {
		if code, _, _ := env.do(req{method: "GET", path: p, token: env.viewer}); code != 200 {
			t.Errorf("%s: want 200, got %d", p, code)
		}
	}
}

func TestBlockIncident_BodyIsValidatedWhenPresent(t *testing.T) {
	env := newSecEnv(t, nil)
	inc := &database.Incident{Type: database.IncidentPortScan, SourceIP: "203.0.113.90", Severity: database.SeverityLow, Status: database.StatusOpen, DetectedAt: time.Now().UTC()}
	if err := env.db.Create(inc).Error; err != nil {
		t.Fatal(err)
	}
	for name, b := range map[string][]byte{"malformed": []byte(`{"duration_minutes":`), "negative": []byte(`{"duration_minutes":-5}`), "huge": []byte(`{"duration_minutes":99999999999}`), "unknown": []byte(`{"x":1}`)} {
		if code, _, _ := env.do(req{method: "POST", path: "/api/incidents/1/block", token: env.admin, body: b}); code != http.StatusBadRequest {
			t.Errorf("%s: want 400, got %d", name, code)
		}
	}
	if env.exec.Blocked["203.0.113.90"] {
		t.Fatal("blocked despite invalid input")
	}
	if code, _, _ := env.do(req{method: "POST", path: "/api/incidents/1/block", token: env.admin}); code != 200 {
		t.Fatalf("no body is fine: %d", code)
	}
	if a := env.lastAudit("incident.block"); a == nil || a.Result != auditOK || a.Target != "incident:1" {
		t.Fatalf("%+v", a)
	}
}

// ---------------------------------------------------------------------------
// Errors, audit trail
// ---------------------------------------------------------------------------

func TestErrorsDoNotLeakInternals(t *testing.T) {
	env := newSecEnv(t, nil)
	env.exec.BlockErr = &pathyError{}
	code, body, _ := env.do(req{method: "POST", path: "/api/firewall/block", token: env.admin, body: jsonBody(map[string]any{"ip": "203.0.113.99"})})
	b, _ := jsonBodyString(body)
	if code != http.StatusConflict || strings.Contains(b, "/usr/sbin") || strings.Contains(b, "secret-token") {
		t.Fatalf("internal detail leaked (%d): %s", code, b)
	}
	if code, body, _ := env.do(req{method: "GET", path: "/api/nope", token: env.admin}); code != http.StatusNotFound {
		t.Fatalf("unknown route: %d %v", code, body)
	}
	if code, _, _ := env.do(req{method: "GET", path: "/api/incidents/18446744073709551616", token: env.viewer}); code != http.StatusBadRequest {
		t.Fatalf("overflowing id: %d", code)
	}
}

type pathyError struct{}

func (*pathyError) Error() string {
	return "exec /usr/sbin/ufw failed with token=secret-token at /var/lib/vanguard/vanguard.db"
}

func TestAdminAudit_AdminOnly_NoSecrets(t *testing.T) {
	env := newSecEnv(t, nil)
	env.do(req{method: "POST", path: "/api/firewall/block", token: env.admin, body: jsonBody(map[string]any{"ip": "203.0.113.31", "reason": "password=hunter2"})})
	if code, _, _ := env.do(req{method: "GET", path: "/api/audit/admin", token: env.viewer}); code != http.StatusForbidden {
		t.Fatalf("viewer: %d", code)
	}
	if code, _, _ := env.do(req{method: "GET", path: "/api/audit/admin"}); code != http.StatusUnauthorized {
		t.Fatalf("anonymous: %d", code)
	}
	code, body, _ := env.do(req{method: "GET", path: "/api/audit/admin?limit=10", token: env.admin})
	if code != 200 || body["count"].(float64) < 1 {
		t.Fatalf("%d %v", code, body)
	}
	b, _ := jsonBodyString(body)
	if strings.Contains(b, "hunter2") || strings.Contains(strings.ToLower(b), "password") && !strings.Contains(b, "passwords are never recorded") {
		t.Fatalf("request payload leaked into the audit trail: %s", b)
	}
	if code, _, _ := env.do(req{method: "GET", path: "/api/audit/admin?limit=500", token: env.admin}); code != http.StatusBadRequest {
		t.Fatalf("limit bound: %d", code)
	}
	for _, m := range []string{"POST", "PUT", "DELETE"} {
		if c, _, _ := env.do(req{method: m, path: "/api/audit/admin", token: env.admin, body: []byte(`{}`)}); c != http.StatusNotFound && c != http.StatusMethodNotAllowed {
			t.Errorf("%s /api/audit/admin must not exist: %d", m, c)
		}
	}
}

func TestIOCOperations_AreAudited_WithoutPayload(t *testing.T) {
	env := newSecEnv(t, nil)
	ioc := &database.IOC{Type: database.IOCIP, Value: "198.51.100.77", Source: "feed", Enabled: true}
	if err := env.db.Create(ioc).Error; err != nil {
		t.Fatal(err)
	}
	if code, _, _ := env.do(req{method: "PUT", path: "/api/intel/iocs/1", token: env.admin, body: []byte(`{"enabled":false}`)}); code != 200 {
		t.Fatal(code)
	}
	if a := env.lastAudit("ioc.disable"); a == nil || a.Result != auditOK || a.Target != "ioc:1" {
		t.Fatalf("%+v", a)
	}
	if code, _, _ := env.do(req{method: "DELETE", path: "/api/intel/iocs/1", token: env.admin}); code != 200 {
		t.Fatal(code)
	}
	if a := env.lastAudit("ioc.delete"); a == nil || a.Result != auditOK {
		t.Fatalf("%+v", a)
	}
	// deleting something that does not exist is audited as a failure, not a success
	if code, _, _ := env.do(req{method: "DELETE", path: "/api/intel/iocs/999", token: env.admin}); code != http.StatusNotFound {
		t.Fatal(code)
	}
	if a := env.lastAudit("ioc.delete"); a == nil || a.Result != auditFailed || a.Target != "ioc:999" {
		t.Fatalf("%+v", a)
	}
	// a viewer is refused and leaves no "ok" row behind
	n := env.count(&database.AdminAudit{}, "")
	env.do(req{method: "DELETE", path: "/api/intel/iocs/1", token: env.viewer})
	if env.count(&database.AdminAudit{}, "") != n {
		t.Fatal("a refused (403) request must not look like an operation")
	}
}

func TestSecurityCountersAreVisibleInRuntimeHealth_WithoutRequestData(t *testing.T) {
	env := newSecEnv(t, nil)
	bad := jsonBody(map[string]string{"email": "admin@example.test", "password": "secret-guess-12345"})
	for i := 0; i < loginMaxFailures+2; i++ {
		env.do(req{method: "POST", path: "/api/auth/login", body: bad})
	}
	env.do(req{method: "GET", path: "/api/health", host: "evil.example"})
	_, body, _ := env.do(req{method: "GET", path: "/api/health/runtime", token: env.admin})
	c := comps(t, body)["api_security"]
	if c == nil || c["state"] != "healthy" {
		t.Fatalf("api_security component missing or wrong: %v", c)
	}
	cnt := c["counters"].(map[string]any)
	if cnt["login_failures"].(float64) < float64(loginMaxFailures) || cnt["login_throttled"].(float64) < 1 || cnt["host_rejected"].(float64) < 1 {
		t.Fatalf("counters: %v", cnt)
	}
	if !strings.Contains(c["detail"].(string), "throttling") {
		t.Fatalf("recent throttling must be stated: %v", c["detail"])
	}
	b, _ := jsonBodyString(body)
	if strings.Contains(b, "secret-guess-12345") || strings.Contains(b, "admin@example.test") {
		t.Fatal("request data leaked into health output")
	}
}
