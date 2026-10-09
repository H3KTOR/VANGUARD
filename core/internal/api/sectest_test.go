package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/labstack/echo/v4"

	"vanguard/core/internal/auth"
	"vanguard/core/internal/database"
	"vanguard/core/internal/firewall"
	"vanguard/core/internal/simulator"
)

// secEnv drives the real router in-process (no sockets) so that tests control
// the TCP peer address, Host and Origin exactly.
type secEnv struct {
	t      *testing.T
	srv    *Server
	e      *echo.Echo
	db     *database.DB
	exec   *firewall.MockExecutor
	mgr    *auth.Manager
	admin  string
	viewer string
}

func newSecEnv(t *testing.T, mutate func(*Server)) *secEnv {
	t.Helper()
	db, err := database.Open(database.Config{Path: filepath.Join(t.TempDir(), "sec.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if s, err := db.DB.DB(); err == nil {
			s.Close()
		}
	})
	mgr, _ := auth.NewManager("test-secret-key-not-for-prod", time.Hour)
	exec := firewall.NewMockExecutor()
	srv := &Server{DB: db, Auth: mgr, Registry: simulator.NewRegistry(), StartedAt: time.Now(),
		Autopilot: firewall.NewAutopilot(db, exec, firewall.DefaultConfig())}
	if mutate != nil {
		mutate(srv)
	}
	env := &secEnv{t: t, srv: srv, e: srv.NewEcho(), db: db, exec: exec, mgr: mgr}
	env.admin = realUserToken(t, db, mgr, "admin@example.test", database.RoleAdmin)
	env.viewer = realUserToken(t, db, mgr, "viewer@example.test", database.RoleViewer)
	return env
}

type req struct {
	method, path, token string
	body                []byte
	remote              string // TCP peer, default loopback
	host, origin        string
	headers             map[string]string
	chunked             bool
}

func (env *secEnv) do(r req) (int, map[string]any, http.Header) {
	env.t.Helper()
	var body *bytes.Reader
	if r.body != nil {
		body = bytes.NewReader(r.body)
	} else {
		body = bytes.NewReader(nil)
	}
	hr := httptest.NewRequest(r.method, r.path, body)
	if r.chunked {
		hr.ContentLength = -1
	}
	hr.RemoteAddr = "127.0.0.1:50000"
	if r.remote != "" {
		hr.RemoteAddr = r.remote
	}
	hr.Host = "127.0.0.1:8080"
	if r.host != "" {
		hr.Host = r.host
	}
	if r.origin != "" {
		hr.Header.Set("Origin", r.origin)
	}
	if r.body != nil {
		hr.Header.Set("Content-Type", "application/json")
	}
	if r.token != "" {
		hr.Header.Set("Authorization", "Bearer "+r.token)
	}
	for k, v := range r.headers {
		hr.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	env.e.ServeHTTP(rec, hr)
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec.Code, out, rec.Header()
}

func (env *secEnv) count(model any, where string, args ...any) int64 {
	env.t.Helper()
	var n int64
	q := env.db.Model(model)
	if where != "" {
		q = q.Where(where, args...)
	}
	if err := q.Count(&n).Error; err != nil {
		env.t.Fatal(err)
	}
	return n
}

func (env *secEnv) lastAudit(action string) *database.AdminAudit {
	var a database.AdminAudit
	if err := env.db.Where("action = ?", action).Order("id DESC").First(&a).Error; err != nil {
		return nil
	}
	return &a
}

func jsonBody(v any) []byte { b, _ := json.Marshal(v); return b }

// ---------------------------------------------------------------------------
// Authentication / session boundaries
// ---------------------------------------------------------------------------

func TestToken_RevalidatedAgainstLiveAccount(t *testing.T) {
	env := newSecEnv(t, nil)
	if code, _, _ := env.do(req{method: "GET", path: "/api/auth/me", token: env.viewer}); code != 200 {
		t.Fatalf("baseline: %d", code)
	}
	// disabling the account takes effect on the very next request
	if err := env.db.Model(&database.User{}).Where("email = ?", "viewer@example.test").Update("is_active", false).Error; err != nil {
		t.Fatal(err)
	}
	if code, _, _ := env.do(req{method: "GET", path: "/api/auth/me", token: env.viewer}); code != http.StatusUnauthorized {
		t.Fatalf("a disabled account's token must stop working immediately, got %d", code)
	}
	// deleting the account (or restoring a backup without it) does too
	if err := env.db.Where("email = ?", "admin@example.test").Delete(&database.User{}).Error; err != nil {
		t.Fatal(err)
	}
	if code, _, _ := env.do(req{method: "GET", path: "/api/dashboard/summary", token: env.admin}); code != http.StatusUnauthorized {
		t.Fatalf("a deleted account's token must be refused, got %d", code)
	}
}

func TestToken_RoleComesFromTheDatabaseNotTheToken(t *testing.T) {
	env := newSecEnv(t, nil)
	body := jsonBody(map[string]any{"ip": "203.0.113.5"})
	if code, _, _ := env.do(req{method: "POST", path: "/api/firewall/block", token: env.admin, body: body}); code != 200 {
		t.Fatalf("admin baseline: %d", code)
	}
	// demote: the old token still says "admin"
	if err := env.db.Model(&database.User{}).Where("email = ?", "admin@example.test").Update("role", database.RoleViewer).Error; err != nil {
		t.Fatal(err)
	}
	before := env.count(&database.FirewallRule{}, "")
	if code, _, _ := env.do(req{method: "POST", path: "/api/firewall/block", token: env.admin, body: jsonBody(map[string]any{"ip": "203.0.113.6"})}); code != http.StatusForbidden {
		t.Fatalf("a demoted admin must lose admin rights immediately, got %d", code)
	}
	if env.count(&database.FirewallRule{}, "") != before {
		t.Fatal("state changed despite the refusal")
	}
}

func TestToken_RejectsForgedExpiredAndMismatched(t *testing.T) {
	env := newSecEnv(t, nil)
	other, _ := auth.NewManager("a-completely-different-secret-value", time.Hour)
	var u database.User
	env.db.Where("email = ?", "admin@example.test").First(&u)
	forged, _, _ := other.IssueToken(&u)
	if code, _, _ := env.do(req{method: "GET", path: "/api/auth/me", token: forged}); code != 401 {
		t.Fatalf("token signed with another secret: %d", code)
	}
	// valid signature but the email no longer matches the account (id reuse after a restore)
	ghost := u
	ghost.Email = "someone-else@example.test"
	tok, _, _ := env.mgr.IssueToken(&ghost)
	if code, _, _ := env.do(req{method: "GET", path: "/api/auth/me", token: tok}); code != 401 {
		t.Fatalf("token whose email does not match the account: %d", code)
	}
	for _, bad := range []string{"", "not-a-jwt", "a.b.c", "eyJhbGciOiJub25lIn0.eyJ1c2VyX2lkIjoxfQ."} {
		if code, _, _ := env.do(req{method: "GET", path: "/api/auth/me", token: bad}); code != 401 {
			t.Fatalf("malformed token %q: %d", bad, code)
		}
	}
	if code, _, _ := env.do(req{method: "GET", path: "/api/auth/me", headers: map[string]string{"Authorization": "Basic YWRtaW46eA=="}}); code != 401 {
		t.Fatalf("non-bearer scheme: %d", code)
	}
}

func TestLogin_UniformFailureAndNoEnumeration(t *testing.T) {
	env := newSecEnv(t, nil)
	if err := env.db.Model(&database.User{}).Where("email = ?", "viewer@example.test").Update("is_active", false).Error; err != nil {
		t.Fatal(err)
	}
	var bodies []string
	for _, c := range []map[string]string{
		{"email": "nobody@example.test", "password": "a-test-password-123"},
		{"email": "admin@example.test", "password": "wrong-password-xyz"},
		{"email": "viewer@example.test", "password": "a-test-password-123"}, // correct password, disabled account
	} {
		code, body, _ := env.do(req{method: "POST", path: "/api/auth/login", body: jsonBody(c)})
		if code != http.StatusUnauthorized {
			t.Fatalf("%v: want 401, got %d", c["email"], code)
		}
		b, _ := json.Marshal(body)
		bodies = append(bodies, string(b))
	}
	if bodies[0] != bodies[1] || bodies[1] != bodies[2] {
		t.Fatalf("failure responses must be indistinguishable: %v", bodies)
	}
	// the right credentials still work
	if code, body, _ := env.do(req{method: "POST", path: "/api/auth/login", body: jsonBody(map[string]string{"email": "admin@example.test", "password": "a-test-password-123"})}); code != 200 || body["token"] == nil {
		t.Fatalf("valid login: %d %v", code, body)
	}
	// over-long inputs are refused without reaching bcrypt
	long := strings.Repeat("a", 300)
	if code, _, _ := env.do(req{method: "POST", path: "/api/auth/login", body: jsonBody(map[string]string{"email": long, "password": "x"})}); code != 401 {
		t.Fatalf("long email: %d", code)
	}
}

func TestLogin_ThrottlesRepeatedFailuresPerAddress_AndSessionsKeepWorking(t *testing.T) {
	env := newSecEnv(t, nil)
	bad := jsonBody(map[string]string{"email": "admin@example.test", "password": "nope-nope-nope"})
	for i := 0; i < loginMaxFailures; i++ {
		// a forged X-Forwarded-For must not rotate the throttle key
		code, _, _ := env.do(req{method: "POST", path: "/api/auth/login", body: bad, headers: map[string]string{"X-Forwarded-For": "203.0.113." + string(rune('1'+i)), "X-Real-IP": "198.51.100.9"}})
		if code != 401 {
			t.Fatalf("attempt %d: %d", i, code)
		}
	}
	code, _, hdr := env.do(req{method: "POST", path: "/api/auth/login", body: bad})
	if code != http.StatusTooManyRequests || hdr.Get("Retry-After") == "" {
		t.Fatalf("want 429 with Retry-After after %d failures, got %d", loginMaxFailures, code)
	}
	// even the correct password is refused while throttled (no oracle)
	good := jsonBody(map[string]string{"email": "admin@example.test", "password": "a-test-password-123"})
	if code, _, _ := env.do(req{method: "POST", path: "/api/auth/login", body: good}); code != http.StatusTooManyRequests {
		t.Fatalf("correct password during lockout: %d", code)
	}
	// a different client address is unaffected
	if code, _, _ := env.do(req{method: "POST", path: "/api/auth/login", body: good, remote: "127.0.0.2:4000"}); code != 200 {
		t.Fatalf("other address: %d", code)
	}
	// an existing session is not affected by the lockout
	if code, _, _ := env.do(req{method: "GET", path: "/api/auth/me", token: env.admin}); code != 200 {
		t.Fatalf("existing session during lockout: %d", code)
	}
	if env.srv.sec.loginThrottled.Load() < 2 {
		t.Fatal("throttling must be counted")
	}
}

func TestRegister_Validation_AndBootstrapRules(t *testing.T) {
	// fresh instance with no users at all
	db, _ := database.Open(database.Config{Path: filepath.Join(t.TempDir(), "b.db")})
	t.Cleanup(func() {
		if s, err := db.DB.DB(); err == nil {
			s.Close()
		}
	})
	mgr, _ := auth.NewManager("test-secret-key-not-for-prod", time.Hour)
	srv := &Server{DB: db, Auth: mgr, Registry: simulator.NewRegistry(), StartedAt: time.Now()}
	env := &secEnv{t: t, srv: srv, e: srv.NewEcho(), db: db, mgr: mgr}

	good := jsonBody(map[string]string{"email": "first@example.test", "password": "a-long-enough-password"})
	// 1. a remote address cannot claim the first admin account
	if code, _, _ := env.do(req{method: "POST", path: "/api/auth/register", body: good, remote: "198.51.100.7:1234"}); code != http.StatusForbidden {
		t.Fatalf("remote bootstrap must be refused, got %d", code)
	}
	if env.count(&database.User{}, "") != 0 {
		t.Fatal("a user was created by a refused request")
	}
	// 2. invalid input
	for name, b := range map[string][]byte{
		"bad email":    jsonBody(map[string]string{"email": "not-an-email", "password": "a-long-enough-password"}),
		"space email":  jsonBody(map[string]string{"email": "a b@example.test", "password": "a-long-enough-password"}),
		"short pw":     jsonBody(map[string]string{"email": "x@example.test", "password": "short"}),
		"72+ byte pw":  jsonBody(map[string]string{"email": "x@example.test", "password": strings.Repeat("p", 73)}),
		"giant email":  jsonBody(map[string]string{"email": strings.Repeat("a", 300) + "@example.test", "password": "a-long-enough-password"}),
		"missing pw":   jsonBody(map[string]string{"email": "x@example.test"}),
		"malformed":    []byte(`{"email":`),
		"two at-signs": jsonBody(map[string]string{"email": "a@b@example.test", "password": "a-long-enough-password"}),
	} {
		if code, _, _ := env.do(req{method: "POST", path: "/api/auth/register", body: b}); code != http.StatusBadRequest {
			t.Errorf("%s: want 400, got %d", name, code)
		}
	}
	if env.count(&database.User{}, "") != 0 {
		t.Fatal("invalid input created a user")
	}
	// 3. a cross-site browser request is refused even from loopback
	if code, _, _ := env.do(req{method: "POST", path: "/api/auth/register", body: good, origin: "https://evil.example"}); code != http.StatusForbidden {
		t.Fatalf("cross-origin bootstrap must be refused, got %d", code)
	}
	if env.count(&database.User{}, "") != 0 {
		t.Fatal("cross-origin request created a user")
	}
	// 4. the legitimate local bootstrap works, and only one of many racing requests wins
	done := make(chan int, 12)
	for i := 0; i < 12; i++ {
		go func(i int) {
			b := jsonBody(map[string]string{"email": "racer" + string(rune('a'+i)) + "@example.test", "password": "a-long-enough-password"})
			code, _, _ := env.do(req{method: "POST", path: "/api/auth/register", body: b})
			done <- code
		}(i)
	}
	created := 0
	for i := 0; i < 12; i++ {
		if <-done == http.StatusCreated {
			created++
		}
	}
	if created != 1 || env.count(&database.User{}, "") != 1 || env.count(&database.User{}, "role = ?", database.RoleAdmin) != 1 {
		t.Fatalf("exactly one bootstrap admin expected, created=%d users=%d", created, env.count(&database.User{}, ""))
	}
	if a := env.lastAudit("user.create"); a == nil || a.Result != auditOK || a.Actor != "bootstrap" {
		t.Fatalf("bootstrap must be audited: %+v", a)
	}
}

func TestRegister_RemoteBootstrapOnlyWithExplicitOptIn(t *testing.T) {
	db, _ := database.Open(database.Config{Path: filepath.Join(t.TempDir(), "o.db")})
	t.Cleanup(func() {
		if s, err := db.DB.DB(); err == nil {
			s.Close()
		}
	})
	mgr, _ := auth.NewManager("test-secret-key-not-for-prod", time.Hour)
	srv := &Server{DB: db, Auth: mgr, Registry: simulator.NewRegistry(), StartedAt: time.Now(), Security: SecurityConfig{AllowRemoteBootstrap: true}}
	env := &secEnv{t: t, srv: srv, e: srv.NewEcho(), db: db, mgr: mgr}
	good := jsonBody(map[string]string{"email": "first@example.test", "password": "a-long-enough-password"})
	if code, _, _ := env.do(req{method: "POST", path: "/api/auth/register", body: good, remote: "198.51.100.7:1234"}); code != http.StatusCreated {
		t.Fatalf("opt-in remote bootstrap: %d", code)
	}
}

func TestRegister_AfterBootstrapNeedsALiveAdmin(t *testing.T) {
	env := newSecEnv(t, nil)
	b := jsonBody(map[string]string{"email": "new@example.test", "password": "a-long-enough-password", "role": "admin"})
	for name, tok := range map[string]string{"anonymous": "", "viewer": env.viewer} {
		if code, _, _ := env.do(req{method: "POST", path: "/api/auth/register", body: b, token: tok}); code != http.StatusForbidden {
			t.Errorf("%s: want 403, got %d", name, code)
		}
	}
	if env.count(&database.User{}, "email = ?", "new@example.test") != 0 {
		t.Fatal("refused registration created a user")
	}
	if code, _, _ := env.do(req{method: "POST", path: "/api/auth/register", body: b, token: env.admin}); code != http.StatusCreated {
		t.Fatalf("admin registering: %d", code)
	}
	if a := env.lastAudit("user.create"); a == nil || a.Actor != "admin@example.test" {
		t.Fatalf("user creation by an admin must be audited with that admin: %+v", a)
	}
	// a demoted/disabled admin's old token can no longer create accounts
	env.db.Model(&database.User{}).Where("email = ?", "admin@example.test").Update("is_active", false)
	b2 := jsonBody(map[string]string{"email": "late@example.test", "password": "a-long-enough-password"})
	if code, _, _ := env.do(req{method: "POST", path: "/api/auth/register", body: b2, token: env.admin}); code != http.StatusForbidden {
		t.Fatalf("disabled admin token: %d", code)
	}
	if env.count(&database.User{}, "email = ?", "late@example.test") != 0 {
		t.Fatal("a disabled admin created an account")
	}
}

func TestDatabaseFailure_AuthFailsClosed_ButHealthKeepsAnswering(t *testing.T) {
	env := newSecEnv(t, nil)
	if s, err := env.db.DB.DB(); err == nil {
		s.Close()
	}
	for _, p := range []string{"/api/auth/me", "/api/incidents", "/api/firewall/rules"} {
		if code, _, _ := env.do(req{method: "GET", path: p, token: env.admin}); code != http.StatusServiceUnavailable {
			t.Errorf("%s with the database down must fail closed with 503, got %d", p, code)
		}
	}
	if code, body, _ := env.do(req{method: "POST", path: "/api/auth/login", body: jsonBody(map[string]string{"email": "admin@example.test", "password": "a-test-password-123"})}); code != http.StatusServiceUnavailable {
		t.Errorf("login with the database down: %d %v", code, body)
	}
	if code, _, _ := env.do(req{method: "GET", path: "/api/health/runtime", token: env.admin}); code != 200 {
		t.Errorf("runtime health must keep answering, got %d", code)
	}
	if code, _, _ := env.do(req{method: "GET", path: "/api/health/runtime", token: "garbage"}); code != 401 {
		t.Errorf("the health exception still requires a valid signed token, got %d", code)
	}
}
