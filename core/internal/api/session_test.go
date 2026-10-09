package api

import (
	"net/http"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"vanguard/core/internal/database"
)

func (env *secEnv) login(email, pw string) string {
	env.t.Helper()
	code, body, _ := env.do(req{method: "POST", path: "/api/auth/login", body: jsonBody(map[string]string{"email": email, "password": pw})})
	if code != 200 {
		env.t.Fatalf("login %s: %d %v", email, code, body)
	}
	return body["token"].(string)
}

const testPW = "a-test-password-123"

func uid(n uint) string { return strconv.FormatUint(uint64(n), 10) }

func TestLogout_EndsOnlyThatSession_ServerSide(t *testing.T) {
	env := newSecEnv(t, nil)
	a := env.login("admin@example.test", testPW)
	b := env.login("admin@example.test", testPW)
	if code, _, _ := env.do(req{method: "GET", path: "/api/auth/me", token: a}); code != 200 {
		t.Fatal(code)
	}
	if code, _, _ := env.do(req{method: "POST", path: "/api/auth/logout", token: a}); code != 200 {
		t.Fatalf("logout: %d", code)
	}
	// the very same, still-unexpired, correctly signed token is dead
	if code, _, _ := env.do(req{method: "GET", path: "/api/auth/me", token: a}); code != http.StatusUnauthorized {
		t.Fatalf("a logged-out token must be refused, got %d", code)
	}
	if code, _, _ := env.do(req{method: "POST", path: "/api/firewall/block", token: a, body: jsonBody(map[string]any{"ip": "203.0.113.61"})}); code != http.StatusUnauthorized || env.exec.Blocked["203.0.113.61"] {
		t.Fatal("a revoked token performed a privileged action")
	}
	if code, _, _ := env.do(req{method: "GET", path: "/api/auth/me", token: b}); code != 200 {
		t.Fatalf("other sessions must be unaffected, got %d", code)
	}
	if code, _, _ := env.do(req{method: "POST", path: "/api/auth/logout", token: a}); code != http.StatusUnauthorized {
		t.Fatalf("second logout with the dead token: %d", code)
	}
	if r := env.lastAudit("auth.logout"); r == nil || r.Actor != "admin@example.test" {
		t.Fatalf("%+v", r)
	}
}

func TestTokensWithoutALiveSessionAreRefused(t *testing.T) {
	env := newSecEnv(t, nil)
	var u database.User
	env.db.Where("email = ?", "admin@example.test").First(&u)
	noJTI, _, _ := env.mgr.IssueToken(&u) // signed correctly, no session id
	if code, _, _ := env.do(req{method: "GET", path: "/api/auth/me", token: noJTI}); code != http.StatusUnauthorized {
		t.Fatalf("legacy/no-session token: %d", code)
	}
	jti, _ := database.NewSessionID()
	unknown, _, _ := env.mgr.IssueSessionToken(&u, jti)
	if code, _, _ := env.do(req{method: "GET", path: "/api/auth/me", token: unknown}); code != http.StatusUnauthorized {
		t.Fatalf("unknown session: %d", code)
	}
	var v database.User
	env.db.Where("email = ?", "viewer@example.test").First(&v)
	env.db.CreateSession(&database.Session{ID: jti, UserID: v.ID, ExpiresAt: time.Now().Add(time.Hour)})
	if code, _, _ := env.do(req{method: "GET", path: "/api/auth/me", token: unknown}); code != http.StatusUnauthorized {
		t.Fatalf("a session of another account must not authorize this token: %d", code)
	}
	jti2, _ := database.NewSessionID()
	exp, _, _ := env.mgr.IssueSessionToken(&u, jti2)
	env.db.CreateSession(&database.Session{ID: jti2, UserID: u.ID, ExpiresAt: time.Now().Add(-time.Minute)})
	if code, _, _ := env.do(req{method: "GET", path: "/api/auth/me", token: exp}); code != http.StatusUnauthorized {
		t.Fatalf("server-side expiry: %d", code)
	}
}

func TestRevokeAll_KeepCurrent_AndSessionList(t *testing.T) {
	env := newSecEnv(t, nil)
	a := env.login("viewer@example.test", testPW)
	b := env.login("viewer@example.test", testPW)
	c := env.login("viewer@example.test", testPW)
	code, body, _ := env.do(req{method: "GET", path: "/api/auth/sessions", token: a})
	if code != 200 {
		t.Fatal(code)
	}
	sess := body["sessions"].([]any)
	if len(sess) != 4 { // three logins + the helper's token
		t.Fatalf("%d sessions: %v", len(sess), sess)
	}
	cur := 0
	for _, s := range sess {
		m := s.(map[string]any)
		if len(m["id"].(string)) != 8 {
			t.Fatalf("session ids are shortened in listings: %v", m["id"])
		}
		if m["current"] == true {
			cur++
		}
	}
	if cur != 1 {
		t.Fatalf("exactly one current session expected, got %d", cur)
	}
	if code, body, _ := env.do(req{method: "POST", path: "/api/auth/sessions/revoke-all", token: a, body: []byte(`{"keep_current":true}`)}); code != 200 || body["revoked"].(float64) != 3 {
		t.Fatalf("%d %v", code, body)
	}
	if code, _, _ := env.do(req{method: "GET", path: "/api/auth/me", token: a}); code != 200 {
		t.Fatal("the kept session must still work")
	}
	for _, tok := range []string{b, c, env.viewer} {
		if code, _, _ := env.do(req{method: "GET", path: "/api/auth/me", token: tok}); code != http.StatusUnauthorized {
			t.Fatalf("a revoked session still works: %d", code)
		}
	}
	env.do(req{method: "POST", path: "/api/auth/sessions/revoke-all", token: a, body: []byte(`{}`)})
	if code, _, _ := env.do(req{method: "GET", path: "/api/auth/me", token: a}); code != http.StatusUnauthorized {
		t.Fatal("revoke-all without keep_current ends the caller's session too")
	}
}

func TestAdminRevokeSessions_AdminOnly_AndAudited(t *testing.T) {
	env := newSecEnv(t, nil)
	var v database.User
	env.db.Where("email = ?", "viewer@example.test").First(&v)
	victim := env.login("viewer@example.test", testPW)
	path := "/api/users/" + uid(v.ID) + "/revoke-sessions"
	before := env.count(&database.Session{}, "revoked_at IS NULL")
	if code, _, _ := env.do(req{method: "POST", path: path, token: env.viewer}); code != http.StatusForbidden {
		t.Fatal(code)
	}
	if env.count(&database.Session{}, "revoked_at IS NULL") != before {
		t.Fatal("a refused request revoked sessions")
	}
	if code, body, _ := env.do(req{method: "POST", path: path, token: env.admin}); code != 200 || body["revoked"].(float64) < 2 {
		t.Fatalf("%d %v", code, body)
	}
	if code, _, _ := env.do(req{method: "GET", path: "/api/auth/me", token: victim}); code != http.StatusUnauthorized {
		t.Fatal("the target's session must be dead")
	}
	if code, _, _ := env.do(req{method: "GET", path: "/api/auth/me", token: env.admin}); code != 200 {
		t.Fatal("the admin's own session must be untouched")
	}
	if a := env.lastAudit("admin.revoke_sessions"); a == nil || a.Result != auditOK || a.Actor != "admin@example.test" || a.Target != "user:"+uid(v.ID) {
		t.Fatalf("%+v", a)
	}
	if code, _, _ := env.do(req{method: "POST", path: "/api/users/99999/revoke-sessions", token: env.admin}); code != http.StatusNotFound {
		t.Fatal(code)
	}
	if a := env.lastAudit("admin.revoke_sessions"); a.Result != auditFailed {
		t.Fatalf("a revoke against a missing account is a failure, not a success: %+v", a)
	}
}

func TestSessionsAreBounded_AndSurviveARestart(t *testing.T) {
	env := newSecEnv(t, nil)
	var first string
	for i := 0; i < database.MaxActiveSessionsPerUser+5; i++ {
		tok := env.login("viewer@example.test", testPW)
		if i == 0 {
			first = tok
		}
	}
	var u database.User
	env.db.Where("email = ?", "viewer@example.test").First(&u)
	if n := env.count(&database.Session{}, "user_id = ?", u.ID); n > int64(database.MaxActiveSessionsPerUser) {
		t.Fatalf("session rows for one account grew to %d", n)
	}
	if code, _, _ := env.do(req{method: "GET", path: "/api/auth/me", token: first}); code != http.StatusUnauthorized {
		t.Fatalf("the oldest session is evicted when the limit is exceeded, got %d", code)
	}
	live := env.login("viewer@example.test", testPW)
	// a second server instance on the same database (a process restart)
	srv2 := &Server{DB: env.db, Auth: env.mgr, Registry: env.srv.Registry, StartedAt: time.Now(), Autopilot: env.srv.Autopilot}
	e2 := &secEnv{t: t, srv: srv2, e: srv2.NewEcho(), db: env.db, exec: env.exec, mgr: env.mgr}
	if code, _, _ := e2.do(req{method: "GET", path: "/api/auth/me", token: live}); code != 200 {
		t.Fatalf("a restart must not log everyone out: %d", code)
	}
	e2.do(req{method: "POST", path: "/api/auth/logout", token: live})
	if code, _, _ := env.do(req{method: "GET", path: "/api/auth/me", token: live}); code != http.StatusUnauthorized {
		t.Fatal("revocation is stored in the database, not in process memory")
	}
}

func TestConcurrentLoginsAndRevocations_StayConsistent(t *testing.T) {
	env := newSecEnv(t, nil)
	var wg sync.WaitGroup
	codes := make(chan int, 200)
	for w := 0; w < 8; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < 5; i++ {
				code, body, _ := env.do(req{method: "POST", path: "/api/auth/login", body: jsonBody(map[string]string{"email": "viewer@example.test", "password": testPW}), remote: "127.0.0." + uid(uint(10+w)) + ":1"})
				codes <- code
				if code == 200 && i%2 == 0 {
					tok := body["token"].(string)
					c, _, _ := env.do(req{method: "POST", path: "/api/auth/sessions/revoke-all", token: tok, body: []byte(`{"keep_current":true}`)})
					codes <- c
				}
			}
		}(w)
	}
	wg.Wait()
	close(codes)
	for c := range codes {
		if c >= 500 && c != http.StatusServiceUnavailable {
			t.Fatalf("server error %d under concurrent session changes", c)
		}
	}
	var u database.User
	env.db.Where("email = ?", "viewer@example.test").First(&u)
	if n := env.count(&database.Session{}, "user_id = ? AND revoked_at IS NULL", u.ID); n > int64(database.MaxActiveSessionsPerUser) {
		t.Fatalf("active sessions %d exceed the bound", n)
	}
}

func TestPurgeSessions_RemovesExpiredAndOrphans_Bounded(t *testing.T) {
	env := newSecEnv(t, nil)
	var u database.User
	env.db.Where("email = ?", "viewer@example.test").First(&u)
	old := time.Now().UTC().Add(-48 * time.Hour)
	for i := 0; i < 5; i++ {
		id, _ := database.NewSessionID()
		env.db.Create(&database.Session{ID: id, UserID: u.ID, ExpiresAt: old, CreatedAt: old.Add(-time.Hour)})
	}
	orphan, _ := database.NewSessionID()
	env.db.Create(&database.Session{ID: orphan, UserID: 9999, CreatedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour)})
	keepBefore := env.count(&database.Session{}, "expires_at > ? AND user_id <> 9999", time.Now())
	n, err := env.db.PurgeSessions(time.Now().UTC(), 1000)
	if err != nil || n != 6 {
		t.Fatalf("purged %d, err %v", n, err)
	}
	if env.count(&database.Session{}, "expires_at > ? AND user_id <> 9999", time.Now()) != keepBefore {
		t.Fatal("live sessions must not be purged")
	}
}

func TestRegister_RequiresAnActiveSessionNotJustAValidSignature(t *testing.T) {
	env := newSecEnv(t, nil)
	tok := env.login("admin@example.test", testPW)
	env.do(req{method: "POST", path: "/api/auth/logout", token: tok})
	b := jsonBody(map[string]string{"email": "late@example.test", "password": "a-long-enough-password"})
	if code, _, _ := env.do(req{method: "POST", path: "/api/auth/register", body: b, token: tok}); code != http.StatusForbidden {
		t.Fatalf("a logged-out admin token created an account: %d", code)
	}
	if env.count(&database.User{}, "email = ?", "late@example.test") != 0 {
		t.Fatal("account created")
	}
}

func TestLoginCreatesASessionThatExpiresWithTheToken(t *testing.T) {
	env := newSecEnv(t, nil)
	env.login("admin@example.test", testPW)
	var s database.Session
	env.db.Order("created_at DESC").First(&s)
	if s.ClientIP != "127.0.0.1" || len(s.ID) != 32 || !s.ExpiresAt.After(time.Now()) || s.ExpiresAt.After(time.Now().Add(env.mgr.TTL()+time.Minute)) {
		t.Fatalf("%+v", s)
	}
}

func TestSecurityHeaders_IncludeCSPAndFriends(t *testing.T) {
	env := newSecEnv(t, nil)
	_, _, h := env.do(req{method: "GET", path: "/api/health"})
	if h.Get("Content-Security-Policy") != APICSP || h.Get("Cross-Origin-Opener-Policy") != "same-origin" || h.Get("Permissions-Policy") == "" {
		t.Fatalf("%v", h)
	}
	if h.Get("Strict-Transport-Security") != "" {
		t.Fatal("HSTS must not be sent over a plain-HTTP connection")
	}
	for _, bad := range []string{"unsafe-eval", "unsafe-inline", "*"} {
		if strings.Contains(DashboardCSP, bad) {
			t.Errorf("the dashboard CSP must not contain %q", bad)
		}
	}
	if !strings.Contains(DashboardCSP, "frame-ancestors 'none'") || !strings.Contains(DashboardCSP, "script-src 'self'") {
		t.Fatal(DashboardCSP)
	}
}
