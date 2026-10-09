package api

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"vanguard/core/internal/database"
)

func TestAuditIntegrityAPI_AdminOnly_ReadOnly_DetectsTampering(t *testing.T) {
	env := newSecEnv(t, nil)
	env.do(req{method: "POST", path: "/api/firewall/block", token: env.admin, body: jsonBody(map[string]any{"ip": "203.0.113.20"})})
	env.do(req{method: "POST", path: "/api/firewall/block", token: env.admin, body: jsonBody(map[string]any{"ip": "203.0.113.21"})})
	if code, _, _ := env.do(req{method: "GET", path: "/api/audit/integrity"}); code != http.StatusUnauthorized {
		t.Fatal(code)
	}
	if code, _, _ := env.do(req{method: "GET", path: "/api/audit/integrity", token: env.viewer}); code != http.StatusForbidden {
		t.Fatal(code)
	}
	// before sealing: nothing examined, recent records are "unsealed", and that is not an accusation
	_, body, _ := env.do(req{method: "GET", path: "/api/audit/integrity", token: env.admin})
	rep := body["report"].(map[string]any)
	if rep["ok"] != true || rep["entries_examined"].(float64) != 0 || rep["unsealed_records"].(map[string]any)["admin_audits"].(float64) < 2 {
		t.Fatalf("%v", rep)
	}
	if _, err := env.db.SealPending(time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	_, body, _ = env.do(req{method: "GET", path: "/api/audit/integrity", token: env.admin})
	rep = body["report"].(map[string]any)
	if rep["ok"] != true || rep["completed"] != true || rep["entries_examined"].(float64) < 2 {
		t.Fatalf("%v", rep)
	}
	if !strings.Contains(body["meaning"].(string), "not proof of authenticity") {
		t.Fatal("the response must not overstate what verification proves")
	}

	var before, ledgerBefore int64
	env.db.Model(&database.AdminAudit{}).Count(&before)
	env.db.Model(&database.AuditLedgerEntry{}).Count(&ledgerBefore)

	env.db.Exec("UPDATE admin_audits SET target = '198.51.100.99' WHERE action = 'firewall.block' AND id = (SELECT MIN(id) FROM admin_audits WHERE action = 'firewall.block')")
	_, body, _ = env.do(req{method: "GET", path: "/api/audit/integrity", token: env.admin})
	rep = body["report"].(map[string]any)
	if rep["ok"] != false || !strings.Contains(jsonBodyStr(rep["findings"]), "modified_record") {
		t.Fatalf("tampering must make the integrity report fail: %v", rep)
	}
	if strings.Contains(jsonBodyStr(rep), "198.51.100.99") {
		t.Fatal("findings must not echo record content")
	}
	var after, ledgerAfter int64
	env.db.Model(&database.AdminAudit{}).Count(&after)
	env.db.Model(&database.AuditLedgerEntry{}).Count(&ledgerAfter)
	if after != before || ledgerAfter != ledgerBefore {
		t.Fatal("the GET changed the database")
	}
	for _, p := range []string{"?from_seq=abc", "?max_entries=0", "?max_entries=100001", "?from_seq=-1"} {
		if code, _, _ := env.do(req{method: "GET", path: "/api/audit/integrity" + p, token: env.admin}); code != http.StatusBadRequest {
			t.Errorf("%s: %d", p, code)
		}
	}
	if code, _, _ := env.do(req{method: "POST", path: "/api/audit/integrity", token: env.admin, body: []byte(`{}`)}); code != http.StatusNotFound && code != http.StatusMethodNotAllowed {
		t.Fatalf("no mutating verb may exist: %d", code)
	}
}

func jsonBodyStr(v any) string { return string(jsonBody(v)) }

func TestPrivilegedAndAuthEventsAreAudited(t *testing.T) {
	env := newSecEnv(t, func(s *Server) { s.BackupDir = t.TempDir() })
	env.do(req{method: "POST", path: "/api/auth/login", body: jsonBody(map[string]string{"email": "admin@example.test", "password": "a-test-password-123"})})
	if a := env.lastAudit("auth.login"); a == nil || a.Actor != "admin@example.test" || a.Result != auditOK {
		t.Fatalf("login: %+v", a)
	}
	if strings.Contains(jsonBodyStr(env.lastAudit("auth.login")), "a-test-password-123") {
		t.Fatal("a password reached the audit trail")
	}
	// a failed login is NOT recorded row-by-row (an attacker must not be able to grow the table)...
	n := env.count(&database.AdminAudit{}, "")
	for i := 0; i < loginMaxFailures-1; i++ {
		env.do(req{method: "POST", path: "/api/auth/login", body: jsonBody(map[string]string{"email": "x@example.test", "password": "wrong-password-1"})})
	}
	if env.count(&database.AdminAudit{}, "") != n {
		t.Fatal("individual failures must not each add a row")
	}
	// ...but the lockout is, exactly once
	for i := 0; i < 5; i++ {
		env.do(req{method: "POST", path: "/api/auth/login", body: jsonBody(map[string]string{"email": "x@example.test", "password": "wrong-password-1"})})
	}
	if c := env.count(&database.AdminAudit{}, "action = ?", "auth.lockout"); c != 1 {
		t.Fatalf("lockout rows: %d", c)
	}
	// backup verify is audited with its real outcome
	_, created, _ := env.do(req{method: "POST", path: "/api/backup", token: env.admin, body: []byte(`{}`)})
	name := created["name"].(string)
	env.do(req{method: "GET", path: "/api/backup/" + name + "/verify", token: env.admin})
	if a := env.lastAudit("backup.verify"); a == nil || a.Result != auditOK || a.Target != name {
		t.Fatalf("%+v", a)
	}
}
