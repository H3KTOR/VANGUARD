package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"vanguard/core/internal/auth"
	"vanguard/core/internal/backup"
	"vanguard/core/internal/database"
	"vanguard/core/internal/firewall"
	"vanguard/core/internal/simulator"
)

func backupServer(t *testing.T, withDir bool) (*httptest.Server, *database.DB, string, string, string) {
	t.Helper()
	dir := t.TempDir()
	db, err := database.Open(database.Config{Path: filepath.Join(dir, "api.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if s, err := db.DB.DB(); err == nil {
			s.Close()
		}
	})
	mgr, _ := auth.NewManager("test-secret-key-not-for-prod", time.Hour)
	srv := &Server{DB: db, Auth: mgr, Registry: simulator.NewRegistry(), StartedAt: time.Now(),
		Autopilot: firewall.NewAutopilot(db, firewall.NewMockExecutor(), firewall.DefaultConfig())}
	bdir := filepath.Join(dir, "backups")
	if withDir {
		srv.BackupDir = bdir
	}
	ts := httptest.NewServer(srv.NewEcho())
	t.Cleanup(ts.Close)
	admin := bootstrapAdminToken(t, ts)
	viewer := realUserToken(t, db, mgr, "viewer@x.test", database.RoleViewer)
	_ = db.CreateIncident(&database.Incident{Type: database.IncidentPortScan, SourceIP: "203.0.113.1", RiskScore: 10, DetectedAt: time.Now().UTC()})
	return ts, db, admin, viewer, bdir
}

func TestBackupAPI_AdminOnly_NoPathsNoDownloadNoRestore(t *testing.T) {
	ts, _, admin, viewer, bdir := backupServer(t, true)
	for _, r := range [][2]string{{"GET", "/api/backup"}, {"POST", "/api/backup"}, {"GET", "/api/backup/vanguard-backup-20261009T120000Z/verify"}} {
		if code, _ := call(t, r[0], ts.URL+r[1], viewer, []byte(`{}`)); code != http.StatusForbidden {
			t.Errorf("%s %s by a non-admin: %d", r[0], r[1], code)
		}
		req, _ := http.NewRequest(r[0], ts.URL+r[1], strings.NewReader(`{}`))
		resp, _ := http.DefaultClient.Do(req)
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("%s %s unauthenticated: %d", r[0], r[1], resp.StatusCode)
		}
	}
	code, created := call(t, "POST", ts.URL+"/api/backup", admin, []byte(`{"label":"manual"}`))
	if code != http.StatusCreated {
		t.Fatalf("%d %v", code, created)
	}
	name := created["name"].(string)
	raw, _ := json.Marshal(created)
	if strings.Contains(string(raw), bdir) || strings.Contains(string(raw), filepath.Dir(bdir)) {
		t.Fatalf("the response must not reveal filesystem paths: %s", raw)
	}
	_, list := call(t, "GET", ts.URL+"/api/backup", admin, nil)
	if list["count"] != float64(1) || list["last_backup_at"] == "" {
		t.Fatalf("%v", list)
	}
	rawList, _ := json.Marshal(list)
	if strings.Contains(string(rawList), bdir) {
		t.Fatal("listing leaked a path")
	}
	audit := list["recent_activity"].([]any)
	if len(audit) != 1 || audit[0].(map[string]any)["actor"] != "admin@vanguard.local" || audit[0].(map[string]any)["kind"] != "create" {
		t.Fatalf("creation must be audited with the authenticated actor: %v", audit)
	}
	// no download and no restore over HTTP, by design
	for _, r := range [][2]string{{"GET", "/api/backup/" + name + "/download"}, {"GET", "/api/backup/" + name}, {"POST", "/api/backup/restore"}, {"POST", "/api/backup/" + name + "/restore"}, {"PUT", "/api/backup"}, {"DELETE", "/api/backup/" + name}} {
		if code, _ := call(t, r[0], ts.URL+r[1], admin, []byte(`{}`)); code != http.StatusNotFound && code != http.StatusMethodNotAllowed {
			t.Errorf("%s %s must not exist, got %d", r[0], r[1], code)
		}
	}
}

func TestBackupAPI_VerifyDetectsTamperingAndRejectsBadNames(t *testing.T) {
	ts, _, admin, _, bdir := backupServer(t, true)
	_, created := call(t, "POST", ts.URL+"/api/backup", admin, nil)
	name := created["name"].(string)
	code, rep := call(t, "GET", ts.URL+"/api/backup/"+name+"/verify", admin, nil)
	if code != 200 || rep["valid"] != true {
		t.Fatalf("%d %v", code, rep)
	}
	p := filepath.Join(bdir, name, backup.DBFile)
	b, _ := os.ReadFile(p)
	b[len(b)-100] ^= 0xFF
	_ = os.WriteFile(p, b, 0o600)
	_, rep = call(t, "GET", ts.URL+"/api/backup/"+name+"/verify", admin, nil)
	if rep["valid"] != false || len(rep["problems"].([]any)) == 0 {
		t.Fatalf("tampering must be reported: %v", rep)
	}
	for _, bad := range []string{"not-a-backup", "..", "vanguard-backup-20261009T120000Z.partial", "VANGUARD"} {
		if code, _ := call(t, "GET", ts.URL+"/api/backup/"+bad+"/verify", admin, nil); code != 400 && code != 404 {
			t.Errorf("%q: %d", bad, code)
		}
	}
}

func TestBackupAPI_ValidationConflictAndStrictBody(t *testing.T) {
	ts, _, admin, _, _ := backupServer(t, true)
	if code, _ := call(t, "POST", ts.URL+"/api/backup", admin, []byte(`{"label":"Bad Label!"}`)); code != 400 {
		t.Errorf("bad label: %d", code)
	}
	if code, _ := call(t, "POST", ts.URL+"/api/backup", admin, []byte(`{"label":"a","path":"/etc"}`)); code != 400 {
		t.Errorf("unknown field (a path must never be accepted): %d", code)
	}
	if code, _ := call(t, "POST", ts.URL+"/api/backup", admin, []byte(`{"exclude_users":true,"label":"nouser"}`)); code != 201 {
		t.Errorf("exclude users: %d", code)
	}
	// distinct names within the same second would collide: second call conflicts or gets a new second
	_, _ = call(t, "POST", ts.URL+"/api/backup", admin, []byte(`{"label":"dup"}`))
	code, _ := call(t, "POST", ts.URL+"/api/backup", admin, []byte(`{"label":"dup"}`))
	if code != 409 && code != 201 {
		t.Errorf("duplicate within one second must conflict (409) or be a new name: %d", code)
	}
}

func TestBackupAPI_UnconfiguredIsExplicit(t *testing.T) {
	ts, _, admin, _, _ := backupServer(t, false)
	if code, _ := call(t, "GET", ts.URL+"/api/backup", admin, nil); code != http.StatusServiceUnavailable {
		t.Fatalf("%d", code)
	}
}
