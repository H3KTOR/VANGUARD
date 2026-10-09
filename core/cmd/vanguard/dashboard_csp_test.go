package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"vanguard/core/internal/api"
	"vanguard/core/internal/auth"
	"vanguard/core/internal/database"
)

// The Content-Security-Policy is only meaningful if the page it protects obeys
// it. This test serves the REAL embedded production build through the real
// router and checks the page against the policy: same-origin scripts only, no
// inline script/style, no event-handler attributes, no third-party origins.
// (A browser run of the same check is recorded in docs/PHASE16.md.)
func TestEmbeddedDashboardIsServedUnderACompatibleCSP(t *testing.T) {
	db, err := database.Open(database.Config{Path: filepath.Join(t.TempDir(), "d.db")})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	mgr, _ := auth.NewManager("test-secret-test-secret-test-secret", time.Hour)
	srv := &api.Server{DB: db, Auth: mgr, StartedAt: time.Now()}
	e := srv.NewEcho()
	if err := mountFrontend(e); err != nil {
		t.Fatal(err)
	}
	get := func(path string) (*httptest.ResponseRecorder, string) {
		r := httptest.NewRequest("GET", path, nil)
		r.Host = "127.0.0.1:8080"
		w := httptest.NewRecorder()
		e.ServeHTTP(w, r)
		b, _ := io.ReadAll(w.Result().Body)
		return w, string(b)
	}
	w, body := get("/")
	if w.Code == http.StatusNotFound && strings.Contains(body, "dashboard build not found") {
		t.Skip("the dashboard is not built into this binary (run `make build-frontend`); CI builds it before this test")
	}
	if w.Code != 200 {
		t.Fatalf("GET /: %d", w.Code)
	}
	if got := w.Header().Get("Content-Security-Policy"); got != api.DashboardCSP {
		t.Fatalf("the dashboard page must carry the dashboard CSP, got %q", got)
	}
	for _, h := range []string{"X-Content-Type-Options", "X-Frame-Options", "Referrer-Policy"} {
		if w.Header().Get(h) == "" {
			t.Errorf("missing %s", h)
		}
	}
	lower := strings.ToLower(body)
	for _, tag := range regexp.MustCompile(`<script[^>]*>`).FindAllString(lower, -1) {
		if !strings.Contains(tag, " src=") {
			t.Errorf("inline <script> would be blocked by script-src self: %s", tag)
		}
	}
	if strings.Contains(lower, "<style") {
		t.Error("an inline <style> element would be blocked by style-src 'self'")
	}
	if regexp.MustCompile(`\son[a-z]+\s*=`).MatchString(lower) {
		t.Error("inline event-handler attributes would be blocked")
	}
	for _, m := range regexp.MustCompile(`(?:src|href)\s*=\s*"([^"]+)"`).FindAllStringSubmatch(body, -1) {
		if strings.HasPrefix(m[1], "http://") || strings.HasPrefix(m[1], "https://") || strings.HasPrefix(m[1], "//") {
			t.Errorf("the page references a third-party origin: %s", m[1])
		}
	}
	// every referenced asset is served, with the same protections
	for _, m := range regexp.MustCompile(`(?:src|href)\s*=\s*"(/assets/[^"]+)"`).FindAllStringSubmatch(body, -1) {
		aw, _ := get(m[1])
		if aw.Code != 200 {
			t.Errorf("%s: %d", m[1], aw.Code)
		}
		if aw.Header().Get("X-Content-Type-Options") != "nosniff" {
			t.Errorf("%s lacks nosniff", m[1])
		}
	}
	// API responses get the locked-down policy
	aw, _ := get("/api/health")
	if aw.Header().Get("Content-Security-Policy") != api.APICSP {
		t.Error("API responses must carry the API CSP")
	}
}
