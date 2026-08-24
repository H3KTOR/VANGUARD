package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"vanguard/core/internal/auth"
	"vanguard/core/internal/database"
	"vanguard/core/internal/firewall"
	"vanguard/core/internal/simulator"
)

func testServer(t *testing.T) (*httptest.Server, *database.DB) {
	t.Helper()
	db, err := database.Open(database.Config{Path: ":memory:"})
	if err != nil {
		t.Fatalf("failed to open db: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	mgr, err := auth.NewManager("test-secret-key-not-for-prod", time.Hour)
	if err != nil {
		t.Fatalf("failed to build auth manager: %v", err)
	}
	exec := firewall.NewMockExecutor()
	ap := firewall.NewAutopilot(db, exec, firewall.DefaultConfig())
	srv := &Server{DB: db, Autopilot: ap, Auth: mgr, Registry: simulator.NewRegistry(), StartedAt: time.Now()}
	ts := httptest.NewServer(srv.NewEcho())
	t.Cleanup(ts.Close)
	return ts, db
}

func TestHealthEndpointIsPublic(t *testing.T) {
	ts, _ := testServer(t)
	resp, err := http.Get(ts.URL + "/api/health")
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
}

func TestProtectedRouteRejectsMissingToken(t *testing.T) {
	ts, _ := testServer(t)
	resp, err := http.Get(ts.URL + "/api/incidents")
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", resp.StatusCode)
	}
}

func bootstrapAdminToken(t *testing.T, ts *httptest.Server) string {
	t.Helper()
	resp, err := http.Post(ts.URL+"/api/auth/register", "application/json",
		strings.NewReader(`{"email":"admin@vanguard.local","password":"supersecret123"}`))
	if err != nil {
		t.Fatalf("register request failed: %v", err)
	}
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("expected 201 from bootstrap register, got %d", resp.StatusCode)
	}

	resp, err = http.Post(ts.URL+"/api/auth/login", "application/json",
		strings.NewReader(`{"email":"admin@vanguard.local","password":"supersecret123"}`))
	if err != nil {
		t.Fatalf("login request failed: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 from login, got %d", resp.StatusCode)
	}
	buf := make([]byte, 4096)
	n, _ := resp.Body.Read(buf)
	body := string(buf[:n])
	idx := strings.Index(body, `"token":"`)
	if idx < 0 {
		t.Fatalf("token not found in login response: %s", body)
	}
	rest := body[idx+len(`"token":"`):]
	return rest[:strings.Index(rest, `"`)]
}

func TestBootstrapRegisterFirstUserBecomesAdmin(t *testing.T) {
	ts, db := testServer(t)
	token := bootstrapAdminToken(t, ts)
	if token == "" {
		t.Fatal("expected non-empty token")
	}
	u, err := db.GetUserByEmail("admin@vanguard.local")
	if err != nil {
		t.Fatalf("failed to fetch bootstrapped user: %v", err)
	}
	if u.Role != database.RoleAdmin {
		t.Fatalf("expected first registered user to be admin, got %s", u.Role)
	}
}

func TestSecondRegisterRequiresAdminAuth(t *testing.T) {
	ts, _ := testServer(t)
	_ = bootstrapAdminToken(t, ts) // creates the first (admin) user

	resp, err := http.Post(ts.URL+"/api/auth/register", "application/json",
		strings.NewReader(`{"email":"someone@vanguard.local","password":"anothersecret123"}`))
	if err != nil {
		t.Fatalf("register request failed: %v", err)
	}
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 for unauthenticated second registration, got %d", resp.StatusCode)
	}
}

func TestDashboardSummaryWithValidToken(t *testing.T) {
	ts, _ := testServer(t)
	token := bootstrapAdminToken(t, ts)

	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/dashboard/summary", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
}

func TestRunSimulationDryRunViaAPI(t *testing.T) {
	ts, _ := testServer(t)
	token := bootstrapAdminToken(t, ts)

	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/simulate/ssh-bruteforce",
		strings.NewReader(`{"dry_run":true}`))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
}

func TestPanicEnterRequiresConfirmation(t *testing.T) {
	ts, _ := testServer(t)
	token := bootstrapAdminToken(t, ts)

	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/panic/enter",
		strings.NewReader(`{"reason":"test","confirmed":false}`))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 for unconfirmed panic mode, got %d", resp.StatusCode)
	}
}
