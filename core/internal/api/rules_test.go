package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"vanguard/core/internal/auth"
	"vanguard/core/internal/database"
	"vanguard/core/internal/firewall"
	"vanguard/core/internal/rules"
	"vanguard/core/internal/simulator"
	"vanguard/core/internal/tuning"
)

func rulesServer(t *testing.T) (*httptest.Server, *database.DB, string, string, *tuning.Store) {
	t.Helper()
	db, err := database.Open(database.Config{Path: t.TempDir() + "/r.db"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if s, err := db.DB.DB(); err == nil {
			s.Close()
		}
	})
	mgr, _ := auth.NewManager("test-secret-key-not-for-prod", time.Hour)
	st := tuning.Load(db)
	srv := &Server{DB: db, Auth: mgr, Registry: simulator.NewRegistry(), StartedAt: time.Now(),
		Autopilot: firewall.NewAutopilot(db, firewall.NewMockExecutor(), firewall.DefaultConfig()),
		Tuning:    st,
		RuleCtx:   rules.Context{HostSecurity: true, SystemPosture: true, Intel: true, Honeypot: true, MinRiskToBan: 60, AutopilotActive: true}}
	ts := httptest.NewServer(srv.NewEcho())
	t.Cleanup(ts.Close)
	admin := bootstrapAdminToken(t, ts)
	viewer := realUserToken(t, db, mgr, "viewer@x.test", database.RoleViewer)
	return ts, db, admin, viewer, st
}

func TestRulesAPI_InventoryReadableByAnyAuthenticatedUser(t *testing.T) {
	ts, _, admin, viewer, _ := rulesServer(t)
	for _, tok := range []string{admin, viewer} {
		code, body := call(t, "GET", ts.URL+"/api/rules", tok, nil)
		if code != 200 || body["count"].(float64) < 30 {
			t.Fatalf("%d %v", code, body["count"])
		}
	}
	resp, _ := http.Get(ts.URL + "/api/rules")
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthenticated: %d", resp.StatusCode)
	}
}

func TestTuningAPI_StateChangesRequireAdmin_ReadsDoNot(t *testing.T) {
	ts, _, _, viewer, _ := rulesServer(t)
	if code, _ := call(t, "GET", ts.URL+"/api/rules/tuning", viewer, nil); code != 200 {
		t.Fatalf("read-only inspection must work for a viewer: %d", code)
	}
	if code, _ := call(t, "POST", ts.URL+"/api/rules/tuning/preview", viewer, []byte(`{"values":{"ssh_bruteforce_min_attempts":20}}`)); code != 200 {
		t.Fatalf("preview is read-only and open to a viewer: %d", code)
	}
	if code, _ := call(t, "GET", ts.URL+"/api/rules/guidance", viewer, nil); code != 200 {
		t.Fatalf("guidance read: %d", code)
	}
	for name, req := range map[string][3]string{
		"apply":    {"PUT", "/api/rules/tuning", `{"expected_revision":0,"values":{"ssh_bruteforce_min_attempts":5}}`},
		"rollback": {"POST", "/api/rules/tuning/rollback", `{"expected_revision":0}`},
	} {
		if code, _ := call(t, req[0], ts.URL+req[1], viewer, []byte(req[2])); code != http.StatusForbidden {
			t.Errorf("%s by a non-admin must be 403, got %d", name, code)
		}
	}
	_, cur := call(t, "GET", ts.URL+"/api/rules/tuning", viewer, nil)
	if cur["revision"] != float64(0) {
		t.Fatal("a forbidden request must not change anything")
	}
}

func TestTuningAPI_PreviewApplyConflictAckInvalidRollback(t *testing.T) {
	ts, _, admin, _, st := rulesServer(t)
	base := ts.URL + "/api/rules/tuning"

	// preview: not applied
	code, pv := call(t, "POST", base+"/preview", admin, []byte(`{"values":{"web_dir_scan_min_404s":20}}`))
	if code != 200 || pv["applied"] != false || pv["requires_acknowledgement"] != true {
		t.Fatalf("%d %v", code, pv)
	}
	if _, rev := st.Current(); rev != 0 {
		t.Fatal("preview applied something")
	}

	// weakening without acknowledgement is refused with a machine-readable code
	code, r := call(t, "PUT", base, admin, []byte(`{"expected_revision":0,"values":{"web_dir_scan_min_404s":20},"reason":"noisy crawler"}`))
	if code != 409 || r["code"] != "needs_acknowledgement" {
		t.Fatalf("%d %v", code, r)
	}
	// acknowledged: applied and audited with the real identity
	code, r = call(t, "PUT", base, admin, []byte(`{"expected_revision":0,"values":{"web_dir_scan_min_404s":20},"reason":"noisy crawler","acknowledge_weakening":true}`))
	if code != 200 || r["revision"] != float64(1) {
		t.Fatalf("%d %v", code, r)
	}
	_, g := call(t, "GET", base, admin, nil)
	h := g["history"].([]any)[0].(map[string]any)
	if h["actor"] != "admin@vanguard.local" || h["reason"] != "noisy crawler" || h["weakening_acknowledged"] != true {
		t.Fatalf("audit entry: %v", h)
	}
	// stale revision => conflict
	if code, r = call(t, "PUT", base, admin, []byte(`{"expected_revision":0,"values":{"web_dir_scan_min_404s":10},"acknowledge_weakening":true}`)); code != 409 || r["code"] != "conflict" {
		t.Fatalf("%d %v", code, r)
	}
	// invalid values / unknown fields / malformed / oversize
	for name, body := range map[string]string{
		"out of range":  `{"expected_revision":1,"values":{"ssh_bruteforce_min_attempts":1}}`,
		"too large":     `{"expected_revision":1,"values":{"http_flood_max_requests":999999999}}`,
		"unknown field": `{"expected_revision":1,"values":{"ssh_bruteforce_min_attempts":9,"auto_ban_threshold":1}}`,
		"code attempt":  `{"expected_revision":1,"values":{},"script":"os.Exit(1)"}`,
		"wrong type":    `{"expected_revision":1,"values":{"ssh_bruteforce_min_attempts":"nine"}}`,
		"not json":      `{{{`,
	} {
		code, _ := call(t, "PUT", base, admin, []byte(body))
		if code != 400 && code != 422 {
			t.Errorf("%s: want 400/422, got %d", name, code)
		}
	}
	if code, _ := call(t, "PUT", base, admin, []byte(`{"expected_revision":1,"values":{},"reason":"`+strings.Repeat("x", 5000)+`"}`)); code != http.StatusRequestEntityTooLarge {
		t.Errorf("oversize body: %d", code)
	}
	if _, rev := st.Current(); rev != 1 {
		t.Fatalf("rejected requests must leave revision 1 untouched, got %d", rev)
	}
	// rollback restores defaults as a new revision
	code, r = call(t, "POST", base+"/rollback", admin, []byte(`{"expected_revision":1,"reason":"crawler gone"}`))
	if code != 200 || r["revision"] != float64(2) {
		t.Fatalf("%d %v", code, r)
	}
	if v, _ := st.Current(); v != tuning.Defaults() {
		t.Fatal("rollback did not restore defaults")
	}
	if code, r = call(t, "POST", base+"/rollback", admin, []byte(`{"expected_revision":0}`)); code != 409 {
		t.Fatalf("stale rollback: %d %v", code, r)
	}
}

func TestTuningAPI_ConcurrentAppliesDoNotCorrupt(t *testing.T) {
	ts, _, admin, _, st := rulesServer(t)
	var wg sync.WaitGroup
	codes := make([]int, 8)
	for i := range codes {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			body := `{"expected_revision":0,"values":{"port_scan_distinct_ports":` + string(rune('0'+5+i)) + `}}`
			codes[i], _ = call(t, "PUT", ts.URL+"/api/rules/tuning", admin, []byte(body))
		}(i)
	}
	wg.Wait()
	ok := 0
	for _, c := range codes {
		if c == 200 {
			ok++
		}
	}
	if ok != 1 {
		t.Fatalf("exactly one concurrent update may win, got %d (%v)", ok, codes)
	}
	if _, rev := st.Current(); rev != 1 {
		t.Fatalf("revision %d", rev)
	}
}

func TestTuningAPI_RuntimeHealthShowsIgnoredStoredTuning(t *testing.T) {
	ts, db, admin, _, _ := rulesServer(t)
	_, _ = call(t, "PUT", ts.URL+"/api/rules/tuning", admin, []byte(`{"expected_revision":0,"values":{"port_scan_distinct_ports":9}}`))
	_ = db.Model(&database.RuleTuningRevision{}).Where("id = ?", 1).Update("values", "garbage").Error
	// a restarted server over the same database
	st2 := tuning.Load(db)
	if st2.LoadError() == "" {
		t.Fatal("corrupt stored tuning must be reported")
	}
}
