package intel

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"gorm.io/gorm"

	"vanguard/core/internal/database"
)

func loadedMatcher(t *testing.T, recs ...string) (*Matcher, *database.DB) {
	t.Helper()
	db := testDB(t)
	if _, err := imp(t, db, feed("src", recs...), ImportOptions{}); err != nil {
		t.Fatal(err)
	}
	m := NewMatcher(db)
	m.SetClock(func() time.Time { return t0 })
	if err := m.Reload(); err != nil {
		t.Fatal(err)
	}
	return m, db
}

func TestMatcher_ExactIPv4AndIPv6(t *testing.T) {
	m, _ := loadedMatcher(t, rec("ip", "203.0.113.7"), rec("ip", "2001:db8::bad"))
	for _, hit := range []string{"203.0.113.7", " 203.0.113.7 ", "::ffff:203.0.113.7", "2001:DB8:0:0:0:0:0:BAD", "2001:db8::bad"} {
		if len(m.MatchIP(hit)) != 1 {
			t.Errorf("%q should match", hit)
		}
	}
	for _, miss := range []string{"203.0.113.70", "203.0.113.6", "203.0.113.0", "2001:db8::bae", "2001:db8::ba", "::ffff:203.0.113.8", "garbage", "", "203.0.113.7/32", "203.0.113.7:443"} {
		if len(m.MatchIP(miss)) != 0 {
			t.Errorf("%q must not match", miss)
		}
	}
}

func TestMatcher_DomainExactNoSubstringNoSubdomain(t *testing.T) {
	m, _ := loadedMatcher(t, rec("domain", "evil.example.com"))
	for _, hit := range []string{"evil.example.com", "EVIL.Example.COM", "evil.example.com:8080", "evil.example.com."} {
		if len(m.MatchHost(hit)) != 1 {
			t.Errorf("%q should match", hit)
		}
	}
	for _, miss := range []string{"notevil.example.com", "a.evil.example.com", "evil.example.com.attacker.net", "evil.example.co", "example.com", "evil-example.com", ""} {
		if len(m.MatchHost(miss)) != 0 {
			t.Errorf("%q must not match", miss)
		}
	}
}

func TestMatcher_URL(t *testing.T) {
	m, _ := loadedMatcher(t, rec("url", "https://evil.example.com/dl/payload.bin?id=7"))
	if len(m.MatchURL("evil.example.com", "/dl/payload.bin?id=7")) != 1 {
		t.Error("exact url should match (scheme-agnostic)")
	}
	if len(m.MatchURL("Evil.Example.com:443", "/dl/payload.bin?id=7")) != 1 {
		t.Error("host case/default port must normalize")
	}
	for _, c := range [][2]string{
		{"evil.example.com", "/dl/payload.bin?id=8"},
		{"evil.example.com", "/dl/payload.bin"},
		{"evil.example.com", "/dl/payload.bin?id=7&x=1"},
		{"evil.example.com", "/dl/payload.bin/"},
		{"other.example.com", "/dl/payload.bin?id=7"},
		{"", "/dl/payload.bin?id=7"}, // Host not logged => unobservable
		{"evil.example.com", "dl/payload.bin?id=7"},
	} {
		if len(m.MatchURL(c[0], c[1])) != 0 {
			t.Errorf("%v must not match", c)
		}
	}
}

func TestMatcher_SHA256CaseAndNearMiss(t *testing.T) {
	h := strings.Repeat("ab", 32)
	m, _ := loadedMatcher(t, rec("sha256", h))
	if len(m.MatchSHA256(strings.ToUpper(h))) != 1 {
		t.Error("hash case must normalize")
	}
	for _, miss := range []string{h[:63], h + "0", strings.Repeat("ab", 31) + "ac", "", "zz"} {
		if len(m.MatchSHA256(miss)) != 0 {
			t.Errorf("%q must not match", miss)
		}
	}
}

func TestMatcher_ExpiredAtMatchTimeAndDisabledNeverMatch(t *testing.T) {
	m, db := loadedMatcher(t,
		rec("ip", "203.0.113.31", `"expires_at":"2026-10-02T00:00:00Z"`),
		rec("ip", "203.0.113.32", `"enabled":false`),
		rec("ip", "203.0.113.33"),
	)
	if len(m.MatchIP("203.0.113.31")) != 1 || len(m.MatchIP("203.0.113.32")) != 0 || len(m.MatchIP("203.0.113.33")) != 1 {
		t.Fatal("initial activity wrong")
	}
	// Time passes with NO reload: the snapshot is stale but expiry still holds.
	m.SetClock(func() time.Time { return t0.Add(48 * time.Hour) })
	if len(m.MatchIP("203.0.113.31")) != 0 {
		t.Fatal("expired indicator matched from a stale snapshot")
	}
	if len(m.MatchIP("203.0.113.33")) != 1 {
		t.Fatal("indicator without expiry must stay active")
	}
	// Operator disable takes effect on reload.
	rows, _ := db.ListIOCs(database.IOCFilter{Value: "203.0.113.33"})
	_, _ = db.SetIOCEnabled(rows[0].ID, false)
	_ = m.Reload()
	if len(m.MatchIP("203.0.113.33")) != 0 {
		t.Fatal("disabled indicator matched")
	}
}

func TestMatcher_MultipleIndicatorsOneObservation(t *testing.T) {
	db := testDB(t)
	imp(t, db, feed("a", rec("ip", "203.0.113.41", `"confidence":"low"`)), ImportOptions{})
	imp(t, db, feed("b", rec("ip", "203.0.113.41", `"confidence":"high"`)), ImportOptions{})
	m := NewMatcher(db)
	refs := m.MatchIP("203.0.113.41")
	if len(refs) != 2 || refs[0].Source == refs[1].Source {
		t.Fatalf("both sources must match: %+v", refs)
	}
}

func TestMatcher_IsMaliciousHonorsConfidence(t *testing.T) {
	db := testDB(t)
	imp(t, db, feed("f",
		rec("ip", "203.0.113.51", `"confidence":"high"`),
		rec("ip", "203.0.113.52", `"confidence":"medium"`),
		rec("ip", "203.0.113.53", `"confidence":"low"`),
		rec("ip", "203.0.113.54"),
	), ImportOptions{})
	m := NewMatcher(db)
	want := map[string]bool{"203.0.113.51": true, "203.0.113.52": true, "203.0.113.53": false, "203.0.113.54": false, "203.0.113.55": false}
	for ip, w := range want {
		if m.IsMalicious(ip) != w {
			t.Errorf("IsMalicious(%s) = %v, want %v", ip, !w, w)
		}
	}
}

func TestMatcher_ReloadFailureKeepsSnapshotAndIsVisible(t *testing.T) {
	m, db := loadedMatcher(t, rec("ip", "203.0.113.61"))
	_ = db.Callback().Query().Before("gorm:query").Register("test:fail_iocs", func(tx *gorm.DB) {
		if tx.Statement.Table == "iocs" {
			_ = tx.AddError(errors.New("db locked"))
		}
	})
	if err := m.Reload(); err == nil {
		t.Fatal("expected reload error")
	}
	if len(m.MatchIP("203.0.113.61")) != 1 {
		t.Fatal("a failed reload must not replace the snapshot with an empty set")
	}
	st := m.Status()
	if !st.Loaded || st.LastError == "" || st.Indicators != 1 {
		t.Fatalf("failure must be visible: %+v", st)
	}
}

func TestMatcher_NeverLoadedIsNotLoaded(t *testing.T) {
	db := testDB(t)
	_ = db.Callback().Query().Before("gorm:query").Register("test:fail_iocs2", func(tx *gorm.DB) {
		if tx.Statement.Table == "iocs" {
			_ = tx.AddError(errors.New("boom"))
		}
	})
	m := NewMatcher(db)
	if st := m.Status(); st.Loaded || st.LastError == "" {
		t.Fatalf("%+v", st)
	}
}

func TestMatcher_ConcurrentMatchAndReload(t *testing.T) {
	m, _ := loadedMatcher(t, rec("ip", "203.0.113.71"), rec("domain", "evil.example.com"))
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				if i%4 == 0 {
					_ = m.Reload()
				}
				_ = m.MatchIP("203.0.113.71")
				_ = m.MatchHost("evil.example.com")
				_ = m.Status()
			}
		}(i)
	}
	wg.Wait()
	if len(m.MatchIP("203.0.113.71")) != 1 {
		t.Fatal("lost indicator after concurrent reloads")
	}
}

func TestMatcher_RestartPersistence(t *testing.T) {
	m, db := loadedMatcher(t, rec("ip", "203.0.113.81"))
	_ = m
	m2 := NewMatcher(db) // "restart": fresh matcher over the same database
	m2.SetClock(func() time.Time { return t0 })
	_ = m2.Reload()
	if len(m2.MatchIP("203.0.113.81")) != 1 {
		t.Fatal("indicators must survive restart")
	}
}

func TestMatcher_RunRefusesSecondLoopAndStopsOnCancel(t *testing.T) {
	m, _ := loadedMatcher(t, rec("ip", "203.0.113.99"))
	ctx, cancel := context.WithCancel(context.Background())
	first := make(chan struct{})
	go func() { m.Run(ctx, time.Hour); close(first) }()
	deadline := time.Now().Add(2 * time.Second)
	for !m.running.Load() && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	second := make(chan struct{})
	go func() { m.Run(context.Background(), time.Hour); close(second) }()
	select {
	case <-second:
	case <-time.After(2 * time.Second):
		t.Fatal("a second Run must return immediately")
	}
	cancel()
	select {
	case <-first:
	case <-time.After(2 * time.Second):
		t.Fatal("Run must stop when its context is cancelled")
	}
	if m.running.Load() {
		t.Fatal("running flag must clear after the loop exits so it can be restarted")
	}
}
