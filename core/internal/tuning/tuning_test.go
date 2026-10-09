package tuning

import (
	"errors"
	"path/filepath"
	"sync"
	"testing"

	"vanguard/core/internal/database"
)

func newStore(t *testing.T) (*Store, *database.DB, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "t.db")
	db, err := database.Open(database.Config{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if s, err := db.DB.DB(); err == nil {
			s.Close()
		}
	})
	return Load(db), db, path
}

func ip(n int) *int { return &n }

func TestDefaultsMatchCompiledAndValidate(t *testing.T) {
	d := Defaults()
	if errs := Validate(d); len(errs) != 0 {
		t.Fatalf("defaults must be inside their own ranges: %v", errs)
	}
	for _, sp := range Specs() {
		if sp.Default < sp.Min || sp.Default > sp.Max {
			t.Errorf("%s default %d outside %d..%d", sp.Key, sp.Default, sp.Min, sp.Max)
		}
	}
	s, _, _ := newStore(t)
	if v, rev := s.Current(); v != d || rev != 0 {
		t.Fatalf("fresh store must serve defaults at revision 0: %+v %d", v, rev)
	}
}

func TestValidateBoundaries(t *testing.T) {
	for _, sp := range Specs() {
		for _, c := range []struct {
			v  int
			ok bool
		}{{sp.Min - 1, false}, {sp.Min, true}, {sp.Max, true}, {sp.Max + 1, false}, {-5, false}, {0, false}} {
			v := Defaults()
			*v.field(sp.Key) = c.v
			if got := len(Validate(v)) == 0; got != c.ok {
				t.Errorf("%s=%d valid=%v want %v", sp.Key, c.v, got, c.ok)
			}
		}
	}
}

func TestPreviewNeverMutates(t *testing.T) {
	s, db, _ := newStore(t)
	pv := s.Preview(Patch{SSHBruteForceMinAttempts: ip(50)})
	if pv.Applied || !pv.RequiresAcknowledgement || len(pv.Changes) != 1 || !pv.Changes[0].Weakens || len(pv.Errors) != 0 {
		t.Fatalf("%+v", pv)
	}
	if v, rev := s.Current(); v != Defaults() || rev != 0 {
		t.Fatal("preview changed the effective values")
	}
	var n int64
	db.Model(&database.RuleTuningRevision{}).Count(&n)
	if n != 0 {
		t.Fatal("preview wrote to the history")
	}
	bad := s.Preview(Patch{SSHBruteForceMinAttempts: ip(1)})
	if len(bad.Errors) == 0 {
		t.Fatal("out-of-range preview must report errors")
	}
}

func TestApplyTighteningNeedsNoAckWeakeningDoes(t *testing.T) {
	s, _, _ := newStore(t)
	rev, err := s.Apply(0, Patch{SSHBruteForceMinAttempts: ip(5)}, "admin@x", "tighten", false)
	if err != nil || rev != 1 {
		t.Fatalf("lowering a threshold (more sensitive) is allowed: %v", err)
	}
	if _, err := s.Apply(1, Patch{SSHBruteForceMinAttempts: ip(40)}, "admin@x", "relax", false); !errors.Is(err, ErrNeedsAck) {
		t.Fatalf("raising a threshold must need explicit acknowledgement: %v", err)
	}
	if v, rev := s.Current(); v.SSHBruteForceMinAttempts != 5 || rev != 1 {
		t.Fatal("a refused change must not apply")
	}
	if rev, err = s.Apply(1, Patch{SSHBruteForceMinAttempts: ip(40)}, "admin@x", "relax: expected scanner traffic", true); err != nil || rev != 2 {
		t.Fatal(err)
	}
	h, _ := s.History(10)
	if len(h) != 2 || h[0].Status != "active" || h[1].Status != "superseded" || !h[0].WeakeningAcknowledged || h[0].Actor != "admin@x" || h[0].Changes[0].From != 5 || h[0].Changes[0].To != 40 {
		t.Fatalf("history: %+v", h)
	}
}

func TestApplyIsAtomicAndValidated(t *testing.T) {
	s, _, _ := newStore(t)
	// one valid field + one invalid field: nothing may be applied
	_, err := s.Apply(0, Patch{SSHBruteForceMinAttempts: ip(5), HTTPFloodMaxRequests: ip(10)}, "a@x", "", true)
	if !errors.Is(err, ErrInvalid) {
		t.Fatalf("%v", err)
	}
	if v, rev := s.Current(); v != Defaults() || rev != 0 {
		t.Fatal("a partially valid update must not partially apply")
	}
	if _, err := s.Apply(0, Patch{}, "a@x", "", true); !errors.Is(err, ErrNoChange) {
		t.Fatalf("empty patch: %v", err)
	}
	if _, err := s.Apply(0, Patch{SSHBruteForceMinAttempts: ip(5)}, "  ", "", false); !errors.Is(err, ErrNoActor) {
		t.Fatalf("an actor is mandatory: %v", err)
	}
}

func TestConcurrentApplyExactlyOneWins(t *testing.T) {
	s, db, _ := newStore(t)
	var wg sync.WaitGroup
	results := make([]error, 12)
	for i := range results {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, results[i] = s.Apply(0, Patch{SSHBruteForceMinAttempts: ip(4 + i)}, "a@x", "race", true)
		}(i)
	}
	wg.Wait()
	ok := 0
	for _, e := range results {
		switch {
		case e == nil:
			ok++
		case errors.Is(e, ErrConflict):
		default:
			// SQLite lock contention surfaces as a plain error; it must
			// still not have applied anything.
		}
	}
	if ok != 1 {
		t.Fatalf("exactly one concurrent update based on revision 0 may succeed, got %d", ok)
	}
	var active int64
	db.Model(&database.RuleTuningRevision{}).Where("status = ?", "active").Count(&active)
	if active != 1 {
		t.Fatalf("exactly one active revision, got %d", active)
	}
	if _, rev := s.Current(); rev != 1 {
		t.Fatalf("revision = %d", rev)
	}
}

func TestStaleRevisionConflicts(t *testing.T) {
	s, _, _ := newStore(t)
	_, _ = s.Apply(0, Patch{PortScanDistinctPorts: ip(10)}, "a@x", "", false)
	if _, err := s.Apply(0, Patch{PortScanDistinctPorts: ip(9)}, "b@x", "", false); !errors.Is(err, ErrConflict) {
		t.Fatalf("a request based on an outdated revision must conflict: %v", err)
	}
	if _, err := s.Rollback(0, "b@x", ""); !errors.Is(err, ErrConflict) {
		t.Fatalf("rollback with a stale revision: %v", err)
	}
}

func TestRollbackRestoresPreviousValuesAndKeepsHistory(t *testing.T) {
	s, _, _ := newStore(t)
	if _, err := s.Rollback(0, "a@x", ""); !errors.Is(err, ErrNothingToRevert) {
		t.Fatalf("%v", err)
	}
	_, _ = s.Apply(0, Patch{WebDirScanMin404s: ip(4)}, "a@x", "one", false)
	_, _ = s.Apply(1, Patch{WebDirScanMin404s: ip(6)}, "a@x", "two", true)
	rev, err := s.Rollback(2, "b@x", "bad idea")
	if err != nil || rev != 3 {
		t.Fatalf("%v rev=%d", err, rev)
	}
	if v, _ := s.Current(); v.WebDirScanMin404s != 4 {
		t.Fatalf("rollback must restore the preceding revision's values: %+v", v)
	}
	h, _ := s.History(10)
	if len(h) != 3 || h[0].Kind != "rollback" || h[0].RolledBackTo != 1 || h[0].Actor != "b@x" {
		t.Fatalf("history must record the rollback as its own revision: %+v", h)
	}
	// rolling back the first override returns to compiled defaults
	s2, _, _ := newStore(t)
	_, _ = s2.Apply(0, Patch{WebDirScanMin404s: ip(4)}, "a@x", "", false)
	if _, err := s2.Rollback(1, "a@x", ""); err != nil {
		t.Fatal(err)
	}
	if v, _ := s2.Current(); v != Defaults() {
		t.Fatalf("%+v", v)
	}
}

func TestPersistenceAcrossRestartAndLastKnownValid(t *testing.T) {
	s, db, _ := newStore(t)
	_, _ = s.Apply(0, Patch{HTTPFloodMaxRequests: ip(1000)}, "a@x", "", true)
	s2 := Load(db) // "restart"
	if v, rev := s2.Current(); v.HTTPFloodMaxRequests != 1000 || rev != 1 || s2.LoadError() != "" {
		t.Fatalf("%+v %d %q", v, rev, s2.LoadError())
	}

	// corrupt the active row: the store must fall back to defaults, say so,
	// and still allow an operator to supersede it (no lock-out).
	if err := db.Model(&database.RuleTuningRevision{}).Where("id = ?", 1).Update("values", "{not json").Error; err != nil {
		t.Fatal(err)
	}
	s3 := Load(db)
	if v, _ := s3.Current(); v != Defaults() || s3.LoadError() == "" {
		t.Fatalf("corrupt stored tuning must be ignored loudly: %+v %q", v, s3.LoadError())
	}
	if _, err := s3.Apply(1, Patch{HTTPFloodMaxRequests: ip(500)}, "a@x", "repair", true); err != nil {
		t.Fatalf("operator must be able to repair: %v", err)
	}
	// out-of-range stored values are also refused at load
	_ = db.Model(&database.RuleTuningRevision{}).Where("status = ?", "active").Update("values", `{"ssh_bruteforce_min_attempts":1,"failed_then_success_min_failed":10,"port_scan_distinct_ports":15,"web_dir_scan_min_404s":8,"http_flood_max_requests":300}`)
	if s4 := Load(db); s4.LoadError() == "" {
		t.Fatal("out-of-range stored values must not be activated")
	}
}

func TestNoCodeOrExpressionSurface(t *testing.T) {
	// The only input type is a set of integers keyed by a fixed key list.
	if len(Keys()) != 5 {
		t.Fatalf("tunable surface changed unexpectedly: %v", Keys())
	}
	for _, sp := range Specs() {
		if sp.Min < 1 {
			t.Errorf("%s allows a value below 1, which could disable a rule", sp.Key)
		}
	}
}
