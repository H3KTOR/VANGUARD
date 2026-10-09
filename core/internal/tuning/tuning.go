// Package tuning implements VANGUARD's safe, auditable operator overrides
// for a small set of detection thresholds.
//
// Only plain integer thresholds can be tuned, each inside a fixed
// [min,max] range. There is no rule expression, script or code input of
// any kind; a request is a set of numbers that is validated as a whole
// before it can take effect. Changes that make a rule LESS sensitive
// (a higher threshold) additionally require an explicit acknowledgement,
// and every apply/rollback is recorded in an append-only history with the
// acting identity. Nothing is ever applied automatically.
package tuning

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"gorm.io/gorm"

	"vanguard/core/internal/database"
	"vanguard/core/internal/thresholds"
)

// Values is the full set of tunable thresholds.
type Values struct {
	SSHBruteForceMinAttempts   int `json:"ssh_bruteforce_min_attempts"`
	FailedThenSuccessMinFailed int `json:"failed_then_success_min_failed"`
	PortScanDistinctPorts      int `json:"port_scan_distinct_ports"`
	WebDirScanMin404s          int `json:"web_dir_scan_min_404s"`
	HTTPFloodMaxRequests       int `json:"http_flood_max_requests"`
}

// Spec describes one tunable.
type Spec struct {
	Key         string `json:"key"`
	Rule        string `json:"rule_id"` // incident type the value controls
	Description string `json:"description"`
	Comparison  string `json:"comparison"` // how the rule uses the value
	Default     int    `json:"default"`
	Min         int    `json:"min"`
	Max         int    `json:"max"`
}

// Specs returns the tunables in a stable order.
func Specs() []Spec {
	return []Spec{
		{"ssh_bruteforce_min_attempts", "ssh_bruteforce", "failed SSH logins from one address inside the window", "fires when count > value", thresholds.SSHBruteForceMinAttempts, 3, 500},
		{"failed_then_success_min_failed", "failed_then_success_login", "failures from one address before a success that is treated as suspicious", "fires when failures >= value", thresholds.FailedThenSuccessMinFailed, 3, 500},
		{"port_scan_distinct_ports", "port_scan", "distinct decoy/other ports touched by one address inside the window", "fires when distinct ports > value", thresholds.PortScanDistinctPorts, 5, 500},
		{"web_dir_scan_min_404s", "web_directory_scan", "404 responses on sensitive paths from one address inside the window", "fires when count >= value", thresholds.WebDirScanMin404s, 3, 500},
		{"http_flood_max_requests", "http_flood", "requests from one address inside the window", "fires when requests > value", thresholds.HTTPFloodMaxRequests, 50, 100000},
	}
}

// Defaults returns the compiled default values.
func Defaults() Values {
	return Values{
		SSHBruteForceMinAttempts:   thresholds.SSHBruteForceMinAttempts,
		FailedThenSuccessMinFailed: thresholds.FailedThenSuccessMinFailed,
		PortScanDistinctPorts:      thresholds.PortScanDistinctPorts,
		WebDirScanMin404s:          thresholds.WebDirScanMin404s,
		HTTPFloodMaxRequests:       thresholds.HTTPFloodMaxRequests,
	}
}

func (v *Values) field(key string) *int {
	switch key {
	case "ssh_bruteforce_min_attempts":
		return &v.SSHBruteForceMinAttempts
	case "failed_then_success_min_failed":
		return &v.FailedThenSuccessMinFailed
	case "port_scan_distinct_ports":
		return &v.PortScanDistinctPorts
	case "web_dir_scan_min_404s":
		return &v.WebDirScanMin404s
	case "http_flood_max_requests":
		return &v.HTTPFloodMaxRequests
	}
	return nil
}

// Validate checks every value against its range.
func Validate(v Values) []string {
	var errs []string
	for _, sp := range Specs() {
		x := *v.field(sp.Key)
		if x < sp.Min || x > sp.Max {
			errs = append(errs, fmt.Sprintf("%s=%d is outside the allowed range %d..%d", sp.Key, x, sp.Min, sp.Max))
		}
	}
	return errs
}

// Change is one difference between two value sets.
type Change struct {
	Key  string `json:"key"`
	Rule string `json:"rule_id"`
	From int    `json:"from"`
	To   int    `json:"to"`
	// Weakens is true when the new value makes the rule fire less readily.
	// All tunables are "fires above/at value", so higher = less sensitive.
	Weakens bool `json:"weakens_detection"`
}

// Diff lists the changes needed to go from a to b (stable order).
func Diff(a, b Values) []Change {
	var out []Change
	for _, sp := range Specs() {
		from, to := *a.field(sp.Key), *b.field(sp.Key)
		if from != to {
			out = append(out, Change{Key: sp.Key, Rule: sp.Rule, From: from, To: to, Weakens: to > from})
		}
	}
	return out
}

// Patch carries optional fields: nil means "keep the current value".
type Patch struct {
	SSHBruteForceMinAttempts   *int `json:"ssh_bruteforce_min_attempts"`
	FailedThenSuccessMinFailed *int `json:"failed_then_success_min_failed"`
	PortScanDistinctPorts      *int `json:"port_scan_distinct_ports"`
	WebDirScanMin404s          *int `json:"web_dir_scan_min_404s"`
	HTTPFloodMaxRequests       *int `json:"http_flood_max_requests"`
}

// Merge applies p over base and returns the candidate set.
func (p Patch) Merge(base Values) Values {
	if p.SSHBruteForceMinAttempts != nil {
		base.SSHBruteForceMinAttempts = *p.SSHBruteForceMinAttempts
	}
	if p.FailedThenSuccessMinFailed != nil {
		base.FailedThenSuccessMinFailed = *p.FailedThenSuccessMinFailed
	}
	if p.PortScanDistinctPorts != nil {
		base.PortScanDistinctPorts = *p.PortScanDistinctPorts
	}
	if p.WebDirScanMin404s != nil {
		base.WebDirScanMin404s = *p.WebDirScanMin404s
	}
	if p.HTTPFloodMaxRequests != nil {
		base.HTTPFloodMaxRequests = *p.HTTPFloodMaxRequests
	}
	return base
}

// Errors returned by Apply / Rollback.
var (
	ErrConflict        = errors.New("configuration changed since the revision you based this on")
	ErrInvalid         = errors.New("invalid configuration")
	ErrNeedsAck        = errors.New("this change makes at least one rule less sensitive and requires explicit acknowledgement")
	ErrNoChange        = errors.New("no change")
	ErrNothingToRevert = errors.New("there is no earlier revision to roll back to")
	ErrNoActor         = errors.New("an authenticated actor is required")
)

type snapshot struct {
	vals Values
	rev  uint
}

// Store holds the effective values and persists their history.
type Store struct {
	db        *database.DB
	cur       atomic.Pointer[snapshot]
	loadError atomic.Value // string
}

// Load returns a Store initialised from the database. A corrupt or
// out-of-range stored revision is NOT applied: the store falls back to the
// compiled defaults and reports the problem via LoadError (health shows it
// as degraded). It never fails startup.
func Load(db *database.DB) *Store {
	s := &Store{db: db}
	s.cur.Store(&snapshot{vals: Defaults()})
	s.loadError.Store("")
	if db == nil {
		return s
	}
	var row database.RuleTuningRevision
	err := db.Where("status = ?", "active").Order("id DESC").First(&row).Error
	switch {
	case errors.Is(err, gorm.ErrRecordNotFound):
		return s
	case err != nil:
		s.loadError.Store("could not read the stored tuning: " + err.Error())
		return s
	}
	var v Values
	if jerr := json.Unmarshal([]byte(row.Values), &v); jerr != nil {
		s.loadError.Store(fmt.Sprintf("stored tuning revision %d is corrupt; using compiled defaults", row.ID))
		return s
	}
	if errs := Validate(v); len(errs) > 0 {
		s.loadError.Store(fmt.Sprintf("stored tuning revision %d is out of range (%s); using compiled defaults", row.ID, errs[0]))
		return s
	}
	s.cur.Store(&snapshot{vals: v, rev: row.ID})
	return s
}

// Current returns the effective values and their revision (0 = defaults).
func (s *Store) Current() (Values, uint) {
	c := s.cur.Load()
	return c.vals, c.rev
}

// Values satisfies the engine's small interface.
func (s *Store) Values() Values { v, _ := s.Current(); return v }

// Revision returns the active revision number.
func (s *Store) Revision() uint { _, r := s.Current(); return r }

// LoadError reports why stored tuning was ignored at startup ("" = none).
func (s *Store) LoadError() string { e, _ := s.loadError.Load().(string); return e }

func clean(s string, n int) string {
	s = strings.TrimSpace(strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, s))
	if len(s) > n {
		s = s[:n]
	}
	return s
}

// Preview validates a patch against the current values WITHOUT changing
// anything.
type Preview struct {
	BaseRevision            uint     `json:"base_revision"`
	Candidate               Values   `json:"candidate"`
	Changes                 []Change `json:"changes"`
	Errors                  []string `json:"errors"`
	RequiresAcknowledgement bool     `json:"requires_acknowledgement"`
	Applied                 bool     `json:"applied"` // always false
}

// Preview computes what Apply would do.
func (s *Store) Preview(p Patch) Preview {
	cur, rev := s.Current()
	cand := p.Merge(cur)
	pv := Preview{BaseRevision: rev, Candidate: cand, Errors: Validate(cand), Changes: Diff(cur, cand)}
	for _, c := range pv.Changes {
		if c.Weakens {
			pv.RequiresAcknowledgement = true
		}
	}
	if pv.Errors == nil {
		pv.Errors = []string{}
	}
	if pv.Changes == nil {
		pv.Changes = []Change{}
	}
	return pv
}

// Apply validates and activates a patch atomically, but only if
// expectedRev is still the active revision.
func (s *Store) Apply(expectedRev uint, p Patch, actor, reason string, ackWeakening bool) (uint, error) {
	if strings.TrimSpace(actor) == "" {
		return 0, ErrNoActor
	}
	var newRev uint
	var newVals Values
	err := s.db.Transaction(func(tx *gorm.DB) error {
		curVals, curRev, err := activeTx(tx)
		if err != nil {
			return err
		}
		if curRev != expectedRev {
			return ErrConflict
		}
		cand := p.Merge(curVals)
		if errs := Validate(cand); len(errs) > 0 {
			return fmt.Errorf("%w: %s", ErrInvalid, strings.Join(errs, "; "))
		}
		changes := Diff(curVals, cand)
		if len(changes) == 0 {
			return ErrNoChange
		}
		weak := false
		for _, c := range changes {
			weak = weak || c.Weakens
		}
		if weak && !ackWeakening {
			return ErrNeedsAck
		}
		row, err := insertActive(tx, cand, changes, "apply", actor, reason, weak && ackWeakening, 0, curRev)
		if err != nil {
			return err
		}
		newRev, newVals = row.ID, cand
		return nil
	})
	if err != nil {
		return 0, err
	}
	s.cur.Store(&snapshot{vals: newVals, rev: newRev})
	return newRev, nil
}

// Rollback re-activates the values of the revision that was active before
// the current one (as a NEW revision, so history stays linear and
// complete). expectedRev guards against concurrent changes.
func (s *Store) Rollback(expectedRev uint, actor, reason string) (uint, error) {
	if strings.TrimSpace(actor) == "" {
		return 0, ErrNoActor
	}
	var newRev uint
	var newVals Values
	err := s.db.Transaction(func(tx *gorm.DB) error {
		curVals, curRev, err := activeTx(tx)
		if err != nil {
			return err
		}
		if curRev != expectedRev {
			return ErrConflict
		}
		if curRev == 0 {
			return ErrNothingToRevert
		}
		// Previous effective values: the revision this one superseded.
		var prev database.RuleTuningRevision
		perr := tx.Where("id < ?", curRev).Order("id DESC").First(&prev).Error
		var target Values
		var targetRev uint
		switch {
		case errors.Is(perr, gorm.ErrRecordNotFound):
			target, targetRev = Defaults(), 0 // first override: roll back to defaults
		case perr != nil:
			return perr
		default:
			if jerr := json.Unmarshal([]byte(prev.Values), &target); jerr != nil || len(Validate(target)) > 0 {
				return fmt.Errorf("%w: revision %d cannot be restored", ErrInvalid, prev.ID)
			}
			targetRev = prev.ID
		}
		changes := Diff(curVals, target)
		if len(changes) == 0 {
			return ErrNoChange
		}
		// A rollback can raise thresholds (e.g. undoing a tightening). It is
		// an explicit operator act on a recorded revision, so it is allowed
		// without a separate acknowledgement but is flagged in the history.
		row, err := insertActive(tx, target, changes, "rollback", actor, reason, false, targetRev, curRev)
		if err != nil {
			return err
		}
		newRev, newVals = row.ID, target
		return nil
	})
	if err != nil {
		return 0, err
	}
	s.cur.Store(&snapshot{vals: newVals, rev: newRev})
	return newRev, nil
}

func activeTx(tx *gorm.DB) (Values, uint, error) {
	var row database.RuleTuningRevision
	err := tx.Where("status = ?", "active").Order("id DESC").First(&row).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return Defaults(), 0, nil
	}
	if err != nil {
		return Values{}, 0, err
	}
	var v Values
	if jerr := json.Unmarshal([]byte(row.Values), &v); jerr != nil || len(Validate(v)) > 0 {
		// A corrupt/out-of-range active row is not in effect (Load fell back
		// to the defaults). Treat the defaults as the base so an operator can
		// still supersede it with a valid revision instead of being locked out.
		return Defaults(), row.ID, nil
	}
	return v, row.ID, nil
}

func insertActive(tx *gorm.DB, v Values, changes []Change, kind, actor, reason string, ack bool, rolledBackTo, prevRev uint) (*database.RuleTuningRevision, error) {
	vb, _ := json.Marshal(v)
	cb, _ := json.Marshal(changes)
	if prevRev != 0 {
		if err := tx.Model(&database.RuleTuningRevision{}).Where("id = ?", prevRev).Update("status", "superseded").Error; err != nil {
			return nil, err
		}
	}
	row := database.RuleTuningRevision{
		CreatedAt: time.Now().UTC(), Actor: clean(actor, 128), Reason: clean(reason, 256), Kind: kind, Status: "active",
		Values: string(vb), Changes: string(cb), WeakeningAcknowledged: ack, RolledBackTo: rolledBackTo,
	}
	if err := tx.Create(&row).Error; err != nil {
		return nil, err
	}
	return &row, nil
}

// HistoryEntry is the API view of one revision.
type HistoryEntry struct {
	Revision              uint      `json:"revision"`
	CreatedAt             time.Time `json:"created_at"`
	Actor                 string    `json:"actor"`
	Reason                string    `json:"reason"`
	Kind                  string    `json:"kind"`
	Status                string    `json:"status"`
	WeakeningAcknowledged bool      `json:"weakening_acknowledged"`
	RolledBackTo          uint      `json:"rolled_back_to,omitempty"`
	Changes               []Change  `json:"changes"`
}

// History returns the most recent revisions, newest first (max 50).
func (s *Store) History(limit int) ([]HistoryEntry, error) {
	if limit <= 0 || limit > 50 {
		limit = 20
	}
	var rows []database.RuleTuningRevision
	if err := s.db.Order("id DESC").Limit(limit).Find(&rows).Error; err != nil {
		return nil, err
	}
	out := make([]HistoryEntry, 0, len(rows))
	for _, r := range rows {
		var ch []Change
		_ = json.Unmarshal([]byte(r.Changes), &ch)
		if ch == nil {
			ch = []Change{}
		}
		out = append(out, HistoryEntry{r.ID, r.CreatedAt, r.Actor, r.Reason, r.Kind, r.Status, r.WeakeningAcknowledged, r.RolledBackTo, ch})
	}
	return out, nil
}

// Keys lists the tunable keys (sorted) for tests/docs.
func Keys() []string {
	var k []string
	for _, s := range Specs() {
		k = append(k, s.Key)
	}
	sort.Strings(k)
	return k
}
