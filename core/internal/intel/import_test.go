package intel

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gorm.io/gorm"

	"vanguard/core/internal/database"
)

var t0 = time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)

func testDB(t *testing.T) *database.DB {
	t.Helper()
	db, err := database.Open(database.Config{Path: filepath.Join(t.TempDir(), "i.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if s, err := db.DB.DB(); err == nil {
			s.Close()
		}
	})
	return db
}

func feed(source string, recs ...string) string {
	return fmt.Sprintf(`{"format":"vanguard-ioc","version":1,"source":%q,"indicators":[%s]}`, source, strings.Join(recs, ","))
}

func rec(typ, val string, extra ...string) string {
	s := fmt.Sprintf(`{"type":%q,"value":%q`, typ, val)
	for _, e := range extra {
		s += "," + e
	}
	return s + "}"
}

func imp(t *testing.T, db *database.DB, body string, o ImportOptions) (ImportReport, error) {
	t.Helper()
	o.Now = t0
	return Import(db, strings.NewReader(body), o)
}

func countIOCs(t *testing.T, db *database.DB) int {
	t.Helper()
	var n int64
	if err := db.Model(&database.IOC{}).Count(&n).Error; err != nil {
		t.Fatal(err)
	}
	return int(n)
}

func TestImport_HappyPathNormalizesAndReports(t *testing.T) {
	db := testDB(t)
	rep, err := imp(t, db, feed("f1",
		rec("ip", "::ffff:203.0.113.7", `"confidence":"high"`, `"description":"scanner"`),
		rec("domain", "Evil.Example.COM."),
		rec("url", "HTTP://evil.example.com:80/x#f"),
		rec("sha256", strings.ToUpper(strings.Repeat("ab", 32))),
	), ImportOptions{})
	if err != nil || rep.Status != "applied" || rep.Accepted != 4 || rep.Rejected != 0 {
		t.Fatalf("%+v %v", rep, err)
	}
	rows, _ := db.ListIOCs(database.IOCFilter{})
	got := map[string]string{}
	for _, r := range rows {
		got[string(r.Type)] = r.Value
		if r.Source != "f1" || !r.Enabled || r.ImportID != rep.ImportID {
			t.Errorf("provenance wrong: %+v", r)
		}
	}
	if got["ip"] != "203.0.113.7" || got["domain"] != "evil.example.com" || got["url"] != "http://evil.example.com/x" || got["sha256"] != strings.Repeat("ab", 32) {
		t.Errorf("not normalized: %v", got)
	}
}

func TestImport_JSONLFormat(t *testing.T) {
	db := testDB(t)
	body := `{"format":"vanguard-ioc","version":1,"source":"jl"}` + "\n" +
		rec("ip", "203.0.113.8") + "\n\n" + rec("domain", "bad.example.net") + "\n"
	rep, err := imp(t, db, body, ImportOptions{})
	if err != nil || rep.Accepted != 2 {
		t.Fatalf("%+v %v", rep, err)
	}
}

func TestImport_InvalidRecordsRejectedIndividually(t *testing.T) {
	db := testDB(t)
	rep, err := imp(t, db, feed("f",
		rec("ip", "203.0.113.9"),
		rec("ip", "999.1.1.1"),
		rec("file_path", "/etc/passwd"),
		rec("url", "http://u:p@evil.example.com/"),
		rec("domain", "ok.example.com", `"confidence":"certain"`),
		rec("domain", "d.example.com", `"description":"`+strings.Repeat("x", 600)+`"`),
		`{"type":"ip","value":"203.0.113.10","surprise":1}`,
		rec("ip", "203.0.113.11", `"expires_at":"not-a-date"`),
	), ImportOptions{})
	if err != nil || rep.Accepted != 1 || rep.Rejected != 7 || len(rep.RejectSample) == 0 {
		t.Fatalf("%+v %v", rep, err)
	}
	if countIOCs(t, db) != 1 {
		t.Fatal("only the one valid record may be stored")
	}
}

func TestImport_StrictAbortsEverything(t *testing.T) {
	db := testDB(t)
	rep, err := imp(t, db, feed("f", rec("ip", "203.0.113.9"), rec("ip", "bad")), ImportOptions{Strict: true})
	if !errors.Is(err, ErrImportRejected) || rep.Status != "rejected" {
		t.Fatalf("%+v %v", rep, err)
	}
	if countIOCs(t, db) != 0 {
		t.Fatal("strict failure must write nothing")
	}
}

func TestImport_ExpiredAndDisabledAndNoExpiry(t *testing.T) {
	db := testDB(t)
	rep, err := imp(t, db, feed("f",
		rec("ip", "203.0.113.20", `"expires_at":"2026-09-01T00:00:00Z"`),
		rec("ip", "203.0.113.21", `"expires_at":"2027-01-01T00:00:00Z"`),
		rec("ip", "203.0.113.22"),
		rec("ip", "203.0.113.23", `"enabled":false`),
	), ImportOptions{})
	if err != nil || rep.Expired != 1 || rep.Accepted != 3 || rep.Disabled != 1 {
		t.Fatalf("%+v %v", rep, err)
	}
	active, total, _ := db.ActiveIOCs(t0, 100)
	if total != 2 || len(active) != 2 {
		t.Fatalf("active=%d total=%d (no-expiry must be active, disabled must not)", len(active), total)
	}
	// Later, the dated one expires but the no-expiry one stays active.
	_, total, _ = db.ActiveIOCs(t0.AddDate(1, 0, 0), 100)
	if total != 1 {
		t.Fatalf("after expiry active=%d", total)
	}
}

func TestImport_InFileAndCrossImportDuplicates(t *testing.T) {
	db := testDB(t)
	body := feed("f", rec("ip", "203.0.113.30"), rec("ip", "203.0.113.30"), rec("ip", "::ffff:203.0.113.30"))
	rep, _ := imp(t, db, body, ImportOptions{})
	if rep.Accepted != 1 || rep.Duplicate != 2 || countIOCs(t, db) != 1 {
		t.Fatalf("in-file dup: %+v", rep)
	}
	rep, _ = imp(t, db, body, ImportOptions{})
	if rep.Accepted != 0 || rep.Updated != 0 || rep.Duplicate != 3 || countIOCs(t, db) != 1 {
		t.Fatalf("re-import must be a no-op: %+v", rep)
	}
	rep, _ = imp(t, db, feed("f", rec("ip", "203.0.113.30", `"confidence":"high"`)), ImportOptions{})
	if rep.Updated != 1 || countIOCs(t, db) != 1 {
		t.Fatalf("changed metadata must update in place: %+v", rep)
	}
	// Same value from another source is a separate indicator.
	imp(t, db, feed("other", rec("ip", "203.0.113.30")), ImportOptions{})
	if countIOCs(t, db) != 2 {
		t.Fatal("(type,value,source) identity violated")
	}
}

func TestImport_OperatorDisableSurvivesReimport(t *testing.T) {
	db := testDB(t)
	imp(t, db, feed("f", rec("ip", "203.0.113.40")), ImportOptions{})
	rows, _ := db.ListIOCs(database.IOCFilter{})
	if _, err := db.SetIOCEnabled(rows[0].ID, false); err != nil {
		t.Fatal(err)
	}
	imp(t, db, feed("f", rec("ip", "203.0.113.40", `"description":"updated"`)), ImportOptions{})
	got, _ := db.GetIOC(rows[0].ID)
	if got.Enabled || got.Description != "updated" {
		t.Fatalf("operator disable must persist while metadata refreshes: %+v", got)
	}
}

func TestImport_StructuralRejections(t *testing.T) {
	db := testDB(t)
	imp(t, db, feed("keep", rec("ip", "203.0.113.50")), ImportOptions{})
	bad := map[string]string{
		"empty":                "",
		"not json":             "hello world",
		"wrong format":         `{"format":"stix","version":1,"source":"x","indicators":[]}`,
		"wrong version":        `{"format":"vanguard-ioc","version":2,"source":"x","indicators":[` + rec("ip", "203.0.113.51") + `]}`,
		"no source":            `{"format":"vanguard-ioc","version":1,"indicators":[` + rec("ip", "203.0.113.51") + `]}`,
		"bad source":           feed("Bad Source!", rec("ip", "203.0.113.51")),
		"no indicators":        feed("x"),
		"all invalid":          feed("x", rec("ip", "nope"), rec("ip", "nope2")),
		"all expired":          feed("x", rec("ip", "203.0.113.52", `"expires_at":"2020-01-01T00:00:00Z"`)),
		"truncated json":       `{"format":"vanguard-ioc","version":1,"source":"x","indicators":[` + rec("ip", "203.0.113.53"),
		"malformed jsonl line": `{"format":"vanguard-ioc","version":1,"source":"x"}` + "\n" + rec("ip", "203.0.113.54") + "\n{broken\n",
		"bad generated_at":     `{"format":"vanguard-ioc","version":1,"source":"x","generated_at":"yesterday","indicators":[` + rec("ip", "203.0.113.55") + `]}`,
	}
	for name, body := range bad {
		rep, err := imp(t, db, body, ImportOptions{})
		if !errors.Is(err, ErrImportRejected) || rep.Status != "rejected" || rep.Error == "" {
			t.Errorf("%s: want rejection, got %+v err=%v", name, rep, err)
		}
	}
	if countIOCs(t, db) != 1 {
		t.Fatalf("failed imports must leave existing intelligence untouched, have %d", countIOCs(t, db))
	}
	imports, _ := db.ListIOCImports(100)
	rejected := 0
	for _, i := range imports {
		if i.Status == "rejected" {
			rejected++
		}
	}
	if rejected != len(bad) {
		t.Errorf("every rejected attempt must leave an audit row, got %d/%d", rejected, len(bad))
	}
}

func TestImport_SourceConflictWithOption(t *testing.T) {
	db := testDB(t)
	if _, err := imp(t, db, feed("a", rec("ip", "203.0.113.60")), ImportOptions{Source: "b"}); !errors.Is(err, ErrImportRejected) {
		t.Fatalf("conflicting source must be rejected: %v", err)
	}
	body := `{"format":"vanguard-ioc","version":1,"indicators":[` + rec("ip", "203.0.113.60") + `]}`
	if rep, err := imp(t, db, body, ImportOptions{Source: "from-cli"}); err != nil || rep.Source != "from-cli" {
		t.Fatalf("option source should fill a missing header source: %+v %v", rep, err)
	}
}

func TestImport_SizeAndRecordLimits(t *testing.T) {
	db := testDB(t)
	huge := feed("big", rec("ip", "203.0.113.70", `"description":"`+strings.Repeat("a", MaxImportBytes)+`"`))
	if rep, err := imp(t, db, huge, ImportOptions{}); !errors.Is(err, ErrImportRejected) || !strings.Contains(rep.Error, "exceeds") {
		t.Fatalf("oversize: %+v %v", rep, err)
	}
	var sb strings.Builder
	sb.WriteString(`{"format":"vanguard-ioc","version":1,"source":"many","indicators":[`)
	for i := 0; i <= MaxImportRecords; i++ {
		if i > 0 {
			sb.WriteByte(',')
		}
		fmt.Fprintf(&sb, `{"type":"ip","value":"10.%d.%d.%d"}`, (i>>16)&255, (i>>8)&255, i&255)
	}
	sb.WriteString("]}")
	if rep, err := imp(t, db, sb.String(), ImportOptions{}); !errors.Is(err, ErrImportRejected) || !strings.Contains(rep.Error, "max") {
		t.Fatalf("too many records: %+v %v", rep, err)
	}
	if countIOCs(t, db) != 0 {
		t.Fatal("rejected oversize imports must write nothing")
	}
}

func TestImport_LargeButPermittedInput(t *testing.T) {
	db := testDB(t)
	var sb strings.Builder
	sb.WriteString(`{"format":"vanguard-ioc","version":1,"source":"large","indicators":[`)
	n := 5000
	for i := 0; i < n; i++ {
		if i > 0 {
			sb.WriteByte(',')
		}
		fmt.Fprintf(&sb, `{"type":"ip","value":"198.51.%d.%d","description":"bulk"}`, (i>>8)&255, i&255)
	}
	sb.WriteString("]}")
	rep, err := imp(t, db, sb.String(), ImportOptions{})
	if err != nil || rep.Accepted != n {
		t.Fatalf("%+v %v", rep, err)
	}
}

func TestImport_ReplaceSourceGuards(t *testing.T) {
	db := testDB(t)
	var initial []string
	for i := 1; i <= 10; i++ {
		initial = append(initial, rec("ip", fmt.Sprintf("203.0.113.%d", 100+i)))
	}
	imp(t, db, feed("rp", initial...), ImportOptions{})
	imp(t, db, feed("untouched", rec("ip", "203.0.113.200")), ImportOptions{})

	// A one-record feed would wipe 90% of the source: refused.
	if _, err := imp(t, db, feed("rp", rec("ip", "203.0.113.101")), ImportOptions{ReplaceSource: true}); !errors.Is(err, ErrImportRejected) {
		t.Fatalf("shrink guard missing: %v", err)
	}
	if countIOCs(t, db) != 11 {
		t.Fatalf("refused replace must change nothing, have %d", countIOCs(t, db))
	}
	// Mostly-invalid feed refused.
	if _, err := imp(t, db, feed("rp", rec("ip", "203.0.113.101"), rec("ip", "x"), rec("ip", "y")), ImportOptions{ReplaceSource: true, AllowShrink: true}); !errors.Is(err, ErrImportRejected) {
		t.Fatalf("invalid-ratio guard missing: %v", err)
	}
	// Reasonable replace: 8 of the 10 + 1 new => 2 removed, other source untouched.
	var next []string
	for i := 1; i <= 8; i++ {
		next = append(next, rec("ip", fmt.Sprintf("203.0.113.%d", 100+i)))
	}
	next = append(next, rec("ip", "203.0.113.150"))
	rep, err := imp(t, db, feed("rp", next...), ImportOptions{ReplaceSource: true})
	if err != nil || rep.Removed != 2 || rep.Accepted != 1 {
		t.Fatalf("%+v %v", rep, err)
	}
	if countIOCs(t, db) != 8+1+1 {
		t.Fatalf("have %d", countIOCs(t, db))
	}
}

func TestImport_TransactionRollsBackOnMidwayFailure(t *testing.T) {
	db := testDB(t)
	imp(t, db, feed("keep", rec("ip", "203.0.113.80")), ImportOptions{})
	created := 0
	_ = db.Callback().Create().Before("gorm:create").Register("test:fail_third", func(tx *gorm.DB) {
		if tx.Statement.Table == "iocs" {
			created++
			if created == 3 {
				_ = tx.AddError(errors.New("disk full"))
			}
		}
	})
	rep, err := imp(t, db, feed("new", rec("ip", "203.0.113.81"), rec("ip", "203.0.113.82"), rec("ip", "203.0.113.83"), rec("ip", "203.0.113.84")), ImportOptions{})
	if !errors.Is(err, ErrImportRejected) || rep.Accepted != 0 {
		t.Fatalf("%+v %v", rep, err)
	}
	if countIOCs(t, db) != 1 {
		t.Fatalf("partial apply leaked: %d rows", countIOCs(t, db))
	}
}

func TestIOCStore_MigratesOntoExistingDatabase(t *testing.T) {
	path := filepath.Join(t.TempDir(), "old.db")
	db, err := database.Open(database.Config{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	inc := &database.Incident{Type: database.IncidentPortScan, SourceIP: "203.0.113.5", RiskScore: 10}
	_ = db.CreateIncident(inc)
	_ = db.Migrator().DropTable(&database.IOC{}, &database.IOCImport{}, &database.IOCMatch{})
	s, _ := db.DB.DB()
	s.Close()
	db2, err := database.Open(database.Config{Path: path})
	if err != nil {
		t.Fatalf("migrate old db: %v", err)
	}
	defer func() { s, _ := db2.DB.DB(); s.Close() }()
	if _, err := db2.GetIncident(inc.ID); err != nil {
		t.Fatal("pre-existing incident lost")
	}
	if rep, err := imp(t, db2, feed("f", rec("ip", "203.0.113.90")), ImportOptions{}); err != nil || rep.Accepted != 1 {
		t.Fatalf("import on migrated db: %+v %v", rep, err)
	}
}

func TestIOC_PersistenceAcrossReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "p.db")
	db, _ := database.Open(database.Config{Path: path})
	imp(t, db, feed("f", rec("ip", "203.0.113.91")), ImportOptions{})
	s, _ := db.DB.DB()
	s.Close()
	db2, _ := database.Open(database.Config{Path: path})
	defer func() { s, _ := db2.DB.DB(); s.Close() }()
	if _, total, _ := db2.ActiveIOCs(t0, 10); total != 1 {
		t.Fatal("indicator lost across reopen")
	}
}
