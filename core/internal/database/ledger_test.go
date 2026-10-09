package database

import (
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

var t0 = time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)

func ledgerDB(t *testing.T) *DB {
	t.Helper()
	db, err := Open(Config{Path: filepath.Join(t.TempDir(), "l.db")})
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

func addAudits(t *testing.T, db *DB, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		if err := db.RecordAdminAudit(&AdminAudit{At: t0.Add(time.Duration(i) * time.Second), Actor: "a@x", Action: "firewall.block", Target: "203.0.113.1", Result: "ok"}); err != nil {
			t.Fatal(err)
		}
	}
}

func mustSeal(t *testing.T, db *DB) SealResult {
	t.Helper()
	r, err := db.SealPending(t0.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func mustVerify(t *testing.T, db *DB) *VerifyReport {
	t.Helper()
	r, err := db.VerifyLedger(VerifyOptions{})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func kinds(r *VerifyReport) string {
	var k []string
	for _, f := range r.Findings {
		k = append(k, f.Kind)
	}
	return strings.Join(k, ",")
}

func TestLedger_ValidChainAcrossAllCoveredTables(t *testing.T) {
	db := ledgerDB(t)
	addAudits(t, db, 3)
	_ = db.RecordBackupAudit(&BackupAudit{At: t0, Kind: "create", Actor: "cli", BackupName: "b1", Result: "ok"})
	_ = db.RecordRetentionRun(&RetentionRun{StartedAt: t0, Actor: "cli", Mode: RetentionModeDryRun, Status: RetentionStatusPreview})
	_ = db.Create(&RuleTuningRevision{CreatedAt: t0, Actor: "admin", Kind: "apply", Status: "active", Values: `{"a":1}`}).Error
	r := mustSeal(t, db)
	if r.Sealed != 6 || r.Remaining {
		t.Fatalf("%+v", r)
	}
	v := mustVerify(t, db)
	if !v.OK || !v.Completed || v.Partial || v.Examined != 6 || v.HeadSeq != 6 || v.LegacyEntries != 6 {
		t.Fatalf("%+v", v)
	}
	// later records are NOT legacy, and the mutable tuning status does not break verification
	addAudits(t, db, 1)
	db.Model(&RuleTuningRevision{}).Where("id = 1").Update("status", "superseded")
	mustSeal(t, db)
	v = mustVerify(t, db)
	if !v.OK || v.HeadSeq != 7 || v.LegacyEntries != 6 {
		t.Fatalf("%+v kinds=%s", v, kinds(v))
	}
}

func TestLedger_UnsealedTailIsReportedNotAccused(t *testing.T) {
	db := ledgerDB(t)
	addAudits(t, db, 2)
	mustSeal(t, db)
	addAudits(t, db, 3)
	v := mustVerify(t, db)
	if !v.OK || v.Unsealed[LedgerAdminAudits] != 3 {
		t.Fatalf("recent records are pending, not a discrepancy: %+v", v)
	}
	if empty := mustVerify(t, ledgerDB(t)); !empty.OK || !empty.Completed || empty.HeadSeq != 0 {
		t.Fatalf("an empty ledger verifies as nothing-to-verify: %+v", empty)
	}
}

func TestLedger_DetectsModifiedAndDeletedRecords(t *testing.T) {
	db := ledgerDB(t)
	addAudits(t, db, 4)
	mustSeal(t, db)
	if err := db.Exec("UPDATE admin_audits SET actor = 'someone-else' WHERE id = 2").Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Exec("DELETE FROM admin_audits WHERE id = 3").Error; err != nil {
		t.Fatal(err)
	}
	v := mustVerify(t, db)
	if v.OK || !strings.Contains(kinds(v), "modified_record") || !strings.Contains(kinds(v), "missing_record") {
		t.Fatalf("tampering must be detected: %+v", v)
	}
	for _, f := range v.Findings {
		if f.Kind == "modified_record" && (f.RecordID != 2 || f.Table != LedgerAdminAudits) {
			t.Fatalf("finding should name the record: %+v", f)
		}
		if strings.Contains(f.Detail, "someone-else") {
			t.Fatal("findings must not echo record content")
		}
	}
}

func TestLedger_DetectsEntryTampering(t *testing.T) {
	cases := map[string]struct {
		sql  string
		want string
	}{
		"digest edited without rehash": {"UPDATE audit_ledger SET record_digest = '" + strings.Repeat("0", 64) + "' WHERE seq = 2", "bad_entry_hash"},
		"link edited":                  {"UPDATE audit_ledger SET prev_hash = '" + strings.Repeat("1", 64) + "' WHERE seq = 3", "broken_link"},
		"entry deleted (gap)":          {"DELETE FROM audit_ledger WHERE seq = 2", "sequence_gap"},
		"last entry truncated":         {"DELETE FROM audit_ledger WHERE seq = 4", ""}, // detected by checkpoints, see below
		"unknown format":               {"UPDATE audit_ledger SET format = 99 WHERE seq = 2", "unknown_format"},
		"time edited":                  {"UPDATE audit_ledger SET sealed_at = '2020-01-01T00:00:00Z' WHERE seq = 2", "bad_entry_hash"},
	}
	for name, c := range cases {
		db := ledgerDB(t)
		addAudits(t, db, 4)
		mustSeal(t, db)
		if err := db.Exec(c.sql).Error; err != nil {
			t.Fatal(name, err)
		}
		v := mustVerify(t, db)
		if c.want == "" {
			if v.HeadSeq != 3 {
				t.Errorf("%s: head %d", name, v.HeadSeq)
			}
			continue // a truncated tail is internally consistent; only an external checkpoint can see it
		}
		if v.OK || !strings.Contains(kinds(v), c.want) {
			t.Errorf("%s: want %s, got ok=%v %s", name, c.want, v.OK, kinds(v))
		}
	}
}

func TestLedger_UnledgeredRowBehindTheFrontier(t *testing.T) {
	db := ledgerDB(t)
	addAudits(t, db, 3)
	mustSeal(t, db)
	// remove a ledger entry AND re-point the rest cannot be done without breaking the hash; an inserted
	// row below the frontier needs a free id: delete a record+entry pair, then re-insert a forged row with that id
	db.Exec("DELETE FROM admin_audits WHERE id = 2")
	v := mustVerify(t, db)
	if v.OK || !strings.Contains(kinds(v), "missing_record") {
		t.Fatalf("%s", kinds(v))
	}
	db.Exec("INSERT INTO admin_audits (id, at, actor, action, result) VALUES (2, '2026-10-10 12:00:00', 'forged', 'x', 'ok')")
	v = mustVerify(t, db)
	if v.OK || !strings.Contains(kinds(v), "modified_record") {
		t.Fatalf("a forged replacement must be a modified record: %s", kinds(v))
	}
}

func TestLedger_ConsistentRewriteIsInvisibleToTheChainButCaughtByACheckpoint(t *testing.T) {
	db := ledgerDB(t)
	addAudits(t, db, 5)
	mustSeal(t, db)
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}
	cp, err := db.MakeCheckpoint(key, t0)
	if err != nil {
		t.Fatal(err)
	}
	if f := db.CheckCheckpoint(*cp, key); len(f) != 0 {
		t.Fatalf("an untouched ledger must match its checkpoint: %+v", f)
	}

	// A privileged attacker edits record 2, then recomputes the digest and every later hash.
	db.Exec("UPDATE admin_audits SET actor = 'attacker-chosen' WHERE id = 2")
	var rows []AuditLedgerEntry
	db.Order("seq ASC").Find(&rows)
	prev := GenesisHash
	for _, e := range rows {
		e.PrevHash = prev
		d, _, _ := recordDigest(db.DB, e.Kind, e.RecordID)
		e.RecordDigest = d
		e.Hash = EntryHash(e)
		db.Save(&e)
		prev = e.Hash
	}
	v := mustVerify(t, db)
	if !v.OK {
		t.Fatalf("the point of this test: a consistent rewrite passes chain verification (%s) - that is the stated limit", kinds(v))
	}
	f := db.CheckCheckpoint(*cp, key)
	if len(f) != 1 || f[0].Kind != "checkpoint_mismatch" {
		t.Fatalf("the external checkpoint must expose the rewrite: %+v", f)
	}

	// truncation is exposed too
	db.Exec("DELETE FROM audit_ledger WHERE seq >= 3")
	if f := db.CheckCheckpoint(*cp, key); len(f) != 1 || f[0].Kind != "checkpoint_entry_missing" {
		t.Fatalf("%+v", f)
	}
}

func TestCheckpoint_AuthenticityAndKeys(t *testing.T) {
	db := ledgerDB(t)
	addAudits(t, db, 2)
	mustSeal(t, db)
	key := []byte(strings.Repeat("k", 32))
	cp, _ := db.MakeCheckpoint(key, t0)
	forged := *cp
	forged.Seq = 1
	if f := db.CheckCheckpoint(forged, key); len(f) != 1 || f[0].Kind != "checkpoint_forged" {
		t.Fatalf("an edited checkpoint must fail its MAC: %+v", f)
	}
	other := []byte(strings.Repeat("z", 32))
	if f := db.CheckCheckpoint(*cp, other); len(f) != 1 || f[0].Kind != "checkpoint_key_mismatch" {
		t.Fatalf("a different key is reported as such, not as tampering: %+v", f)
	}
	if _, err := ParseKey("short"); err == nil {
		t.Fatal("short key")
	}
	if _, err := ParseKey(strings.Repeat("zz", 32)); err == nil {
		t.Fatal("non-hex key")
	}
	if k, err := ParseKey(strings.Repeat("ab", 32) + "\n"); err != nil || len(k) != 32 {
		t.Fatal(err)
	}
	if _, err := ledgerDB(t).MakeCheckpoint(key, t0); err == nil {
		t.Fatal("an empty ledger has nothing to checkpoint")
	}
	if KeyID(key) == KeyID(other) || strings.Contains(KeyID(key), string(key[:4])) {
		t.Fatal("key id")
	}
}

func TestLedger_ConcurrentWritersAndSealersKeepOneGaplessChain(t *testing.T) {
	db := ledgerDB(t)
	var wg sync.WaitGroup
	for w := 0; w < 6; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < 15; i++ {
				_ = db.RecordAdminAudit(&AdminAudit{Actor: "w", Action: "x", Result: "ok", Target: string(rune('a' + w))})
				if i%3 == 0 {
					_, _ = db.SealPending(time.Now())
				}
			}
		}(w)
	}
	wg.Wait()
	for i := 0; i < 5; i++ {
		if r := mustSeal(t, db); !r.Remaining {
			break
		}
	}
	v := mustVerify(t, db)
	if !v.OK || v.HeadSeq != 90 || v.Unsealed[LedgerAdminAudits] != 0 {
		t.Fatalf("%+v %s", v, kinds(v))
	}
}

func TestLedger_SealIsAllOrNothing(t *testing.T) {
	db := ledgerDB(t)
	addAudits(t, db, 3)
	// the third insert into the ledger fails
	if err := db.Exec(`CREATE TRIGGER stop_at_3 BEFORE INSERT ON audit_ledger WHEN NEW.seq = 3 BEGIN SELECT RAISE(ABORT, 'boom'); END`).Error; err != nil {
		t.Fatal(err)
	}
	if _, err := db.SealPending(t0); err == nil {
		t.Fatal("expected failure")
	}
	var n int64
	db.Model(&AuditLedgerEntry{}).Count(&n)
	if n != 0 {
		t.Fatalf("a failed seal left %d partial entries", n)
	}
	db.Exec("DROP TRIGGER stop_at_3")
	if r := mustSeal(t, db); r.Sealed != 3 {
		t.Fatalf("%+v", r)
	}
	if v := mustVerify(t, db); !v.OK {
		t.Fatal(kinds(v))
	}
}

func TestLedger_BatchCapAndPartialVerification(t *testing.T) {
	db := ledgerDB(t)
	addAudits(t, db, MaxSealBatch+5)
	r := mustSeal(t, db)
	if r.Sealed != MaxSealBatch || !r.Remaining {
		t.Fatalf("%+v", r)
	}
	if r = mustSeal(t, db); r.Sealed != 5 || r.Remaining || r.Legacy {
		t.Fatalf("%+v", r)
	}
	v, _ := db.VerifyLedger(VerifyOptions{MaxEntries: 100})
	if !v.Partial || v.Completed || v.Examined != 100 || v.NextSeq != 101 || !v.OK {
		t.Fatalf("%+v", v)
	}
	v2, _ := db.VerifyLedger(VerifyOptions{FromSeq: v.NextSeq, MaxEntries: 5000})
	if !v2.Completed || !v2.OK || v2.Examined != MaxSealBatch+5-100 {
		t.Fatalf("%+v", v2)
	}
	// a window starting after a tampered link still checks the link into it
	db.Exec("UPDATE audit_ledger SET prev_hash = '" + strings.Repeat("2", 64) + "' WHERE seq = 101")
	if v3, _ := db.VerifyLedger(VerifyOptions{FromSeq: 101}); v3.OK {
		t.Fatal("tampering at the window boundary must be seen")
	}
}

func TestLedger_VerifyIsReadOnly(t *testing.T) {
	db := ledgerDB(t)
	addAudits(t, db, 5)
	mustSeal(t, db)
	snap := func() [3]int64 {
		var a, b, c int64
		db.Model(&AuditLedgerEntry{}).Count(&a)
		db.Model(&AdminAudit{}).Count(&b)
		db.Raw("SELECT COALESCE(SUM(length(hash)),0) FROM audit_ledger").Scan(&c)
		return [3]int64{a, b, c}
	}
	before := snap()
	db.Exec("UPDATE admin_audits SET actor='x' WHERE id=1") // even on a damaged database
	mid := snap()
	mustVerify(t, db)
	mustVerify(t, db)
	if snap() != mid || before != mid {
		t.Fatal("verification changed the database")
	}
}

func TestCanonicalSerialization_IsUnambiguous(t *testing.T) {
	a := sum(canon("t", "ab", "c"))
	b := sum(canon("t", "a", "bc"))
	c := sum(canon("t", "ab", "c", ""))
	if a == b || a == c {
		t.Fatal("field boundaries must be part of the encoding")
	}
	if sum(canon("t", "x")) == sum(canon("u", "x")) {
		t.Fatal("the tag must be bound")
	}
	// delimiter smuggling: a value containing what looks like another field
	if sum(canon("t", "a\x01b", "c")) == sum(canon("t", "a", "b\x01c")) {
		t.Fatal("content must not be able to forge a boundary")
	}
}
