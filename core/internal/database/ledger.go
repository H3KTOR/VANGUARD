package database

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"sync"
	"time"

	"gorm.io/gorm"
)

// The audit ledger (Phase 15).
//
// WHAT IT IS: an append-only hash chain of digests of audit records. Each
// entry commits to (format version, sequence, time, source table, record id,
// the SHA-256 of the record's canonical content, and the previous entry's
// hash). Re-computing the chain and re-reading the records detects a modified
// record, a deleted record, a record inserted behind the sealed frontier, a
// missing or reordered ledger entry and a broken link.
//
// WHAT IT IS NOT: proof against someone who can write the database file AND
// recompute the chain - that person can rewrite history consistently. The only
// defence against that is an anchor outside the database (see checkpoint.go).
//
// WHICH RECORDS: only tables VANGUARD never prunes - admin_audits,
// backup_audits, retention_runs, rule_tuning_revisions. Pruned/soft-deleted
// data (incident_events, notes, ioc imports) is NOT covered, because a legal
// deletion would be indistinguishable from tampering without a second
// mechanism.
//
// WHEN: records are sealed shortly AFTER they are written, by one serialized
// sealer (SealPending), not inside the writer's transaction. So there is a
// short window (the "unsealed" tail, reported by Verify) in which a record
// could be altered or removed undetectably.

// LedgerFormat is the canonical-serialization version of ledger entries.
const LedgerFormat = 1

// Source table names covered by the ledger.
const (
	LedgerAdminAudits   = "admin_audits"
	LedgerBackupAudits  = "backup_audits"
	LedgerRetentionRuns = "retention_runs"
	LedgerTuning        = "rule_tuning_revisions"
)

// LedgerKinds is the fixed, ordered list of covered tables.
var LedgerKinds = []string{LedgerAdminAudits, LedgerBackupAudits, LedgerRetentionRuns, LedgerTuning}

// MaxSealBatch bounds how many records one SealPending call seals.
const MaxSealBatch = 2000

// AuditLedgerEntry is one link of the chain.
type AuditLedgerEntry struct {
	Seq          uint64    `gorm:"primaryKey;autoIncrement:false" json:"seq"`
	Format       int       `gorm:"not null" json:"format"`
	SealedAt     string    `gorm:"size:40;not null" json:"sealed_at"` // RFC3339Nano UTC, stored as text so it hashes exactly
	Kind         string    `gorm:"size:32;not null;index:idx_ledger_kind_record,priority:1" json:"kind"`
	RecordID     uint      `gorm:"not null;index:idx_ledger_kind_record,priority:2" json:"record_id"`
	RecordDigest string    `gorm:"size:64;not null" json:"record_digest"`
	PrevHash     string    `gorm:"size:64;not null" json:"prev_hash"`
	Hash         string    `gorm:"size:64;not null" json:"hash"`
	Legacy       bool      `gorm:"not null" json:"legacy"` // sealed at upgrade time, not at creation time
	CreatedAt    time.Time `json:"-"`
}

// TableName pins the table name.
func (AuditLedgerEntry) TableName() string { return "audit_ledger" }

// GenesisHash is the PrevHash of sequence 1.
var GenesisHash = hex.EncodeToString(make([]byte, 32))

// canon is the canonical serialization: for every field, an unsigned varint
// length followed by the raw bytes. It is unambiguous (no delimiter can be
// forged by field content), and it starts with a fixed domain-separation tag.
func canon(tag string, fields ...string) []byte {
	buf := make([]byte, 0, 64+len(fields)*16)
	var tmp [binary.MaxVarintLen64]byte
	put := func(s string) {
		n := binary.PutUvarint(tmp[:], uint64(len(s)))
		buf = append(buf, tmp[:n]...)
		buf = append(buf, s...)
	}
	put(tag)
	n := binary.PutUvarint(tmp[:], uint64(len(fields)))
	buf = append(buf, tmp[:n]...)
	for _, f := range fields {
		put(f)
	}
	return buf
}

func sum(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }

func ts(t time.Time) string { return t.UTC().Format(time.RFC3339Nano) }
func u(n uint) string       { return strconv.FormatUint(uint64(n), 10) }
func b2s(b bool) string {
	if b {
		return "1"
	}
	return "0"
}

// EntryHash computes the hash of an entry from its fields (not its own Hash).
func EntryHash(e AuditLedgerEntry) string {
	return sum(canon("vanguard.audit.entry", strconv.Itoa(e.Format), strconv.FormatUint(e.Seq, 10), e.SealedAt, e.Kind,
		u(e.RecordID), e.RecordDigest, e.PrevHash, b2s(e.Legacy)))
}

// recordDigest returns the digest of the canonical content of one record, or
// false if it does not exist. Mutable bookkeeping columns are excluded
// (rule_tuning_revisions.status flips active->superseded by design).
func recordDigest(tx *gorm.DB, kind string, id uint) (string, bool, error) {
	switch kind {
	case LedgerAdminAudits:
		var r AdminAudit
		if err := tx.Where("id = ?", id).Take(&r).Error; err != nil {
			return "", false, notFound(err)
		}
		return digestAdmin(r), true, nil
	case LedgerBackupAudits:
		var r BackupAudit
		if err := tx.Where("id = ?", id).Take(&r).Error; err != nil {
			return "", false, notFound(err)
		}
		return digestBackup(r), true, nil
	case LedgerRetentionRuns:
		var r RetentionRun
		if err := tx.Where("id = ?", id).Take(&r).Error; err != nil {
			return "", false, notFound(err)
		}
		return digestRetention(r), true, nil
	case LedgerTuning:
		var r RuleTuningRevision
		if err := tx.Where("id = ?", id).Take(&r).Error; err != nil {
			return "", false, notFound(err)
		}
		return digestTuning(r), true, nil
	}
	return "", false, fmt.Errorf("unknown ledger kind %q", kind)
}

func notFound(err error) error {
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil
	}
	return err
}

func digestAdmin(r AdminAudit) string {
	return sum(canon("admin_audits.v1", u(r.ID), ts(r.At), r.Actor, r.ActorRole, r.Action, r.Target, r.Result, r.Detail))
}
func digestBackup(r BackupAudit) string {
	return sum(canon("backup_audits.v1", u(r.ID), ts(r.At), r.Kind, r.Actor, r.BackupName, r.DBSHA256, r.Result, r.Detail))
}
func digestRetention(r RetentionRun) string {
	fin := ""
	if r.FinishedAt != nil {
		fin = ts(*r.FinishedAt)
	}
	return sum(canon("retention_runs.v1", u(r.ID), ts(r.StartedAt), fin, r.Actor, r.Mode, r.Status,
		strconv.Itoa(r.PolicyRevision), strconv.Itoa(r.PolicyDays), ts(r.Cutoff),
		strconv.FormatInt(r.EligibleTotal, 10), strconv.FormatInt(r.IncidentsDeleted, 10), strconv.FormatInt(r.EventsDeleted, 10),
		strconv.FormatInt(r.NotesDeleted, 10), strconv.FormatInt(r.MatchesUnlinked, 10), strconv.FormatInt(r.RulesUnlinked, 10),
		strconv.FormatInt(r.SkippedActive, 10), strconv.FormatInt(r.SkippedNotes, 10), strconv.Itoa(r.Batches),
		u(r.MinID), u(r.MaxID), r.Detail))
}
func digestTuning(r RuleTuningRevision) string {
	return sum(canon("rule_tuning_revisions.v1", u(r.ID), ts(r.CreatedAt), r.Actor, r.Reason, r.Kind, r.Values, r.Changes,
		b2s(r.WeakeningAcknowledged), u(r.RolledBackTo)))
}

var sealMu sync.Mutex

// SealResult describes one SealPending run.
type SealResult struct {
	Sealed    int  `json:"sealed"`
	Remaining bool `json:"more_pending"` // the batch cap was reached
	Legacy    bool `json:"legacy"`       // these entries sealed pre-existing records
}

// SealPending appends ledger entries for audit records created since the last
// seal, at most MaxSealBatch per call, in one transaction (all or nothing). It
// is serialized in-process; a concurrent writer in another process is caught
// by the primary key on seq and the call returns an error to retry.
func (db *DB) SealPending(now time.Time) (SealResult, error) {
	sealMu.Lock()
	defer sealMu.Unlock()
	var res SealResult
	err := db.Transaction(func(tx *gorm.DB) error {
		var head AuditLedgerEntry
		headFound := true
		if err := tx.Order("seq DESC").Take(&head).Error; err != nil {
			if !errors.Is(err, gorm.ErrRecordNotFound) {
				return err
			}
			headFound = false
		}
		res.Legacy = !headFound // the first-ever seal covers records that pre-date the ledger
		prev, seq := GenesisHash, uint64(0)
		if headFound {
			prev, seq = head.Hash, head.Seq
		}
		type pending struct {
			kind string
			id   uint
			at   time.Time
		}
		var todo []pending
		budget := MaxSealBatch
		for _, kind := range LedgerKinds {
			if budget <= 0 {
				res.Remaining = true
				break
			}
			var cursor uint
			if err := tx.Model(&AuditLedgerEntry{}).Where("kind = ?", kind).Select("COALESCE(MAX(record_id),0)").Scan(&cursor).Error; err != nil {
				return err
			}
			var ids []uint
			if err := tx.Table(kind).Where("id > ?", cursor).Order("id ASC").Limit(budget+1).Pluck("id", &ids).Error; err != nil {
				return err
			}
			if len(ids) > budget {
				ids = ids[:budget]
				res.Remaining = true
			}
			for _, id := range ids {
				todo = append(todo, pending{kind: kind, id: id})
			}
			budget -= len(ids)
		}
		for _, p := range todo {
			d, ok, err := recordDigest(tx, p.kind, p.id)
			if err != nil {
				return err
			}
			if !ok {
				continue // vanished between the id scan and the read: nothing to seal
			}
			seq++
			e := AuditLedgerEntry{Seq: seq, Format: LedgerFormat, SealedAt: ts(now), Kind: p.kind, RecordID: p.id,
				RecordDigest: d, PrevHash: prev, Legacy: res.Legacy}
			e.Hash = EntryHash(e)
			if err := tx.Create(&e).Error; err != nil {
				return err
			}
			prev = e.Hash
			res.Sealed++
		}
		return nil
	})
	if err != nil {
		return SealResult{}, err
	}
	return res, nil
}

// VerifyOptions bounds a verification.
type VerifyOptions struct {
	FromSeq    uint64 // first entry to check (0 = 1). Entries before it are trusted only via their hash link.
	MaxEntries int    // default and cap: MaxVerifyEntries
}

// MaxVerifyEntries bounds one verification pass.
const MaxVerifyEntries = 100000

// Finding is one detected discrepancy (identifiers only, never record content).
type Finding struct {
	Kind     string `json:"kind"`
	Seq      uint64 `json:"seq,omitempty"`
	Table    string `json:"table,omitempty"`
	RecordID uint   `json:"record_id,omitempty"`
	Detail   string `json:"detail"`
}

// VerifyReport is the result of a read-only verification.
type VerifyReport struct {
	Completed     bool             `json:"completed"` // the whole ledger from FromSeq to the head was examined
	Partial       bool             `json:"partial"`   // MaxEntries was reached; continue from NextSeq
	NextSeq       uint64           `json:"next_seq,omitempty"`
	FromSeq       uint64           `json:"from_seq"`
	Examined      int              `json:"entries_examined"`
	HeadSeq       uint64           `json:"head_seq"`
	HeadHash      string           `json:"head_hash"`
	LegacyEntries int              `json:"legacy_entries"`   // sealed at upgrade time: integrity before that moment is not established
	Unsealed      map[string]int64 `json:"unsealed_records"` // records created after the sealed frontier (normal, short-lived)
	Findings      []Finding        `json:"findings"`
	OK            bool             `json:"ok"` // no discrepancy found IN WHAT WAS EXAMINED; see the trust assumptions in docs/PHASE15.md
	EarliestSeq   uint64           `json:"earliest_verified_seq,omitempty"`
	FirstSealedAt string           `json:"first_sealed_at,omitempty"`
}

const maxFindings = 50

// VerifyLedger re-computes the chain and re-reads the sealed records. It only
// runs SELECT statements. With FromSeq > 1 the entry before FromSeq is read and
// the chain is checked from there (a prefix is not re-verified).
func (db *DB) VerifyLedger(o VerifyOptions) (*VerifyReport, error) {
	max := o.MaxEntries
	if max <= 0 || max > MaxVerifyEntries {
		max = MaxVerifyEntries
	}
	from := o.FromSeq
	if from == 0 {
		from = 1
	}
	rep := &VerifyReport{FromSeq: from, Findings: []Finding{}, Unsealed: map[string]int64{}}
	add := func(f Finding) {
		if len(rep.Findings) < maxFindings {
			rep.Findings = append(rep.Findings, f)
		}
	}

	var head AuditLedgerEntry
	if err := db.Order("seq DESC").Take(&head).Error; err != nil {
		if !errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, err
		}
		rep.Completed = true // an empty ledger: nothing sealed yet
	} else {
		rep.HeadSeq, rep.HeadHash = head.Seq, head.Hash
	}

	prevHash := GenesisHash
	if from > 1 {
		var p AuditLedgerEntry
		if err := db.Where("seq = ?", from-1).Take(&p).Error; err != nil {
			add(Finding{Kind: "missing_entry", Seq: from - 1, Detail: "the entry before the verification window is missing"})
			prevHash = ""
		} else {
			prevHash = p.Hash
		}
	}

	if rep.HeadSeq > 0 {
		expect := from
		const page = 1000
		last := from - 1
		for rep.Examined < max {
			var rows []AuditLedgerEntry
			lim := page
			if rem := max - rep.Examined; rem < lim {
				lim = rem
			}
			if err := db.Where("seq > ?", last).Order("seq ASC").Limit(lim).Find(&rows).Error; err != nil {
				return nil, err
			}
			if len(rows) == 0 {
				break
			}
			for _, e := range rows {
				rep.Examined++
				last = e.Seq
				if rep.FirstSealedAt == "" {
					rep.FirstSealedAt = e.SealedAt
				}
				if e.Seq != expect {
					add(Finding{Kind: "sequence_gap", Seq: expect, Detail: fmt.Sprintf("expected entry %d but found %d (entries missing or reordered)", expect, e.Seq)})
					expect = e.Seq
					prevHash = ""
				}
				expect++
				if e.Format != LedgerFormat {
					add(Finding{Kind: "unknown_format", Seq: e.Seq, Detail: fmt.Sprintf("format %d is not understood by this build", e.Format)})
					prevHash = ""
					continue
				}
				if prevHash != "" && e.PrevHash != prevHash {
					add(Finding{Kind: "broken_link", Seq: e.Seq, Detail: "prev_hash does not match the previous entry's hash"})
				}
				if EntryHash(e) != e.Hash {
					add(Finding{Kind: "bad_entry_hash", Seq: e.Seq, Detail: "the entry's hash does not match its contents"})
				}
				prevHash = e.Hash
				if e.Legacy {
					rep.LegacyEntries++
				}
				// the record itself
				d, ok, err := recordDigest(db.DB, e.Kind, e.RecordID)
				if err != nil {
					add(Finding{Kind: "unreadable_record", Seq: e.Seq, Table: e.Kind, RecordID: e.RecordID, Detail: "the record could not be read"})
					continue
				}
				switch {
				case !ok:
					add(Finding{Kind: "missing_record", Seq: e.Seq, Table: e.Kind, RecordID: e.RecordID, Detail: "a sealed record no longer exists"})
				case d != e.RecordDigest:
					add(Finding{Kind: "modified_record", Seq: e.Seq, Table: e.Kind, RecordID: e.RecordID, Detail: "a sealed record's content differs from what was sealed"})
				}
			}
			if len(rows) < lim {
				break
			}
		}
		if rep.Examined > 0 {
			rep.EarliestSeq = from
		}
		if last < rep.HeadSeq {
			rep.Partial = true
			rep.NextSeq = last + 1
		} else {
			rep.Completed = true
		}
		if last == rep.HeadSeq && rep.HeadSeq > 0 && prevHash != "" && prevHash != rep.HeadHash {
			add(Finding{Kind: "head_mismatch", Seq: rep.HeadSeq, Detail: "the last entry examined is not the ledger head"})
		}
	}

	// Records beyond the sealed frontier (unsealed, normal) and rows hidden
	// BEHIND it (a row inserted with an old id would have no entry).
	for _, kind := range LedgerKinds {
		var cursor uint
		if err := db.Model(&AuditLedgerEntry{}).Where("kind = ?", kind).Select("COALESCE(MAX(record_id),0)").Scan(&cursor).Error; err != nil {
			return nil, err
		}
		var after, behind, sealed int64
		db.Table(kind).Where("id > ?", cursor).Count(&after)
		if cursor > 0 && rep.Completed && from <= 1 {
			db.Table(kind).Where("id <= ?", cursor).Count(&behind)
			db.Model(&AuditLedgerEntry{}).Where("kind = ?", kind).Count(&sealed)
			if behind > sealed {
				add(Finding{Kind: "unledgered_records", Table: kind, Detail: fmt.Sprintf("%d record(s) exist below the sealed frontier without a ledger entry", behind-sealed)})
			}
		}
		rep.Unsealed[kind] = after
	}
	rep.OK = len(rep.Findings) == 0
	return rep, nil
}
