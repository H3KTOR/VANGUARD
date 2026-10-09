package database

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"gorm.io/gorm"
)

// Checkpoint is an OPTIONAL trust anchor kept OUTSIDE the database: the ledger
// head (sequence and hash) at a moment in time, authenticated with an HMAC key
// that lives in a file only the operator controls. Someone who rewrites the
// database and recomputes the chain cannot make an earlier checkpoint match
// unless the history up to that sequence is byte-identical, and cannot forge a
// new checkpoint without the key.
//
// Limits, stated plainly: a checkpoint proves the chain up to its sequence was
// what it was when the checkpoint was made - not that the records were true to
// begin with, and not anything about entries after it. If the key and the
// database are both on the machine an attacker controls, the anchor is not
// independent: copy checkpoints (and keep the key) elsewhere.
type Checkpoint struct {
	Format    int    `json:"format"`
	Seq       uint64 `json:"seq"`
	Hash      string `json:"hash"`
	CreatedAt string `json:"created_at"`
	KeyID     string `json:"key_id"` // non-secret fingerprint of the key
	MAC       string `json:"mac"`
}

// ErrNoKey / ErrBadKey describe key problems.
var (
	ErrBadKey = errors.New("the checkpoint key must be 64 hexadecimal characters (32 random bytes)")
)

// ParseKey decodes a key file's content.
func ParseKey(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if len(s) != 64 {
		return nil, ErrBadKey
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, ErrBadKey
	}
	return b, nil
}

// KeyID is a short non-secret fingerprint used to tell keys apart (rotation).
func KeyID(key []byte) string {
	h := sha256.Sum256(append([]byte("vanguard.audit.keyid\x00"), key...))
	return hex.EncodeToString(h[:6])
}

func checkpointMAC(key []byte, c Checkpoint) string {
	m := hmac.New(sha256.New, key)
	m.Write(canon("vanguard.audit.checkpoint", strconv.Itoa(c.Format), strconv.FormatUint(c.Seq, 10), c.Hash, c.CreatedAt, c.KeyID))
	return hex.EncodeToString(m.Sum(nil))
}

// MakeCheckpoint captures the current ledger head. It refuses an empty ledger.
func (db *DB) MakeCheckpoint(key []byte, now time.Time) (*Checkpoint, error) {
	var head AuditLedgerEntry
	if err := db.Order("seq DESC").Take(&head).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, errors.New("the ledger is empty; nothing to checkpoint")
		}
		return nil, err
	}
	c := Checkpoint{Format: LedgerFormat, Seq: head.Seq, Hash: head.Hash, CreatedAt: ts(now), KeyID: KeyID(key)}
	c.MAC = checkpointMAC(key, c)
	return &c, nil
}

// CheckCheckpoint verifies the checkpoint's own authenticity and that this
// database's ledger still contains the same entry at that sequence.
func (db *DB) CheckCheckpoint(c Checkpoint, key []byte) []Finding {
	var out []Finding
	if c.Format != LedgerFormat {
		return []Finding{{Kind: "checkpoint_format", Detail: fmt.Sprintf("checkpoint format %d is not understood", c.Format)}}
	}
	if KeyID(key) != c.KeyID {
		return []Finding{{Kind: "checkpoint_key_mismatch", Detail: "this key is not the one that signed the checkpoint (rotated or wrong key); the checkpoint cannot be checked"}}
	}
	if !hmac.Equal([]byte(checkpointMAC(key, c)), []byte(c.MAC)) {
		return []Finding{{Kind: "checkpoint_forged", Detail: "the checkpoint's MAC is invalid: the file was altered or made with another key"}}
	}
	var e AuditLedgerEntry
	if err := db.Where("seq = ?", c.Seq).Take(&e).Error; err != nil {
		return []Finding{{Kind: "checkpoint_entry_missing", Seq: c.Seq, Detail: "the ledger no longer contains the checkpointed entry (history was truncated or replaced)"}}
	}
	if e.Hash != c.Hash {
		out = append(out, Finding{Kind: "checkpoint_mismatch", Seq: c.Seq, Detail: "the ledger entry at the checkpointed sequence differs from the checkpoint (history before it was rewritten)"})
	}
	return out
}
