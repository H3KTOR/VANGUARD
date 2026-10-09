package intel

// Local threat-intelligence import: format "vanguard-ioc" version 1.
//
// JSON document:
//
//	{"format":"vanguard-ioc","version":1,"source":"my-feed",
//	 "generated_at":"2026-10-01T00:00:00Z",
//	 "indicators":[
//	   {"type":"ip","value":"203.0.113.7","description":"scanner",
//	    "reference":"https://example.invalid/report/1","confidence":"high",
//	    "expires_at":"2027-01-01T00:00:00Z","created_at":"2026-09-30T12:00:00Z",
//	    "enabled":true}]}
//
// JSONL: first line is the header object (without "indicators"), every
// following non-empty line is one indicator object.
//
// Semantics (see docs/PHASE6.md):
//   - structural problems (bad/oversize input, wrong format/version, bad or
//     conflicting source, over the record cap) reject the WHOLE import and
//     write nothing but an audit row;
//   - an invalid RECORD is rejected individually and reported; the valid
//     records are applied unless Strict is set (then any bad record
//     rejects everything);
//   - the apply step is a single database transaction;
//   - import is additive. ReplaceSource may delete that source's stale
//     indicators, but only behind guards that stop an empty, truncated or
//     mostly-invalid feed from wiping healthy intelligence;
//   - records already expired are reported, not stored; records the feed
//     marks enabled:false are stored disabled; a re-import never
//     re-enables an indicator an operator disabled.

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
	"time"

	"gorm.io/gorm"

	"vanguard/core/internal/database"
)

// Import limits.
const (
	FormatName            = "vanguard-ioc"
	FormatVersion         = 1
	MaxImportBytes        = 10 * 1024 * 1024
	MaxImportRecords      = 50000
	MaxActiveIOCs         = 100000
	maxRejectSample       = 10
	maxReplaceRejectRatio = 0.20
	minReplaceKeepRatio   = 0.50
)

var sourceRE = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)

// ErrImportRejected is wrapped by every whole-import rejection.
var ErrImportRejected = errors.New("import rejected")

// ImportOptions tunes one import.
type ImportOptions struct {
	// Source is used when the feed header carries none; if both are set
	// they must be equal.
	Source        string
	Strict        bool
	ReplaceSource bool
	AllowShrink   bool
	// Now is injectable for tests.
	Now time.Time
}

// ImportReport summarizes an import attempt. Counts are of INPUT records:
// Accepted (new) + Updated + Duplicate (unchanged) + Rejected + Expired
// partition the records that reached validation, minus in-file duplicates
// which are counted under Duplicate as well.
type ImportReport struct {
	ImportID     uint     `json:"import_id"`
	Status       string   `json:"status"` // applied | rejected
	Source       string   `json:"source"`
	Records      int      `json:"records"`
	Accepted     int      `json:"accepted"`
	Updated      int      `json:"updated"`
	Duplicate    int      `json:"duplicate"`
	Rejected     int      `json:"rejected"`
	Expired      int      `json:"expired"`
	Disabled     int      `json:"disabled"`
	Removed      int      `json:"removed"`
	RejectSample []string `json:"reject_sample,omitempty"`
	Error        string   `json:"error,omitempty"`
}

type feedHeader struct {
	Format      string            `json:"format"`
	Version     int               `json:"version"`
	Source      string            `json:"source"`
	GeneratedAt string            `json:"generated_at"`
	Indicators  []json.RawMessage `json:"indicators"`
}

type feedRecord struct {
	Type        string `json:"type"`
	Value       string `json:"value"`
	Description string `json:"description"`
	Reference   string `json:"reference"`
	Confidence  string `json:"confidence"`
	ExpiresAt   string `json:"expires_at"`
	CreatedAt   string `json:"created_at"`
	Enabled     *bool  `json:"enabled"`
}

type parsedRecord struct {
	idx     int // 1-based record number (line number for JSONL)
	typ     database.IOCType
	value   string
	desc    string
	ref     string
	conf    database.IOCConfidence
	expires *time.Time
	created *time.Time
	enabled bool
}

// Import reads a feed from r and applies it. The returned report is
// always populated; err wraps ErrImportRejected when nothing was applied.
func Import(db *database.DB, r io.Reader, opts ImportOptions) (ImportReport, error) {
	now := opts.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}
	rep := ImportReport{Status: "rejected", Source: opts.Source}

	data, err := io.ReadAll(io.LimitReader(r, MaxImportBytes+1))
	if err != nil {
		return reject(db, rep, opts, nil, 0, fmt.Errorf("read failed: %w", err))
	}
	sum := sha256.Sum256(data)
	hexSum := hex.EncodeToString(sum[:])
	if len(data) > MaxImportBytes {
		return reject(db, rep, opts, nil, hexSum, fmt.Errorf("input exceeds %d bytes", MaxImportBytes))
	}

	hdr, recs, perr := parseFeed(data)
	if perr != nil {
		return reject(db, rep, opts, nil, hexSum, perr)
	}
	if hdr.Format != FormatName {
		return reject(db, rep, opts, &hdr, hexSum, fmt.Errorf("unsupported format %q (want %q)", truncateForErr(hdr.Format), FormatName))
	}
	if hdr.Version != FormatVersion {
		return reject(db, rep, opts, &hdr, hexSum, fmt.Errorf("unsupported version %d (want %d)", hdr.Version, FormatVersion))
	}
	source := hdr.Source
	switch {
	case source == "" && opts.Source != "":
		source = opts.Source
	case source != "" && opts.Source != "" && source != opts.Source:
		return reject(db, rep, opts, &hdr, hexSum, fmt.Errorf("feed source %q conflicts with requested source %q", source, opts.Source))
	}
	if !sourceRE.MatchString(source) {
		return reject(db, rep, opts, &hdr, hexSum, errors.New("source must match ^[a-z0-9][a-z0-9._-]{0,63}$"))
	}
	rep.Source = source
	if len(recs) == 0 {
		return reject(db, rep, opts, &hdr, hexSum, errors.New("feed contains no indicators"))
	}
	if len(recs) > MaxImportRecords {
		return reject(db, rep, opts, &hdr, hexSum, fmt.Errorf("feed has %d records (max %d)", len(recs), MaxImportRecords))
	}
	var generated *time.Time
	if hdr.GeneratedAt != "" {
		t, e := time.Parse(time.RFC3339, hdr.GeneratedAt)
		if e != nil {
			return reject(db, rep, opts, &hdr, hexSum, errors.New("generated_at is not RFC3339"))
		}
		generated = &t
	}
	rep.Records = len(recs)

	// Per-record validation.
	var good []parsedRecord
	seen := map[string]bool{}
	for i, raw := range recs {
		idx := i + 1
		pr, e := parseRecord(raw, idx, now)
		switch {
		case e == errExpired:
			rep.Expired++
			continue
		case e != nil:
			rep.Rejected++
			if len(rep.RejectSample) < maxRejectSample {
				rep.RejectSample = append(rep.RejectSample, fmt.Sprintf("record %d: %v", idx, e))
			}
			continue
		}
		key := string(pr.typ) + "\x00" + pr.value
		if seen[key] {
			rep.Duplicate++
			continue
		}
		seen[key] = true
		good = append(good, pr)
	}
	if opts.Strict && rep.Rejected > 0 {
		return reject(db, rep, opts, &hdr, hexSum, fmt.Errorf("strict mode: %d invalid record(s)", rep.Rejected))
	}
	if len(good) == 0 {
		return reject(db, rep, opts, &hdr, hexSum, errors.New("no valid, unexpired indicators in feed (existing intelligence left untouched)"))
	}

	// Apply atomically.
	var imp database.IOCImport
	txErr := db.Transaction(func(tx *gorm.DB) error {
		var prevCount int64
		if err := tx.Model(&database.IOC{}).Where("source = ?", source).Count(&prevCount).Error; err != nil {
			return err
		}
		imp = database.IOCImport{
			Source: source, FormatVer: hdr.Version, Status: "applied", InputSHA256: hexSum, InputBytes: len(data),
			Records: rep.Records, Replace: opts.ReplaceSource, Strict: opts.Strict, GeneratedAt: generated, CreatedAt: now,
		}
		if err := tx.Create(&imp).Error; err != nil {
			return err
		}
		touched := make([]uint, 0, len(good))
		for _, g := range good {
			var cur database.IOC
			err := tx.Where("type = ? AND value = ? AND source = ?", g.typ, g.value, source).First(&cur).Error
			if errors.Is(err, gorm.ErrRecordNotFound) {
				row := database.IOC{
					Type: g.typ, Value: g.value, Source: source, Description: g.desc, Reference: g.ref,
					Confidence: g.conf, SourceCreatedAt: g.created, ExpiresAt: g.expires, Enabled: g.enabled, ImportID: imp.ID,
				}
				if err := tx.Create(&row).Error; err != nil {
					return err
				}
				touched = append(touched, row.ID)
				rep.Accepted++
				if !g.enabled {
					rep.Disabled++
				}
				continue
			}
			if err != nil {
				return err
			}
			touched = append(touched, cur.ID)
			enabled := g.enabled
			if cur.DisabledByOperator {
				enabled = false // an operator's disable is never undone by a feed
			}
			if cur.Description == g.desc && cur.Reference == g.ref && cur.Confidence == g.conf &&
				timeEq(cur.ExpiresAt, g.expires) && timeEq(cur.SourceCreatedAt, g.created) && cur.Enabled == enabled {
				rep.Duplicate++
				continue
			}
			if err := tx.Model(&cur).Updates(map[string]any{
				"description": g.desc, "reference": g.ref, "confidence": g.conf,
				"expires_at": g.expires, "source_created_at": g.created, "enabled": enabled, "import_id": imp.ID,
			}).Error; err != nil {
				return err
			}
			rep.Updated++
		}

		if opts.ReplaceSource {
			if float64(rep.Rejected)/float64(rep.Records) > maxReplaceRejectRatio {
				return fmt.Errorf("replace_source refused: more than %.0f%% of records are invalid", maxReplaceRejectRatio*100)
			}
			if !opts.AllowShrink && prevCount > 0 && float64(len(good)) < float64(prevCount)*minReplaceKeepRatio {
				return fmt.Errorf("replace_source refused: feed has %d valid records but source holds %d (>50%% shrink; set allow_shrink to override)", len(good), prevCount)
			}
			res := tx.Where("source = ? AND id NOT IN ?", source, touched).Delete(&database.IOC{})
			if res.Error != nil {
				return res.Error
			}
			rep.Removed = int(res.RowsAffected)
		}

		var total int64
		if err := tx.Model(&database.IOC{}).Count(&total).Error; err != nil {
			return err
		}
		if total > MaxActiveIOCs {
			return fmt.Errorf("indicator store would exceed %d entries", MaxActiveIOCs)
		}

		imp.Accepted, imp.Updated, imp.Duplicate, imp.Rejected = rep.Accepted, rep.Updated, rep.Duplicate, rep.Rejected
		imp.Expired, imp.Disabled, imp.Removed = rep.Expired, rep.Disabled, rep.Removed
		imp.RejectSample = strings.Join(rep.RejectSample, "\n")
		if err := tx.Save(&imp).Error; err != nil {
			return err
		}
		return nil
	})
	if txErr != nil {
		// Transaction rolled back: nothing was applied.
		rep.Accepted, rep.Updated, rep.Removed, rep.Disabled = 0, 0, 0, 0
		return reject(db, rep, opts, &hdr, hexSum, txErr)
	}
	rep.Status, rep.ImportID = "applied", imp.ID
	return rep, nil
}

var errExpired = errors.New("expired")

func reject(db *database.DB, rep ImportReport, opts ImportOptions, hdr *feedHeader, sum any, cause error) (ImportReport, error) {
	rep.Status = "rejected"
	msg := cause.Error()
	if len(msg) > 400 {
		msg = msg[:400]
	}
	rep.Error = msg
	row := database.IOCImport{
		Source: truncateStr(rep.Source, database.MaxIOCSourceLen), Status: "rejected", Error: msg,
		Records: rep.Records, Rejected: rep.Rejected, Expired: rep.Expired, Duplicate: rep.Duplicate,
		Replace: opts.ReplaceSource, Strict: opts.Strict, RejectSample: strings.Join(rep.RejectSample, "\n"),
		CreatedAt: time.Now().UTC(),
	}
	if s, ok := sum.(string); ok {
		row.InputSHA256 = s
	}
	if hdr != nil {
		row.FormatVer = hdr.Version
	}
	if err := db.RecordIOCImport(&row); err == nil {
		rep.ImportID = row.ID
	}
	return rep, fmt.Errorf("%w: %s", ErrImportRejected, msg)
}

func truncateStr(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

func timeEq(a, b *time.Time) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return a.Equal(*b)
}

// parseFeed accepts the JSON document form or JSONL.
func parseFeed(data []byte) (feedHeader, []json.RawMessage, error) {
	data = bytes.TrimSpace(data)
	if len(data) == 0 {
		return feedHeader{}, nil, errors.New("empty input")
	}
	var doc feedHeader
	if err := json.Unmarshal(data, &doc); err == nil {
		return doc, doc.Indicators, nil
	}
	// JSONL
	lines := bytes.Split(data, []byte("\n"))
	var hdr feedHeader
	headerSeen := false
	var recs []json.RawMessage
	for n, ln := range lines {
		ln = bytes.TrimSpace(ln)
		if len(ln) == 0 {
			continue
		}
		if len(ln) > 16*1024 {
			return feedHeader{}, nil, fmt.Errorf("line %d exceeds 16 KiB", n+1)
		}
		if !headerSeen {
			if err := json.Unmarshal(ln, &hdr); err != nil {
				return feedHeader{}, nil, errors.New("not a valid JSON document or JSONL (first line must be the header object)")
			}
			headerSeen = true
			continue
		}
		if !json.Valid(ln) {
			return feedHeader{}, nil, fmt.Errorf("line %d is not valid JSON (malformed stream rejected as a whole)", n+1)
		}
		recs = append(recs, json.RawMessage(append([]byte(nil), ln...)))
	}
	if !headerSeen {
		return feedHeader{}, nil, errors.New("no header")
	}
	return hdr, recs, nil
}

func parseRecord(raw json.RawMessage, idx int, now time.Time) (parsedRecord, error) {
	var fr feedRecord
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&fr); err != nil {
		return parsedRecord{}, fmt.Errorf("invalid record: %v", truncateForErr(err.Error()))
	}
	pr := parsedRecord{idx: idx, enabled: true}
	switch t := database.IOCType(strings.ToLower(strings.TrimSpace(fr.Type))); t {
	case database.IOCIP, database.IOCDomain, database.IOCURL, database.IOCSHA256:
		pr.typ = t
	default:
		return pr, fmt.Errorf("unsupported type %q", truncateForErr(fr.Type))
	}
	v, err := Normalize(pr.typ, fr.Value)
	if err != nil {
		return pr, err
	}
	pr.value = v
	if len(fr.Description) > database.MaxIOCDescriptionLen {
		return pr, fmt.Errorf("description longer than %d bytes", database.MaxIOCDescriptionLen)
	}
	if len(fr.Reference) > database.MaxIOCReferenceLen {
		return pr, fmt.Errorf("reference longer than %d bytes", database.MaxIOCReferenceLen)
	}
	pr.desc, pr.ref = cleanText(fr.Description), cleanText(fr.Reference)
	switch c := database.IOCConfidence(strings.ToLower(strings.TrimSpace(fr.Confidence))); c {
	case database.IOCConfidenceNone, database.IOCConfidenceLow, database.IOCConfidenceMedium, database.IOCConfidenceHigh:
		pr.conf = c
	default:
		return pr, fmt.Errorf("confidence must be low, medium, high or empty, got %q", truncateForErr(fr.Confidence))
	}
	if fr.ExpiresAt != "" {
		t, e := time.Parse(time.RFC3339, fr.ExpiresAt)
		if e != nil {
			return pr, errors.New("expires_at is not RFC3339")
		}
		t = t.UTC()
		pr.expires = &t
		if !now.Before(t) {
			return pr, errExpired
		}
	}
	if fr.CreatedAt != "" {
		t, e := time.Parse(time.RFC3339, fr.CreatedAt)
		if e != nil {
			return pr, errors.New("created_at is not RFC3339")
		}
		t = t.UTC()
		pr.created = &t
	}
	if fr.Enabled != nil {
		pr.enabled = *fr.Enabled
	}
	return pr, nil
}

// cleanText removes control characters from free text. Content is kept as
// inert data; it is never interpreted.
func cleanText(s string) string {
	return strings.TrimSpace(strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, s))
}
