package database

// Phase 7: analyst investigation notes.
//
// Notes are analyst-authored text attached to an incident. They are kept
// strictly apart from detector evidence (Incident.Metadata) and never
// influence risk scoring, evidence, or response policy. Author identity is
// whatever the authenticated session supplies -- never fabricated. Edits
// and deletions are soft and each writes an incident_events audit entry
// (without the note text). The table lives in the same local SQLite file
// as everything else and is NOT tamper-evident.

import (
	"errors"
	"strings"
	"time"

	"gorm.io/gorm"
)

const (
	MaxNoteLen          = 2000
	MaxNotesPerIncident = 100
	EventNote           = "note"
)

var (
	ErrNoteEmpty    = errors.New("note text is empty")
	ErrNoteTooLong  = errors.New("note text exceeds the length limit")
	ErrNoteLimit    = errors.New("too many notes on this incident")
	ErrNoAuthor     = errors.New("a note requires an authenticated author")
	ErrNoteNotFound = errors.New("note not found")
)

// IncidentNote is one analyst note.
type IncidentNote struct {
	ID         uint       `gorm:"primaryKey" json:"id"`
	IncidentID uint       `gorm:"not null;index:idx_incident_notes_incident,priority:1" json:"incident_id"`
	Author     string     `gorm:"size:128;not null" json:"author"`
	Text       string     `gorm:"type:text;not null" json:"text"`
	CreatedAt  time.Time  `gorm:"not null" json:"created_at"`
	EditedAt   *time.Time `json:"edited_at,omitempty"`
	EditedBy   string     `gorm:"size:128" json:"edited_by,omitempty"`
	Deleted    bool       `gorm:"not null" json:"deleted"`
	DeletedAt  *time.Time `json:"deleted_at,omitempty"`
	DeletedBy  string     `gorm:"size:128" json:"deleted_by,omitempty"`
}

// IsCorrelatedType reports whether an incident type is inferred by
// combining several observations (rather than observed directly).
func IsCorrelatedType(t IncidentType) bool {
	switch t {
	case IncidentAttackChain, IncidentWebAttackChain, IncidentHighConfidenceCompromise:
		return true
	}
	return false
}

// CorrelatedTypes lists them (used to express evidence-kind filters
// without scanning JSON metadata).
func CorrelatedTypes() []IncidentType {
	return []IncidentType{IncidentAttackChain, IncidentWebAttackChain, IncidentHighConfidenceCompromise}
}

// cleanNote strips control characters (keeping newlines/tabs), trims and
// validates the length. It does NOT redact: the author's text is stored as
// written and redacted when exported.
func cleanNote(text string) (string, error) {
	text = strings.Map(func(r rune) rune {
		if r == '\n' || r == '\t' {
			return r
		}
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, text)
	text = strings.TrimSpace(text)
	if text == "" {
		return "", ErrNoteEmpty
	}
	if len([]rune(text)) > MaxNoteLen {
		return "", ErrNoteTooLong
	}
	return text, nil
}

// AddIncidentNote creates a note. author must be a real authenticated
// identity.
func (db *DB) AddIncidentNote(incidentID uint, author, text string) (*IncidentNote, error) {
	author = strings.TrimSpace(author)
	if author == "" {
		return nil, ErrNoAuthor
	}
	text, err := cleanNote(text)
	if err != nil {
		return nil, err
	}
	var out IncidentNote
	err = db.Transaction(func(tx *gorm.DB) error {
		var inc Incident
		if err := tx.Select("id").First(&inc, incidentID).Error; err != nil {
			return err
		}
		var n int64
		if err := tx.Model(&IncidentNote{}).Where("incident_id = ? AND deleted = ?", incidentID, false).Count(&n).Error; err != nil {
			return err
		}
		if n >= MaxNotesPerIncident {
			return ErrNoteLimit
		}
		out = IncidentNote{IncidentID: incidentID, Author: sanitizeText(author, maxEventActorLen), Text: text, CreatedAt: time.Now().UTC()}
		if err := tx.Create(&out).Error; err != nil {
			return err
		}
		return addEvent(tx, IncidentEvent{IncidentID: incidentID, Kind: EventNote, Actor: author, Outcome: "created", Detail: "note #" + itoa(out.ID) + " added"})
	})
	if err != nil {
		return nil, err
	}
	return &out, nil
}

// UpdateIncidentNote edits a live note's text.
func (db *DB) UpdateIncidentNote(incidentID, noteID uint, editor, text string) (*IncidentNote, error) {
	editor = strings.TrimSpace(editor)
	if editor == "" {
		return nil, ErrNoAuthor
	}
	text, err := cleanNote(text)
	if err != nil {
		return nil, err
	}
	var out IncidentNote
	err = db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("id = ? AND incident_id = ? AND deleted = ?", noteID, incidentID, false).First(&out).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return ErrNoteNotFound
			}
			return err
		}
		now := time.Now().UTC()
		out.Text, out.EditedAt, out.EditedBy = text, &now, sanitizeText(editor, maxEventActorLen)
		if err := tx.Save(&out).Error; err != nil {
			return err
		}
		return addEvent(tx, IncidentEvent{IncidentID: incidentID, Kind: EventNote, Actor: editor, Outcome: "edited", Detail: "note #" + itoa(out.ID) + " edited"})
	})
	if err != nil {
		return nil, err
	}
	return &out, nil
}

// DeleteIncidentNote soft-deletes a note (the row and its text are kept;
// listings hide it).
func (db *DB) DeleteIncidentNote(incidentID, noteID uint, by string) error {
	by = strings.TrimSpace(by)
	if by == "" {
		return ErrNoAuthor
	}
	return db.Transaction(func(tx *gorm.DB) error {
		var n IncidentNote
		if err := tx.Where("id = ? AND incident_id = ? AND deleted = ?", noteID, incidentID, false).First(&n).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return ErrNoteNotFound
			}
			return err
		}
		now := time.Now().UTC()
		n.Deleted, n.DeletedAt, n.DeletedBy = true, &now, sanitizeText(by, maxEventActorLen)
		if err := tx.Save(&n).Error; err != nil {
			return err
		}
		return addEvent(tx, IncidentEvent{IncidentID: incidentID, Kind: EventNote, Actor: by, Outcome: "deleted", Detail: "note #" + itoa(n.ID) + " deleted"})
	})
}

// ListIncidentNotes returns an incident's live notes, oldest first.
func (db *DB) ListIncidentNotes(incidentID uint) ([]IncidentNote, error) {
	var out []IncidentNote
	err := db.Where("incident_id = ? AND deleted = ?", incidentID, false).Order("id ASC").Limit(MaxNotesPerIncident).Find(&out).Error
	return out, err
}

// ListFirewallRulesForIncident returns the rules created for an incident.
func (db *DB) ListFirewallRulesForIncident(incidentID uint, limit int) ([]FirewallRule, error) {
	if limit <= 0 || limit > 50 {
		limit = 50
	}
	var out []FirewallRule
	err := db.Where("incident_id = ?", incidentID).Order("banned_at ASC, id ASC").Limit(limit).Find(&out).Error
	return out, err
}

func itoa(n uint) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
