package database

// Phase 5, Milestone 2: incident lifecycle + audit trail.
//
// Statuses (unchanged from earlier phases): open, auto_blocked,
// investigating, resolved, false_positive. What is new is that moving
// between them is validated, atomic (compare-and-swap inside a
// transaction), and recorded in IncidentEvent.
//
// The audit trail lives in the same local SQLite file as the incidents it
// describes. It is an operational history, NOT tamper-evident: anyone able
// to write the database can alter it.

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"gorm.io/gorm"
)

var (
	// ErrInvalidTransition: the requested status change is not allowed
	// from the incident's current status.
	ErrInvalidTransition = errors.New("invalid incident status transition")
	// ErrConflict: the incident changed underneath the caller between the
	// read and the write; nothing was modified. Safe to retry after
	// re-reading.
	ErrConflict = errors.New("incident was modified concurrently")
)

// validTransitions is the explicit lifecycle table. Same-status requests
// are handled separately as idempotent no-ops.
//
//	open          -> auto_blocked | investigating | resolved | false_positive
//	auto_blocked  -> investigating | resolved | false_positive
//	investigating -> open | resolved | false_positive
//	resolved      -> open | investigating            (reopen on new evidence)
//	false_positive-> open | investigating            (reopen)
//
// auto_blocked is only ever entered from open: a response must never
// overwrite an analyst's decision.
var validTransitions = map[IncidentStatus][]IncidentStatus{
	StatusOpen:          {StatusAutoBlocked, StatusInvestigating, StatusResolved, StatusFalsePositive},
	StatusAutoBlocked:   {StatusInvestigating, StatusResolved, StatusFalsePositive},
	StatusInvestigating: {StatusOpen, StatusResolved, StatusFalsePositive},
	StatusResolved:      {StatusOpen, StatusInvestigating},
	StatusFalsePositive: {StatusOpen, StatusInvestigating},
}

// ValidTransition reports whether from -> to is permitted (from == to is
// not a transition; callers treat it as a no-op).
func ValidTransition(from, to IncidentStatus) bool {
	for _, t := range validTransitions[from] {
		if t == to {
			return true
		}
	}
	return false
}

// IsKnownStatus reports whether s is one of the defined statuses.
func IsKnownStatus(s IncidentStatus) bool {
	_, ok := validTransitions[s]
	return ok
}

// Event kinds recorded in IncidentEvent.
const (
	EventStatusChange = "status_change"
	EventResponse     = "response"     // an automated/manual response action and its outcome
	EventVerification = "verification" // read-only check of a response's effect
)

// MaxEventsPerIncident bounds each incident's audit trail.
const MaxEventsPerIncident = 200

const (
	maxEventsPerIncident = MaxEventsPerIncident
	maxEventDetailLen    = 512
	maxEventActorLen     = 128
)

// IncidentEvent is one entry in an incident's bounded audit trail.
type IncidentEvent struct {
	ID         uint      `gorm:"primaryKey" json:"id"`
	IncidentID uint      `gorm:"not null;index:idx_incident_events_incident_time,priority:1" json:"incident_id"`
	Kind       string    `gorm:"size:32;not null" json:"kind"`
	Actor      string    `gorm:"size:128" json:"actor"` // "system", "autopilot", or an analyst email
	FromStatus string    `gorm:"size:32" json:"from_status,omitempty"`
	ToStatus   string    `gorm:"size:32" json:"to_status,omitempty"`
	Outcome    string    `gorm:"size:32" json:"outcome,omitempty"` // response/verification outcome label
	Detail     string    `gorm:"size:512" json:"detail,omitempty"` // sanitized, length-bounded
	At         time.Time `gorm:"not null;index:idx_incident_events_incident_time,priority:2" json:"at"`
}

// sanitizeText strips control characters and bounds length so audit text
// can never carry multi-line log injection or unbounded content.
func sanitizeText(s string, max int) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, s)
	s = strings.TrimSpace(s)
	if len(s) > max {
		s = s[:max]
	}
	return s
}

func addEvent(tx *gorm.DB, ev IncidentEvent) error {
	ev.Actor = sanitizeText(ev.Actor, maxEventActorLen)
	ev.Detail = sanitizeText(ev.Detail, maxEventDetailLen)
	if ev.At.IsZero() {
		ev.At = time.Now().UTC()
	}
	if err := tx.Create(&ev).Error; err != nil {
		return err
	}
	// Bound history per incident: drop the oldest beyond the cap.
	var count int64
	if err := tx.Model(&IncidentEvent{}).Where("incident_id = ?", ev.IncidentID).Count(&count).Error; err != nil {
		return err
	}
	if over := int(count) - maxEventsPerIncident; over > 0 {
		sub := tx.Model(&IncidentEvent{}).Select("id").Where("incident_id = ?", ev.IncidentID).Order("id ASC").Limit(over)
		return tx.Where("id IN (?)", sub).Delete(&IncidentEvent{}).Error
	}
	return nil
}

// AddIncidentEvent appends a sanitized, bounded audit entry (used for
// response and verification outcomes).
func (db *DB) AddIncidentEvent(ev IncidentEvent) error {
	return addEvent(db.DB, ev)
}

// ListIncidentEvents returns an incident's audit trail, oldest first.
func (db *DB) ListIncidentEvents(incidentID uint) ([]IncidentEvent, error) {
	var evs []IncidentEvent
	err := db.Where("incident_id = ?", incidentID).Order("id ASC").Find(&evs).Error
	return evs, err
}

// TransitionIncident atomically moves an incident to status `to`.
//
//   - unknown incident            -> ErrNotFound
//   - unknown `to`                -> ErrInvalidTransition
//   - to == current               -> no-op success (idempotent), no event
//   - disallowed from -> to       -> ErrInvalidTransition, nothing written
//   - row changed since the read  -> ErrConflict, nothing written
//
// The status write is a compare-and-swap on the status that was validated,
// and the audit event is written in the same transaction.
func (db *DB) TransitionIncident(id uint, to IncidentStatus, actor, reason string) (*Incident, error) {
	if !IsKnownStatus(to) {
		return nil, fmt.Errorf("%w: unknown target status %q", ErrInvalidTransition, to)
	}
	var out Incident
	err := db.Transaction(func(tx *gorm.DB) error {
		var cur Incident
		if err := tx.First(&cur, id).Error; err != nil {
			return err
		}
		if cur.Status == to {
			out = cur
			return nil
		}
		if !ValidTransition(cur.Status, to) {
			return fmt.Errorf("%w: %s -> %s", ErrInvalidTransition, cur.Status, to)
		}
		updates := map[string]any{"status": to}
		switch to {
		case StatusResolved, StatusFalsePositive:
			now := time.Now().UTC()
			updates["resolved_at"] = &now
		case StatusOpen, StatusInvestigating:
			updates["resolved_at"] = nil // reopened
		}
		res := tx.Model(&Incident{}).Where("id = ? AND status = ?", id, cur.Status).Updates(updates)
		if res.Error != nil {
			return res.Error
		}
		if res.RowsAffected == 0 {
			return ErrConflict
		}
		if err := addEvent(tx, IncidentEvent{
			IncidentID: id, Kind: EventStatusChange, Actor: actor,
			FromStatus: string(cur.Status), ToStatus: string(to), Detail: reason,
		}); err != nil {
			return err
		}
		return tx.First(&out, id).Error
	})
	if err != nil {
		return nil, err
	}
	return &out, nil
}

// MarkAutoBlocked records that an automated response blocked the source.
// It only applies to an incident that is still `open`; if an analyst has
// already acted on it (investigating/resolved/false_positive) or it is
// already auto_blocked, the status is left untouched and applied=false is
// returned with a nil error.
func (db *DB) MarkAutoBlocked(id uint, actor, reason string) (applied bool, err error) {
	_, err = db.TransitionIncident(id, StatusAutoBlocked, actor, reason)
	if errors.Is(err, ErrInvalidTransition) || errors.Is(err, ErrConflict) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	inc, gerr := db.GetIncident(id)
	return gerr == nil && inc.Status == StatusAutoBlocked, nil
}
