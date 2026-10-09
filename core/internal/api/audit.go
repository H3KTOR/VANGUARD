package api

import (
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/labstack/echo/v4"

	"vanguard/core/internal/database"
)

// Audit results.
const (
	auditOK      = "ok"
	auditRefused = "refused" // a safeguard or validation said no; nothing changed
	auditFailed  = "failed"  // the operation was attempted and did not complete
)

// audit records a privileged action. It never receives request bodies:
// callers pass an identifier-level target and a short, non-secret detail.
// A failure to write the audit row is logged (without the row's content) and
// does not turn a completed operation into an error: the operation already
// happened and cannot be undone by reporting failure.
func (s *Server) audit(c echo.Context, action, target, result, detail string) {
	actor, role := "anonymous", ""
	if cl := currentClaims(c); cl != nil {
		actor, role = cl.Email, string(cl.Role)
	}
	row := &database.AdminAudit{Actor: actor, ActorRole: role, Action: action, Target: target, Result: result, Detail: detail}
	if err := s.DB.RecordAdminAudit(row); err != nil {
		log.Printf("[api] WARNING: could not record admin audit row for action %s (%s): %v", action, result, err)
	}
}

// cleanReason bounds and sanitizes operator-supplied free text that ends up in
// a rule's reason or an audit trail: control characters (log/line injection)
// become spaces and the length is capped.
func cleanReason(s string, max int) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, s)
	s = strings.TrimSpace(s)
	if len(s) > max {
		s = s[:max]
		for len(s) > 0 && !utf8.ValidString(s) { // never leave half of a UTF-8 sequence
			s = s[:len(s)-1]
		}
	}
	return s
}

// GET /api/audit/admin -- ADMIN-ONLY, read-only: recent privileged actions.
func (s *Server) handleAdminAudit(c echo.Context) error {
	if err := requireAdmin(c); err != nil {
		return err
	}
	limit, err := atoiBounded(c, "limit", 50, 1, 200)
	if err != nil {
		return err
	}
	rows, err := s.DB.ListAdminAudit(limit)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "could not read the audit trail")
	}
	return c.JSON(http.StatusOK, echo.Map{
		"entries": rows, "count": len(rows),
		"note": "append-only by convention, never deleted automatically, NOT tamper-evident; bodies, tokens and passwords are never recorded",
	})
}

// opLimited answers a request refused by an operation gate: 429 with
// Retry-After, counted in runtime health, and audited so repeated attempts are
// visible. Nothing was started.
func (s *Server) opLimited(c echo.Context, action string, wait time.Duration) error {
	s.sec.opLimited.Add(1)
	secs := int(wait.Seconds()) + 1
	c.Response().Header().Set("Retry-After", strconv.Itoa(secs))
	s.audit(c, action, "", auditRefused, "rate limited: another run is in progress or ran too recently")
	return echo.NewHTTPError(http.StatusTooManyRequests, "this operation is already running or ran moments ago; retry shortly")
}
