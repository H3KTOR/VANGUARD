package api

import (
	"net/http"
	"strconv"
	"time"

	"github.com/labstack/echo/v4"

	"vanguard/core/internal/database"
)

type sessionView struct {
	ID        string    `json:"id"` // shortened: enough to tell sessions apart, not usable as a credential
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
	ClientIP  string    `json:"client_ip"`
	Current   bool      `json:"current"`
}

// POST /api/auth/logout -- ends THIS session on the server. The token stops
// working immediately; other sessions of the account are untouched.
func (s *Server) handleLogout(c echo.Context) error {
	cl := currentClaims(c)
	if cl == nil {
		return echo.NewHTTPError(http.StatusUnauthorized, "authentication required")
	}
	if _, err := s.DB.RevokeSession(cl.ID, cl.UserID, "logout", time.Now().UTC()); err != nil {
		return echo.NewHTTPError(http.StatusServiceUnavailable, "could not end the session")
	}
	s.audit(c, "auth.logout", "user:"+strconv.FormatUint(uint64(cl.UserID), 10), auditOK, "")
	return c.JSON(http.StatusOK, echo.Map{"message": "signed out"})
}

// GET /api/auth/sessions -- the caller's own active sessions (bounded).
func (s *Server) handleListSessions(c echo.Context) error {
	cl := currentClaims(c)
	rows, err := s.DB.ListSessions(cl.UserID, time.Now().UTC())
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "could not list sessions")
	}
	out := make([]sessionView, 0, len(rows))
	for _, r := range rows {
		out = append(out, sessionView{ID: r.ID[:8], CreatedAt: r.CreatedAt, ExpiresAt: r.ExpiresAt, ClientIP: r.ClientIP, Current: r.ID == cl.ID})
	}
	return c.JSON(http.StatusOK, echo.Map{"sessions": out, "max_per_account": database.MaxActiveSessionsPerUser})
}

type revokeAllRequest struct {
	KeepCurrent bool `json:"keep_current"`
}

// POST /api/auth/sessions/revoke-all -- ends every session of the caller's
// account (optionally keeping the one making the request).
func (s *Server) handleRevokeAllOwn(c echo.Context) error {
	cl := currentClaims(c)
	var req revokeAllRequest
	if c.Request().ContentLength != 0 {
		if err := decodeStrict(c, &req); err != nil {
			return err
		}
	}
	keep := ""
	if req.KeepCurrent {
		keep = cl.ID
	}
	n, err := s.DB.RevokeUserSessions(cl.UserID, keep, "revoke-all", time.Now().UTC())
	if err != nil {
		return echo.NewHTTPError(http.StatusServiceUnavailable, "could not revoke sessions")
	}
	s.audit(c, "auth.revoke_all", "user:"+strconv.FormatUint(uint64(cl.UserID), 10), auditOK, strconv.FormatInt(n, 10)+" session(s)")
	return c.JSON(http.StatusOK, echo.Map{"revoked": n})
}

// POST /api/users/:id/revoke-sessions -- ADMIN-ONLY: ends every session of any
// account (for example after a suspected token theft).
func (s *Server) handleAdminRevokeSessions(c echo.Context) error {
	if err := requireAdmin(c); err != nil {
		return err
	}
	id, err := parseUintParam(c, "id")
	if err != nil {
		return err
	}
	target := "user:" + strconv.FormatUint(uint64(id), 10)
	if _, err := s.DB.GetUserByID(id); err != nil {
		s.audit(c, "admin.revoke_sessions", target, auditFailed, "no such account")
		return echo.NewHTTPError(http.StatusNotFound, "account not found")
	}
	n, err := s.DB.RevokeUserSessions(id, "", "revoked by admin", time.Now().UTC())
	if err != nil {
		s.audit(c, "admin.revoke_sessions", target, auditFailed, "")
		return echo.NewHTTPError(http.StatusServiceUnavailable, "could not revoke sessions")
	}
	s.audit(c, "admin.revoke_sessions", target, auditOK, strconv.FormatInt(n, 10)+" session(s)")
	return c.JSON(http.StatusOK, echo.Map{"revoked": n})
}
