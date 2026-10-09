package api

import (
	"errors"
	"net/http"

	"github.com/labstack/echo/v4"

	"vanguard/core/internal/database"
)

// guarded runs an expensive read under the server's QueryGuard (Phase 12).
// fn must only compute into variables owned by the caller: on timeout it keeps
// running in the background and must not touch the echo context. A nil Guard
// runs fn inline (unit tests that build a bare Server).
func (s *Server) guarded(c echo.Context, fn func() error) error {
	if s.Guard == nil {
		return fn()
	}
	return s.Guard.Do(c.Request().Context(), fn)
}

// guardFailure maps a guarded() error to an HTTP error: a busy or timed-out
// database is 503 with Retry-After (the client can retry; nothing was
// changed), anything else is the caller's generic failure message.
func guardFailure(c echo.Context, err error, msg string) error {
	if errors.Is(err, database.ErrBusy) || errors.Is(err, database.ErrTimeout) {
		c.Response().Header().Set("Retry-After", "5")
		return echo.NewHTTPError(http.StatusServiceUnavailable, "the server is busy with other queries; retry shortly")
	}
	return echo.NewHTTPError(http.StatusInternalServerError, msg)
}
