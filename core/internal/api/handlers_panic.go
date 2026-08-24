package api

import "net/http"

import "github.com/labstack/echo/v4"

// handlePanicPreview returns the mandatory dry-run preview of what Panic
// Mode would do (which IPs/ports stay open) -- the dashboard MUST display
// this before allowing the two-step confirmation to proceed.
func (s *Server) handlePanicPreview(c echo.Context) error {
	if s.Autopilot == nil {
		return echo.NewHTTPError(http.StatusServiceUnavailable, "autopilot is not configured on this instance")
	}
	claims := currentClaims(c)
	adminIP := c.RealIP()
	_ = claims
	return c.JSON(http.StatusOK, s.Autopilot.PreviewPanicMode(adminIP))
}

type panicEnterRequest struct {
	Reason    string `json:"reason"`
	Confirmed bool   `json:"confirmed"`
}

// handlePanicEnter activates the site-wide lockdown. Requires the frontend
// to have already shown the dry-run preview and collected an explicit
// two-step "Are you sure?" confirmation from the operator, encoded here as
// the mandatory confirmed=true field -- Autopilot.EnterPanicMode rejects
// the call outright if it's missing, as a final safety backstop.
func (s *Server) handlePanicEnter(c echo.Context) error {
	if err := requireAdmin(c); err != nil {
		return err
	}
	if s.Autopilot == nil {
		return echo.NewHTTPError(http.StatusServiceUnavailable, "autopilot is not configured on this instance")
	}
	var req panicEnterRequest
	if err := c.Bind(&req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid request body")
	}
	if !req.Confirmed {
		return echo.NewHTTPError(http.StatusBadRequest, "panic mode requires confirmed=true (two-step confirmation)")
	}
	reason := req.Reason
	if claims := currentClaims(c); claims != nil {
		reason += " (activated by " + claims.Email + ")"
	}
	if err := s.Autopilot.EnterPanicMode(c.Request().Context(), c.RealIP(), reason, true); err != nil {
		return echo.NewHTTPError(http.StatusConflict, err.Error())
	}
	return c.JSON(http.StatusOK, s.Autopilot.PanicModeStatus())
}

// handlePanicExit manually lifts Panic Mode before the 30-minute automatic
// rollback fires.
func (s *Server) handlePanicExit(c echo.Context) error {
	if err := requireAdmin(c); err != nil {
		return err
	}
	if s.Autopilot == nil {
		return echo.NewHTTPError(http.StatusServiceUnavailable, "autopilot is not configured on this instance")
	}
	reason := "manual exit via dashboard"
	if claims := currentClaims(c); claims != nil {
		reason += " by " + claims.Email
	}
	if err := s.Autopilot.ExitPanicMode(c.Request().Context(), reason); err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}
	return c.JSON(http.StatusOK, s.Autopilot.PanicModeStatus())
}

// handlePanicStatus returns current lockdown state, including the
// auto-rollback countdown, for the dashboard's persistent banner.
func (s *Server) handlePanicStatus(c echo.Context) error {
	if s.Autopilot == nil {
		return c.JSON(http.StatusOK, echo.Map{"active": false})
	}
	return c.JSON(http.StatusOK, s.Autopilot.PanicModeStatus())
}
