package api

import (
	"net/http"
	"strconv"
	"time"

	"github.com/labstack/echo/v4"

	"vanguard/core/internal/database"
)

// handleListFirewallRules supports ?active=true to show only currently
// enforced rules, matching the dashboard's "Active Bans" panel.
func (s *Server) handleListFirewallRules(c echo.Context) error {
	activeOnly := c.QueryParam("active") == "true"
	rules, err := s.DB.ListFirewallRules(activeOnly)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to list firewall rules")
	}
	return c.JSON(http.StatusOK, echo.Map{"rules": rules, "count": len(rules)})
}

type manualBlockRequest struct {
	IP              string `json:"ip"`
	Reason          string `json:"reason"`
	DurationMinutes int    `json:"duration_minutes"`
}

// handleManualBlock lets an admin ban an arbitrary IP outside of any
// specific incident (e.g. reacting to an external threat intel report).
// The fail-safe whitelist check inside Autopilot.Ban still applies -- this
// handler cannot be used to bypass it.
func (s *Server) handleManualBlock(c echo.Context) error {
	if err := requireAdmin(c); err != nil {
		return err
	}
	if s.Autopilot == nil {
		return echo.NewHTTPError(http.StatusServiceUnavailable, "autopilot is not configured on this instance")
	}
	var req manualBlockRequest
	if err := c.Bind(&req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid request body")
	}
	if req.IP == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "ip is required")
	}
	duration := firewallManualDefaultTTL
	if req.DurationMinutes > 0 {
		duration = time.Duration(req.DurationMinutes) * time.Minute
	}
	reason := req.Reason
	if reason == "" {
		reason = "Manual block via dashboard"
	}
	if claims := currentClaims(c); claims != nil {
		reason += " by " + claims.Email
	}

	if err := s.Autopilot.Ban(c.Request().Context(), req.IP, reason, duration, nil, database.FirewallSourceManual); err != nil {
		return echo.NewHTTPError(http.StatusConflict, err.Error())
	}
	return c.JSON(http.StatusOK, echo.Map{"message": "IP blocked", "ip": req.IP})
}

const firewallManualDefaultTTL = 1 * time.Hour

// handleManualUnban lifts an active ban immediately, regardless of
// remaining TTL -- the dashboard's "Unban" button on the active-bans list.
func (s *Server) handleManualUnban(c echo.Context) error {
	if err := requireAdmin(c); err != nil {
		return err
	}
	if s.Autopilot == nil {
		return echo.NewHTTPError(http.StatusServiceUnavailable, "autopilot is not configured on this instance")
	}
	raw := c.Param("id")
	id, err := strconv.ParseUint(raw, 10, 64)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid id parameter")
	}
	if err := s.Autopilot.ManualUnban(c.Request().Context(), uint(id)); err != nil {
		return echo.NewHTTPError(http.StatusNotFound, err.Error())
	}
	return c.JSON(http.StatusOK, echo.Map{"message": "IP unbanned"})
}

type whitelistRequest struct {
	IP     string `json:"ip"`
	Reason string `json:"reason"`
}

// handleWhitelist adds an IP to the fail-safe whitelist (it can never be
// auto- or manually-banned again while the rule is active) and lifts any
// existing ban on it immediately.
func (s *Server) handleWhitelist(c echo.Context) error {
	if err := requireAdmin(c); err != nil {
		return err
	}
	if s.Autopilot == nil {
		return echo.NewHTTPError(http.StatusServiceUnavailable, "autopilot is not configured on this instance")
	}
	var req whitelistRequest
	if err := c.Bind(&req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid request body")
	}
	if req.IP == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "ip is required")
	}
	reason := req.Reason
	if reason == "" {
		reason = "Manually whitelisted via dashboard"
	}
	if err := s.Autopilot.Whitelist(c.Request().Context(), req.IP, reason); err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}
	return c.JSON(http.StatusOK, echo.Map{"message": "IP whitelisted", "ip": req.IP})
}

// handleFirewallStatus surfaces the raw executor status string (e.g. `ufw
// status verbose` output, or the MockExecutor's summary) as a diagnostic
// view for the dashboard's "System" tab.
func (s *Server) handleFirewallStatus(c echo.Context) error {
	if s.Autopilot == nil {
		return echo.NewHTTPError(http.StatusServiceUnavailable, "autopilot is not configured on this instance")
	}
	status, err := s.Autopilot.ExecutorStatus(c.Request().Context())
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}
	return c.JSON(http.StatusOK, echo.Map{"status": status})
}
