package api

import (
	"net/http"
	"strconv"
	"time"

	"github.com/labstack/echo/v4"

	"vanguard/core/internal/database"
	"vanguard/core/internal/firewall"
	"vanguard/core/internal/health"
	"vanguard/core/internal/redact"
)

// Bounds for operator-supplied firewall input.
const (
	maxBanMinutes   = 365 * 24 * 60 // one year
	maxReasonLength = 200
)

// safeMsg turns an internal error into text that is safe to show a client:
// absolute paths are masked and the length is bounded.
func safeMsg(err error) string { return health.Sanitize(redact.Text(err.Error())) }

// banMinutes validates an optional duration. 0 means "use the default".
func banMinutes(v int) (time.Duration, error) {
	if v < 0 || v > maxBanMinutes {
		return 0, echo.NewHTTPError(http.StatusBadRequest, "duration_minutes must be between 1 and "+strconv.Itoa(maxBanMinutes)+" (or omitted)")
	}
	return time.Duration(v) * time.Minute, nil
}

// handleListFirewallRules supports ?active=true to show only currently
// enforced rules, matching the dashboard's "Active Bans" panel. Results are
// paged (limit<=500, offset<=10000).
func (s *Server) handleListFirewallRules(c echo.Context) error {
	activeOnly := false
	switch c.QueryParam("active") {
	case "", "false":
	case "true":
		activeOnly = true
	default:
		return echo.NewHTTPError(http.StatusBadRequest, "invalid active (want true or false)")
	}
	limit, err := atoiBounded(c, "limit", 200, 1, 500)
	if err != nil {
		return err
	}
	offset, err := atoiBounded(c, "offset", 0, 0, 10000)
	if err != nil {
		return err
	}
	var rules []database.FirewallRule
	if err := s.guarded(c, func() (e error) { rules, e = s.DB.ListFirewallRulesPage(activeOnly, limit, offset); return }); err != nil {
		return guardFailure(c, err, "failed to list firewall rules")
	}
	return c.JSON(http.StatusOK, echo.Map{"rules": rules, "count": len(rules), "limit": limit, "offset": offset})
}

type manualBlockRequest struct {
	IP              string `json:"ip"`
	Reason          string `json:"reason"`
	DurationMinutes int    `json:"duration_minutes"`
}

// handleManualBlock lets an admin ban an arbitrary IP outside of any
// specific incident (e.g. reacting to an external threat intel report).
// The fail-safe whitelist check inside Autopilot.Ban still applies -- this
// handler cannot be used to bypass it -- and the target must be one valid
// IP address (never a range or "any").
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
	ip, err := firewall.NormalizeIP(req.IP)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "ip must be a single valid IP address")
	}
	duration := firewallManualDefaultTTL
	if d, err := banMinutes(req.DurationMinutes); err != nil {
		return err
	} else if d > 0 {
		duration = d
	}
	reason := cleanReason(req.Reason, maxReasonLength)
	if reason == "" {
		reason = "Manual block via dashboard"
	}
	if claims := currentClaims(c); claims != nil {
		reason += " by " + claims.Email
	}

	if err := s.Autopilot.Ban(c.Request().Context(), ip, reason, duration, nil, database.FirewallSourceManual); err != nil {
		s.audit(c, "firewall.block", ip, auditRefused, safeMsg(err))
		return echo.NewHTTPError(http.StatusConflict, safeMsg(err))
	}
	s.audit(c, "firewall.block", ip, auditOK, "ttl "+duration.String())
	return c.JSON(http.StatusOK, echo.Map{"message": "IP blocked", "ip": ip})
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
	target := "rule:" + strconv.FormatUint(id, 10)
	if err := s.Autopilot.ManualUnban(c.Request().Context(), uint(id)); err != nil {
		s.audit(c, "firewall.unban", target, auditFailed, safeMsg(err))
		return echo.NewHTTPError(http.StatusNotFound, safeMsg(err))
	}
	s.audit(c, "firewall.unban", target, auditOK, "")
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
	ip, err := firewall.NormalizeIP(req.IP)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "ip must be a single valid IP address")
	}
	reason := cleanReason(req.Reason, maxReasonLength)
	if reason == "" {
		reason = "Manually whitelisted via dashboard"
	}
	if err := s.Autopilot.Whitelist(c.Request().Context(), ip, reason); err != nil {
		s.audit(c, "firewall.whitelist", ip, auditFailed, safeMsg(err))
		return echo.NewHTTPError(http.StatusInternalServerError, safeMsg(err))
	}
	s.audit(c, "firewall.whitelist", ip, auditOK, "")
	return c.JSON(http.StatusOK, echo.Map{"message": "IP whitelisted", "ip": ip})
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
		return echo.NewHTTPError(http.StatusInternalServerError, "could not read firewall status: "+safeMsg(err))
	}
	return c.JSON(http.StatusOK, echo.Map{"status": status})
}
