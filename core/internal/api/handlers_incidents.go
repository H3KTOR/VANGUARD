package api

import (
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/labstack/echo/v4"

	"vanguard/core/internal/database"
)

// handleListIncidents supports the dashboard's incident feed with optional
// filters: ?status=open&severity=HIGH&type=ssh_bruteforce&ip=1.2.3.4&since_hours=24&limit=50&offset=0
func (s *Server) handleListIncidents(c echo.Context) error {
	f := database.IncidentFilter{
		Status:   database.IncidentStatus(c.QueryParam("status")),
		Severity: database.Severity(c.QueryParam("severity")),
		Type:     database.IncidentType(c.QueryParam("type")),
		SourceIP: c.QueryParam("ip"),
	}
	if v := c.QueryParam("since_hours"); v != "" {
		if hours, err := strconv.Atoi(v); err == nil && hours > 0 {
			f.Since = time.Now().UTC().Add(-time.Duration(hours) * time.Hour)
		}
	}
	if v := c.QueryParam("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			f.Limit = n
		}
	}
	if v := c.QueryParam("offset"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			f.Offset = n
		}
	}

	incidents, err := s.DB.ListIncidents(f)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to list incidents")
	}
	return c.JSON(http.StatusOK, echo.Map{"incidents": incidents, "count": len(incidents)})
}

func (s *Server) handleGetIncident(c echo.Context) error {
	id, err := parseUintParam(c, "id")
	if err != nil {
		return err
	}
	inc, err := s.DB.GetIncident(id)
	if err != nil {
		if errors.Is(err, database.ErrNotFound) {
			return echo.NewHTTPError(http.StatusNotFound, "incident not found")
		}
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to fetch incident")
	}
	return c.JSON(http.StatusOK, inc)
}

type updateStatusRequest struct {
	Status string `json:"status"`
}

// handleUpdateIncidentStatus drives the dashboard's "Investigate" / "Mark
// False Positive" / "Resolve" incident-card actions from the spec's mockup.
func (s *Server) handleUpdateIncidentStatus(c echo.Context) error {
	id, err := parseUintParam(c, "id")
	if err != nil {
		return err
	}
	var req updateStatusRequest
	if err := c.Bind(&req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid request body")
	}
	status := database.IncidentStatus(req.Status)
	switch status {
	case database.StatusOpen, database.StatusAutoBlocked, database.StatusInvestigating,
		database.StatusResolved, database.StatusFalsePositive:
	default:
		return echo.NewHTTPError(http.StatusBadRequest, "invalid status value")
	}
	if err := s.DB.UpdateIncidentStatus(id, status); err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to update incident status")
	}
	inc, err := s.DB.GetIncident(id)
	if err != nil {
		return echo.NewHTTPError(http.StatusNotFound, "incident not found")
	}
	return c.JSON(http.StatusOK, inc)
}

type blockIncidentRequest struct {
	// DurationMinutes overrides the Autopilot's default/per-type TTL for
	// this manual block. 0 means "use Autopilot's configured default".
	DurationMinutes int `json:"duration_minutes"`
}

// handleBlockIncidentIP implements the dashboard's "Block IP" recommended
// action button: it invokes the exact same Autopilot.Ban() path a real
// automatic response would, but on-demand and bypassing the min-risk-score
// gate (an operator explicitly clicking "Block" is itself sufficient
// justification) -- the fail-safe whitelist check still always applies.
func (s *Server) handleBlockIncidentIP(c echo.Context) error {
	if err := requireAdmin(c); err != nil {
		return err
	}
	id, err := parseUintParam(c, "id")
	if err != nil {
		return err
	}
	inc, err := s.DB.GetIncident(id)
	if err != nil {
		return echo.NewHTTPError(http.StatusNotFound, "incident not found")
	}
	if s.Autopilot == nil {
		return echo.NewHTTPError(http.StatusServiceUnavailable, "autopilot is not configured on this instance")
	}

	var req blockIncidentRequest
	_ = c.Bind(&req) // optional body; ignore parse errors and fall back to defaults

	duration := 1 * time.Hour
	if req.DurationMinutes > 0 {
		duration = time.Duration(req.DurationMinutes) * time.Minute
	}

	claims := currentClaims(c)
	reason := "Manual block via dashboard"
	if claims != nil {
		reason += " by " + claims.Email
	}

	if err := s.Autopilot.Ban(c.Request().Context(), inc.SourceIP, reason, duration, &inc.ID, database.FirewallSourceManual); err != nil {
		return echo.NewHTTPError(http.StatusConflict, err.Error())
	}

	updated, _ := s.DB.GetIncident(id)
	return c.JSON(http.StatusOK, echo.Map{"message": "IP blocked", "incident": updated})
}

func parseUintParam(c echo.Context, name string) (uint, error) {
	raw := c.Param(name)
	n, err := strconv.ParseUint(raw, 10, 64)
	if err != nil {
		return 0, echo.NewHTTPError(http.StatusBadRequest, "invalid "+name+" parameter")
	}
	return uint(n), nil
}
