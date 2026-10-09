package api

import (
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/labstack/echo/v4"

	"vanguard/core/internal/database"
	"vanguard/core/internal/intel"
)

// handleListIncidents supports the dashboard's incident feed with optional
// filters: ?status=open&severity=HIGH&type=ssh_bruteforce&ip=1.2.3.4&since_hours=24&limit=50&offset=0
func (s *Server) handleListIncidents(c echo.Context) error {
	f := database.IncidentFilter{
		Status:   database.IncidentStatus(c.QueryParam("status")),
		Severity: database.Severity(strings.ToUpper(c.QueryParam("severity"))),
		Type:     database.IncidentType(c.QueryParam("type")),
		SourceIP: c.QueryParam("ip"),
	}
	// Malformed filters are client errors, never silently ignored (an ignored
	// filter would return a different, larger result than the caller asked for).
	if f.Status != "" && !database.IsKnownStatus(f.Status) {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid status")
	}
	switch f.Severity {
	case "", database.SeverityLow, database.SeverityMedium, database.SeverityHigh, database.SeverityCritical:
	default:
		return echo.NewHTTPError(http.StatusBadRequest, "invalid severity")
	}
	if f.Type != "" && (len(f.Type) > 64 || strings.ContainsAny(string(f.Type), " '\";")) {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid type")
	}
	if f.SourceIP != "" {
		ip, ok := intel.NormalizeObservedIP(f.SourceIP)
		if !ok {
			return echo.NewHTTPError(http.StatusBadRequest, "invalid ip")
		}
		f.SourceIP = ip
	}
	hours, err := atoiBounded(c, "since_hours", 0, 0, 24*365)
	if err != nil {
		return err
	}
	if hours > 0 {
		f.Since = time.Now().UTC().Add(-time.Duration(hours) * time.Hour)
	}
	if f.Limit, err = atoiBounded(c, "limit", 100, 1, 500); err != nil {
		return err
	}
	if f.Offset, err = atoiBounded(c, "offset", 0, 0, 10000); err != nil {
		return err
	}

	var incidents []database.Incident
	if err := s.guarded(c, func() (e error) { incidents, e = s.DB.ListIncidents(f); return }); err != nil {
		return guardFailure(c, err, "failed to list incidents")
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
	// Reason is optional analyst free text recorded (sanitized, bounded)
	// in the incident's audit trail.
	Reason string `json:"reason"`
}

// handleUpdateIncidentStatus drives the dashboard's "Investigate" / "Mark
// False Positive" / "Resolve" incident actions. Transitions are validated
// against the lifecycle table in database/lifecycle.go and applied
// atomically (compare-and-swap); an illegal transition is a 409, a
// concurrent modification is a 409, and nothing is written in either case.
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
	if !database.IsKnownStatus(status) {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid status value")
	}
	actor := "analyst"
	if claims := currentClaims(c); claims != nil && claims.Email != "" {
		actor = claims.Email
	}
	inc, err := s.DB.TransitionIncident(id, status, actor, req.Reason)
	switch {
	case err == nil:
		return c.JSON(http.StatusOK, inc)
	case errors.Is(err, database.ErrNotFound):
		return echo.NewHTTPError(http.StatusNotFound, "incident not found")
	case errors.Is(err, database.ErrInvalidTransition):
		return echo.NewHTTPError(http.StatusConflict, err.Error())
	case errors.Is(err, database.ErrConflict):
		return echo.NewHTTPError(http.StatusConflict, "incident was modified concurrently; reload and retry")
	default:
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to update incident status")
	}
}

// handleListIncidentEvents returns the incident's bounded audit trail
// (lifecycle changes, response attempts/outcomes, verifications), oldest
// first. Older incidents simply have an empty list.
func (s *Server) handleListIncidentEvents(c echo.Context) error {
	id, err := parseUintParam(c, "id")
	if err != nil {
		return err
	}
	if _, err := s.DB.GetIncident(id); err != nil {
		if errors.Is(err, database.ErrNotFound) {
			return echo.NewHTTPError(http.StatusNotFound, "incident not found")
		}
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to fetch incident")
	}
	evs, err := s.DB.ListIncidentEvents(id)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to list incident events")
	}
	return c.JSON(http.StatusOK, echo.Map{"events": evs, "count": len(evs)})
}

// handleIncidentResponsePlan previews what Autopilot would do for this
// incident under its current policy WITHOUT executing anything: only
// database reads, no firewall calls, no writes. The response carries
// executed=false so a plan can never be mistaken for an action taken.
func (s *Server) handleIncidentResponsePlan(c echo.Context) error {
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
	if s.Autopilot == nil {
		return echo.NewHTTPError(http.StatusServiceUnavailable, "autopilot is not configured on this instance")
	}
	d, err := s.Autopilot.Plan(inc)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to evaluate response policy")
	}
	return c.JSON(http.StatusOK, d)
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
	// The body is optional, but a body that is present must be valid.
	if c.Request().ContentLength != 0 {
		if err := decodeStrict(c, &req); err != nil {
			return err
		}
	}

	duration := 1 * time.Hour
	if d, err := banMinutes(req.DurationMinutes); err != nil {
		return err
	} else if d > 0 {
		duration = d
	}

	claims := currentClaims(c)
	reason := "Manual block via dashboard"
	if claims != nil {
		reason += " by " + claims.Email
	}

	target := "incident:" + strconv.FormatUint(uint64(inc.ID), 10)
	if err := s.Autopilot.Ban(c.Request().Context(), inc.SourceIP, reason, duration, &inc.ID, database.FirewallSourceManual); err != nil {
		s.audit(c, "incident.block", target, auditRefused, safeMsg(err))
		return echo.NewHTTPError(http.StatusConflict, safeMsg(err))
	}
	s.audit(c, "incident.block", target, auditOK, "ttl "+duration.String())

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
