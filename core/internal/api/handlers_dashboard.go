package api

import (
	"net/http"
	"time"

	"github.com/labstack/echo/v4"

	"vanguard/core/internal/database"
)

// handleDashboardSummary returns the aggregate counts the dashboard's top
// header/summary cards need (open incidents by severity, active bans,
// latest metric snapshot) in a single round-trip.
func (s *Server) handleDashboardSummary(c echo.Context) error {
	since24h := time.Now().UTC().Add(-24 * time.Hour)

	var (
		openIncidents, recentIncidents []database.Incident
		activeBans                     []database.FirewallRule
	)
	if err := s.guarded(c, func() (e error) {
		if openIncidents, e = s.DB.ListIncidents(database.IncidentFilter{Status: database.StatusOpen, Limit: 500}); e != nil {
			return e
		}
		if recentIncidents, e = s.DB.ListIncidents(database.IncidentFilter{Since: since24h, Limit: 500}); e != nil {
			return e
		}
		activeBans, e = s.DB.ListFirewallRules(true)
		return e
	}); err != nil {
		return guardFailure(c, err, "failed to load dashboard data")
	}

	bySeverity := map[database.Severity]int{}
	for _, inc := range openIncidents {
		bySeverity[inc.Severity]++
	}

	var latestMetric *database.SystemMetric
	if m, err := s.DB.LatestMetric(); err == nil {
		latestMetric = m
	}

	panicStatus := echo.Map{"active": false}
	if s.Autopilot != nil {
		panicStatus = echo.Map{"active": s.Autopilot.PanicModeStatus().Active}
	}

	return c.JSON(http.StatusOK, echo.Map{
		"open_incidents_total":  len(openIncidents),
		"open_incidents_by_sev": bySeverity,
		"incidents_last_24h":    len(recentIncidents),
		"active_bans_total":     len(activeBans),
		"latest_metric":         latestMetric,
		"panic_mode":            panicStatus,
		"tracked_ips":           s.trackedIPCount(),
	})
}

func (s *Server) trackedIPCount() int {
	if s.Engine == nil {
		return 0
	}
	return s.Engine.State().TrackedIPCount()
}
