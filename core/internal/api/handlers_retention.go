package api

import (
	"net/http"

	"github.com/labstack/echo/v4"

	"vanguard/core/internal/retention"
)

// GET /api/retention -- ADMIN-ONLY, read-only.
//
// Shows the stored data-retention policy and the audit rows of recent runs.
// There is deliberately no HTTP route that changes the policy or deletes
// data: that is `vanguard retention set|run -confirm` on the host.
func (s *Server) handleRetention(c echo.Context) error {
	if err := requireAdmin(c); err != nil {
		return err
	}
	pol, err := s.DB.GetRetentionPolicy()
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "could not read the retention policy")
	}
	runs, err := s.DB.ListRetentionRuns(20)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "could not read retention history")
	}
	return c.JSON(http.StatusOK, echo.Map{
		"policy":  pol,
		"enabled": pol.IncidentRetentionDays > 0,
		"runs":    runs,
		"bounds": echo.Map{
			"min_days": retention.MinRetentionDays, "max_days": retention.MaxRetentionDays,
			"min_batch": retention.MinBatchSize, "max_batch": retention.MaxBatchSize, "max_batches": retention.MaxBatches,
		},
		"note": "0 days = nothing is ever deleted. Open and investigating incidents, incidents with an active ban, and (by default) incidents with live analyst notes are never deleted. " +
			"Change or run retention with the `vanguard retention` CLI on the host. Audit rows are append-only but not tamper-evident.",
	})
}
