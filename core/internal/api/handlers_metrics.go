package api

import (
	"net/http"
	"time"

	"github.com/labstack/echo/v4"

	"vanguard/core/internal/database"
)

// handleLatestMetric returns the most recent system resource sample for the
// dashboard's live CPU/RAM/disk/connections widgets.
func (s *Server) handleLatestMetric(c echo.Context) error {
	m, err := s.DB.LatestMetric()
	if err != nil {
		if err == database.ErrNotFound {
			return c.JSON(http.StatusOK, echo.Map{"metric": nil})
		}
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to fetch latest metric")
	}
	return c.JSON(http.StatusOK, echo.Map{"metric": m})
}

// handleMetricsHistory returns a time-series window for charts.
// ?hours=1 (default 1, max 168) controls how far back to look.
func (s *Server) handleMetricsHistory(c echo.Context) error {
	hours, err := atoiBounded(c, "hours", 1, 1, 168)
	if err != nil {
		return err
	}
	since := time.Now().UTC().Add(-time.Duration(hours) * time.Hour)
	metrics, err := s.DB.GetMetricsSince(since)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to fetch metric history")
	}
	return c.JSON(http.StatusOK, echo.Map{"metrics": metrics, "count": len(metrics)})
}
