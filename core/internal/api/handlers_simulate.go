package api

import (
	"net/http"
	"time"

	"github.com/labstack/echo/v4"

	"vanguard/core/internal/simulator"
)

// handleListScenarios lists available Attack Simulation Mode scenarios for
// the dashboard's "Run Demo" panel.
func (s *Server) handleListScenarios(c echo.Context) error {
	out := make([]echo.Map, 0)
	for _, sim := range s.Registry.List() {
		out = append(out, echo.Map{"name": sim.Name(), "description": sim.Description()})
	}
	return c.JSON(http.StatusOK, echo.Map{"scenarios": out})
}

type runSimulationRequest struct {
	IP            string `json:"ip"`
	AttemptCount  int    `json:"attempt_count"`
	WindowSeconds int    `json:"window_seconds"`
	BanMinutes    int    `json:"ban_minutes"`
	NoAutoban     bool   `json:"no_autoban"`
	DryRun        bool   `json:"dry_run"`
}

// handleRunSimulation triggers a safe, synthetic attack scenario on-demand
// from the dashboard (mirrors `vanguard simulate <scenario>` on the CLI).
// Admin-only since it writes Incident/FirewallRule rows indistinguishable
// from a real detection.
func (s *Server) handleRunSimulation(c echo.Context) error {
	if err := requireAdmin(c); err != nil {
		return err
	}
	scenario := c.Param("scenario")

	var req runSimulationRequest
	_ = c.Bind(&req) // body is optional; zero values fall back to simulator defaults

	opts := simulator.Options{
		SourceIP:      req.IP,
		AttemptCount:  req.AttemptCount,
		WindowSeconds: req.WindowSeconds,
		AutoBan:       !req.NoAutoban,
		DryRun:        req.DryRun,
	}
	if req.BanMinutes > 0 {
		opts.BanDuration = time.Duration(req.BanMinutes) * time.Minute
	}

	result, err := s.Registry.Run(c.Request().Context(), s.DB, scenario, opts)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}
	return c.JSON(http.StatusOK, result)
}
