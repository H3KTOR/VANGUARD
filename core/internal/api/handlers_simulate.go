package api

import (
	"net/http"
	"strconv"

	"github.com/labstack/echo/v4"

	"vanguard/core/internal/firewall"
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

// Simulation bounds.
const (
	maxSimAttempts      = 5000
	maxSimWindowSeconds = 24 * 3600
)

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
	scenario := cleanReason(c.Param("scenario"), 32)

	var req runSimulationRequest
	if c.Request().ContentLength != 0 { // the body is optional, but if present it must be valid
		if err := decodeStrict(c, &req); err != nil {
			return err
		}
	}
	// Bounds: a simulation writes rows that look like real incidents, so its
	// size, time window and target are limited.
	if req.AttemptCount < 0 || req.AttemptCount > maxSimAttempts {
		return echo.NewHTTPError(http.StatusBadRequest, "attempt_count must be between 1 and "+strconv.Itoa(maxSimAttempts)+" (or omitted)")
	}
	if req.WindowSeconds < 0 || req.WindowSeconds > maxSimWindowSeconds {
		return echo.NewHTTPError(http.StatusBadRequest, "window_seconds must be between 1 and "+strconv.Itoa(maxSimWindowSeconds)+" (or omitted)")
	}
	banDur, err := banMinutes(req.BanMinutes)
	if err != nil {
		return err
	}
	ip := ""
	if req.IP != "" {
		if ip, err = firewall.NormalizeIP(req.IP); err != nil {
			return echo.NewHTTPError(http.StatusBadRequest, "ip must be a single valid IP address")
		}
	}

	release, wait, ok := s.simGate.enter()
	if !ok {
		return s.opLimited(c, "simulate.run", wait)
	}
	defer release()

	opts := simulator.Options{
		SourceIP:      ip,
		AttemptCount:  req.AttemptCount,
		WindowSeconds: req.WindowSeconds,
		AutoBan:       !req.NoAutoban,
		DryRun:        req.DryRun,
		BanDuration:   banDur,
	}

	result, err := s.Registry.Run(c.Request().Context(), s.DB, scenario, opts)
	if err != nil {
		s.audit(c, "simulate.run", scenario, auditRefused, safeMsg(err))
		return echo.NewHTTPError(http.StatusBadRequest, safeMsg(err))
	}
	detail := "simulated data"
	if req.DryRun {
		detail = "dry run"
	}
	s.audit(c, "simulate.run", scenario, auditOK, detail)
	return c.JSON(http.StatusOK, result)
}
