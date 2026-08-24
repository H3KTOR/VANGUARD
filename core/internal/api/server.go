// Package api implements VANGUARD's REST API and embedded-frontend server
// using the Echo framework. It is a thin HTTP layer over the existing
// internal packages (database, detection, firewall, simulator, auth) --
// no business logic lives here beyond request validation and JSON shaping.
package api

import (
	"net/http"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"

	"vanguard/core/internal/auth"
	"vanguard/core/internal/database"
	"vanguard/core/internal/detection"
	"vanguard/core/internal/firewall"
	"vanguard/core/internal/simulator"
)

// Server bundles every dependency the HTTP handlers need. Constructed once
// in cmd/vanguard and handed to NewEcho.
type Server struct {
	DB        *database.DB
	Engine    *detection.Engine // may be nil (e.g. simulate-only CLI use)
	Autopilot *firewall.Autopilot
	Auth      *auth.Manager
	Registry  *simulator.Registry
	StartedAt time.Time
}

// NewEcho builds a fully wired Echo instance: global middleware, public
// routes (health, login), and JWT-protected /api/* routes. Static frontend
// asset serving (public/ + go:embed) is attached separately by the caller
// in cmd/vanguard so this package stays frontend-agnostic and easy to unit
// test with httptest.
func (s *Server) NewEcho() *echo.Echo {
	e := echo.New()
	e.HideBanner = true
	e.HTTPErrorHandler = s.errorHandler

	e.Use(middleware.Recover())
	e.Use(middleware.Logger())
	e.Use(middleware.CORSWithConfig(middleware.CORSConfig{
		AllowOrigins: []string{"*"},
		AllowMethods: []string{http.MethodGet, http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodOptions},
		AllowHeaders: []string{echo.HeaderOrigin, echo.HeaderContentType, echo.HeaderAuthorization},
	}))

	// ---- Public ----
	e.GET("/api/health", s.handleHealth)
	e.POST("/api/auth/login", s.handleLogin)
	e.POST("/api/auth/register", s.handleRegister) // first-run admin bootstrap; see handler for the self-limiting guard

	// ---- Protected (JWT required) ----
	protected := e.Group("/api")
	protected.Use(s.jwtMiddleware)

	protected.GET("/auth/me", s.handleMe)

	protected.GET("/dashboard/summary", s.handleDashboardSummary)

	protected.GET("/incidents", s.handleListIncidents)
	protected.GET("/incidents/:id", s.handleGetIncident)
	protected.PUT("/incidents/:id/status", s.handleUpdateIncidentStatus)
	protected.POST("/incidents/:id/block", s.handleBlockIncidentIP)

	protected.GET("/firewall/rules", s.handleListFirewallRules)
	protected.POST("/firewall/block", s.handleManualBlock)
	protected.POST("/firewall/unban/:id", s.handleManualUnban)
	protected.POST("/firewall/whitelist", s.handleWhitelist)
	protected.GET("/firewall/status", s.handleFirewallStatus)

	protected.GET("/metrics/latest", s.handleLatestMetric)
	protected.GET("/metrics/history", s.handleMetricsHistory)

	protected.GET("/simulate/scenarios", s.handleListScenarios)
	protected.POST("/simulate/:scenario", s.handleRunSimulation)

	protected.GET("/panic/preview", s.handlePanicPreview)
	protected.POST("/panic/enter", s.handlePanicEnter)
	protected.POST("/panic/exit", s.handlePanicExit)
	protected.GET("/panic/status", s.handlePanicStatus)

	return e
}

// errorHandler normalizes Echo's default error output to a consistent
// {"error": "..."} JSON shape the frontend can rely on.
func (s *Server) errorHandler(err error, c echo.Context) {
	code := http.StatusInternalServerError
	message := "internal server error"
	if he, ok := err.(*echo.HTTPError); ok {
		code = he.Code
		if m, ok := he.Message.(string); ok {
			message = m
		}
	}
	if !c.Response().Committed {
		_ = c.JSON(code, echo.Map{"error": message})
	}
}

func (s *Server) handleHealth(c echo.Context) error {
	return c.JSON(http.StatusOK, echo.Map{
		"status":     "ok",
		"service":    "vanguard-core",
		"uptime_sec": int(time.Since(s.StartedAt).Seconds()),
	})
}
