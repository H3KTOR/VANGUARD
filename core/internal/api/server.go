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
	"vanguard/core/internal/hostsec"
	"vanguard/core/internal/intel"
	"vanguard/core/internal/pipeline"
	"vanguard/core/internal/rules"
	"vanguard/core/internal/simulator"
	"vanguard/core/internal/tuning"
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

	// Detectors exposes per-scanner operational status (optional; nil
	// when Host Security scanning is disabled).
	Detectors DetectorStatusSource

	// Intel is the local IOC matcher (optional; nil when disabled).
	Intel *intel.Matcher

	// Runtime feeds GET /api/health/runtime (all fields optional).
	Runtime RuntimeSources

	// Tuning is the operator threshold store (Phase 10; nil = unavailable).
	Tuning *tuning.Store
	// RuleCtx carries the runtime facts the rule inventory reflects.
	RuleCtx rules.Context

	// BackupDir is where API-created backups are written (empty = backups
	// are not configured for the API).
	BackupDir string

	// Guard bounds concurrent expensive reads and releases the caller after a
	// deadline (Phase 12). Nil = unguarded.
	Guard *database.QueryGuard

	// QueueStats lists the log-ingestion queues for runtime health (optional).
	QueueStats func() []pipeline.Stats
}

// DetectorStatusSource is implemented by *hostsec.Manager.
type DetectorStatusSource interface {
	Status() []hostsec.ScanStatus
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
	protected.GET("/detectors/status", s.handleDetectorStatus)
	protected.GET("/health/runtime", s.handleRuntimeHealth)
	protected.GET("/backup", s.handleListBackups)
	protected.POST("/backup", s.handleCreateBackup)
	protected.GET("/backup/:name/verify", s.handleVerifyBackup)
	protected.GET("/retention", s.handleRetention)
	protected.GET("/rules", s.handleListRules)
	protected.GET("/rules/tuning", s.handleGetTuning)
	protected.POST("/rules/tuning/preview", s.handlePreviewTuning)
	protected.PUT("/rules/tuning", s.handleApplyTuning)
	protected.POST("/rules/tuning/rollback", s.handleRollbackTuning)
	protected.GET("/rules/guidance", s.handleRuleGuidance)
	protected.GET("/intel/status", s.handleIntelStatus)
	protected.GET("/intel/iocs", s.handleListIOCs)
	protected.GET("/intel/iocs/:id", s.handleGetIOC)
	protected.PUT("/intel/iocs/:id", s.handleUpdateIOC)
	protected.DELETE("/intel/iocs/:id", s.handleDeleteIOC)
	protected.POST("/intel/import", s.handleImportIOCs)
	protected.GET("/intel/imports", s.handleListIOCImports)
	protected.GET("/hunt/matches", s.handleHuntMatches)
	protected.GET("/incidents/:id/events", s.handleListIncidentEvents)
	protected.GET("/incidents/:id/timeline", s.handleIncidentTimeline)
	protected.GET("/incidents/:id/graph", s.handleIncidentGraph)
	protected.GET("/incidents/:id/export", s.handleIncidentExport)
	protected.GET("/incidents/:id/notes", s.handleListNotes)
	protected.POST("/incidents/:id/notes", s.handleAddNote)
	protected.PUT("/incidents/:id/notes/:nid", s.handleEditNote)
	protected.DELETE("/incidents/:id/notes/:nid", s.handleDeleteNote)
	protected.GET("/investigate/incidents", s.handleInvestigateIncidents)
	protected.GET("/incidents/:id/response-plan", s.handleIncidentResponsePlan)
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
