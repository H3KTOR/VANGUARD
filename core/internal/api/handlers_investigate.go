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
	"vanguard/core/internal/investigate"
)

func (s *Server) incidentOr404(c echo.Context) (*database.Incident, error) {
	id, err := parseUintParam(c, "id")
	if err != nil {
		return nil, err
	}
	inc, err := s.DB.GetIncident(id)
	if err != nil {
		if errors.Is(err, database.ErrNotFound) {
			return nil, echo.NewHTTPError(http.StatusNotFound, "incident not found")
		}
		return nil, echo.NewHTTPError(http.StatusInternalServerError, "failed to fetch incident")
	}
	return inc, nil
}

// GET /api/incidents/:id/timeline?offset=&limit=
func (s *Server) handleIncidentTimeline(c echo.Context) error {
	inc, err := s.incidentOr404(c)
	if err != nil {
		return err
	}
	limit, err := atoiBounded(c, "limit", 100, 1, investigate.MaxTimelinePage)
	if err != nil {
		return err
	}
	offset, err := atoiBounded(c, "offset", 0, 0, 10000)
	if err != nil {
		return err
	}
	tl, err := investigate.BuildTimeline(s.DB, inc, offset, limit)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to build timeline")
	}
	return c.JSON(http.StatusOK, tl)
}

// GET /api/incidents/:id/graph
func (s *Server) handleIncidentGraph(c echo.Context) error {
	inc, err := s.incidentOr404(c)
	if err != nil {
		return err
	}
	g, err := investigate.BuildGraph(s.DB, inc)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to build relationships")
	}
	return c.JSON(http.StatusOK, g)
}

// GET /api/incidents/:id/export -- bounded, redacted JSON download.
func (s *Server) handleIncidentExport(c echo.Context) error {
	inc, err := s.incidentOr404(c)
	if err != nil {
		return err
	}
	b, _, err := investigate.BuildExport(s.DB, inc, time.Now().UTC())
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to build export")
	}
	c.Response().Header().Set("Content-Disposition", `attachment; filename="vanguard-incident-`+strconv.FormatUint(uint64(inc.ID), 10)+`.json"`)
	return c.Blob(http.StatusOK, "application/json", b)
}

func authorOf(c echo.Context) (string, error) {
	if cl := currentClaims(c); cl != nil && strings.TrimSpace(cl.Email) != "" {
		return cl.Email, nil
	}
	return "", echo.NewHTTPError(http.StatusUnauthorized, "an authenticated analyst identity is required")
}

type noteBody struct {
	Text string `json:"text"`
}

func noteErr(err error) error {
	switch {
	case errors.Is(err, database.ErrNotFound), errors.Is(err, database.ErrNoteNotFound):
		return echo.NewHTTPError(http.StatusNotFound, "not found")
	case errors.Is(err, database.ErrNoteEmpty), errors.Is(err, database.ErrNoteTooLong):
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	case errors.Is(err, database.ErrNoteLimit):
		return echo.NewHTTPError(http.StatusConflict, err.Error())
	case errors.Is(err, database.ErrNoAuthor):
		return echo.NewHTTPError(http.StatusUnauthorized, err.Error())
	}
	return echo.NewHTTPError(http.StatusInternalServerError, "note operation failed")
}

// GET /api/incidents/:id/notes
func (s *Server) handleListNotes(c echo.Context) error {
	inc, err := s.incidentOr404(c)
	if err != nil {
		return err
	}
	notes, err := s.DB.ListIncidentNotes(inc.ID)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to list notes")
	}
	if notes == nil {
		notes = []database.IncidentNote{}
	}
	return c.JSON(http.StatusOK, echo.Map{"notes": notes, "count": len(notes),
		"note": "analyst statements; not detector evidence and not tamper-evident"})
}

// POST /api/incidents/:id/notes
func (s *Server) handleAddNote(c echo.Context) error {
	inc, err := s.incidentOr404(c)
	if err != nil {
		return err
	}
	author, err := authorOf(c)
	if err != nil {
		return err
	}
	var b noteBody
	if err := c.Bind(&b); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid request body")
	}
	n, err := s.DB.AddIncidentNote(inc.ID, author, b.Text)
	if err != nil {
		return noteErr(err)
	}
	return c.JSON(http.StatusCreated, n)
}

// PUT /api/incidents/:id/notes/:nid
func (s *Server) handleEditNote(c echo.Context) error {
	inc, err := s.incidentOr404(c)
	if err != nil {
		return err
	}
	nid, err := parseUintParam(c, "nid")
	if err != nil {
		return err
	}
	author, err := authorOf(c)
	if err != nil {
		return err
	}
	var b noteBody
	if err := c.Bind(&b); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid request body")
	}
	n, err := s.DB.UpdateIncidentNote(inc.ID, nid, author, b.Text)
	if err != nil {
		return noteErr(err)
	}
	return c.JSON(http.StatusOK, n)
}

// DELETE /api/incidents/:id/notes/:nid  (soft delete, audited)
func (s *Server) handleDeleteNote(c echo.Context) error {
	inc, err := s.incidentOr404(c)
	if err != nil {
		return err
	}
	nid, err := parseUintParam(c, "nid")
	if err != nil {
		return err
	}
	author, err := authorOf(c)
	if err != nil {
		return err
	}
	if err := s.DB.DeleteIncidentNote(inc.ID, nid, author); err != nil {
		return noteErr(err)
	}
	return c.JSON(http.StatusOK, echo.Map{"message": "note deleted"})
}

func boolQuery(c echo.Context, name string) (*bool, error) {
	v := c.QueryParam(name)
	if v == "" {
		return nil, nil
	}
	switch strings.ToLower(v) {
	case "true", "1":
		t := true
		return &t, nil
	case "false", "0":
		f := false
		return &f, nil
	}
	return nil, echo.NewHTTPError(http.StatusBadRequest, "invalid "+name+" (want true or false)")
}

func intQuery(c echo.Context, name string, min, max int) (*int, error) {
	v := c.QueryParam(name)
	if v == "" {
		return nil, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < min || n > max {
		return nil, echo.NewHTTPError(http.StatusBadRequest, "invalid "+name)
	}
	return &n, nil
}

var responseOutcomes = map[string]bool{"succeeded": true, "failed": true, "suppressed": true, "not_eligible": true}
var verificationOutcomes = map[string]bool{"verified": true, "failed": true, "inconclusive": true}

// GET /api/investigate/incidents -- see investigate.Filter for semantics.
func (s *Server) handleInvestigateIncidents(c echo.Context) error {
	f := investigate.Filter{
		Rule: database.IncidentType(c.QueryParam("rule")), Status: database.IncidentStatus(c.QueryParam("status")),
		Severity: database.Severity(strings.ToUpper(c.QueryParam("severity"))), EvidenceKind: c.QueryParam("evidence_kind"),
		ResponseOutcome: c.QueryParam("response_outcome"), VerificationOutcome: c.QueryParam("verification_outcome"),
	}
	if f.Status != "" && !database.IsKnownStatus(f.Status) {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid status")
	}
	switch f.Severity {
	case "", database.SeverityLow, database.SeverityMedium, database.SeverityHigh, database.SeverityCritical:
	default:
		return echo.NewHTTPError(http.StatusBadRequest, "invalid severity")
	}
	if f.EvidenceKind != "" && f.EvidenceKind != "observed" && f.EvidenceKind != "correlated" {
		return echo.NewHTTPError(http.StatusBadRequest, "evidence_kind must be observed or correlated")
	}
	if f.ResponseOutcome != "" && !responseOutcomes[f.ResponseOutcome] {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid response_outcome")
	}
	if f.VerificationOutcome != "" && !verificationOutcomes[f.VerificationOutcome] {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid verification_outcome")
	}
	if f.Rule != "" && (len(f.Rule) > 64 || strings.ContainsAny(string(f.Rule), " '\";")) {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid rule")
	}
	var err error
	if v := c.QueryParam("id"); v != "" {
		n, perr := strconv.ParseUint(v, 10, 64)
		if perr != nil || n == 0 {
			return echo.NewHTTPError(http.StatusBadRequest, "invalid id")
		}
		f.ID = uint(n)
	}
	if v := c.QueryParam("ioc_id"); v != "" {
		n, perr := strconv.ParseUint(v, 10, 64)
		if perr != nil || n == 0 {
			return echo.NewHTTPError(http.StatusBadRequest, "invalid ioc_id")
		}
		f.IOCID = uint(n)
	}
	if v := c.QueryParam("ip"); v != "" {
		ip, ok := intel.NormalizeObservedIP(v)
		if !ok {
			return echo.NewHTTPError(http.StatusBadRequest, "invalid ip")
		}
		f.SourceIP = ip
	}
	if f.RiskMin, err = intQuery(c, "risk_min", 0, 100); err != nil {
		return err
	}
	if f.RiskMax, err = intQuery(c, "risk_max", 0, 100); err != nil {
		return err
	}
	if f.RiskMin != nil && f.RiskMax != nil && *f.RiskMin > *f.RiskMax {
		return echo.NewHTTPError(http.StatusBadRequest, "risk_min exceeds risk_max")
	}
	if f.HasIOCMatch, err = boolQuery(c, "has_ioc_match"); err != nil {
		return err
	}
	if f.Since, err = parseTimeParam(c, "since"); err != nil {
		return err
	}
	if f.Until, err = parseTimeParam(c, "until"); err != nil {
		return err
	}
	if !f.Since.IsZero() && !f.Until.IsZero() && !f.Since.Before(f.Until) {
		return echo.NewHTTPError(http.StatusBadRequest, "since must be before until")
	}
	if f.Limit, err = atoiBounded(c, "limit", 50, 1, investigate.MaxQueryLimit); err != nil {
		return err
	}
	if f.Offset, err = atoiBounded(c, "offset", 0, 0, investigate.MaxQueryOffset); err != nil {
		return err
	}
	res, err := investigate.Query(s.DB, f, time.Now().UTC())
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "investigation query failed")
	}
	return c.JSON(http.StatusOK, res)
}
