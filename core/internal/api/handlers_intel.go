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

// iocView adds the derived, honest lifecycle state to an indicator so the
// UI never has to guess whether something is "active".
type iocView struct {
	database.IOC
	State string `json:"state"` // active | disabled | expired
}

func viewOf(i database.IOC, now time.Time) iocView {
	st := "active"
	switch {
	case !i.Enabled:
		st = "disabled"
	case i.ExpiresAt != nil && !now.Before(*i.ExpiresAt):
		st = "expired"
	}
	return iocView{IOC: i, State: st}
}

func (s *Server) reloadIntel() {
	if s.Intel != nil {
		_ = s.Intel.Reload()
	}
}

func atoiBounded(c echo.Context, name string, def, min, max int) (int, error) {
	v := c.QueryParam(name)
	if v == "" {
		return def, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < min || n > max {
		return 0, echo.NewHTTPError(http.StatusBadRequest, "invalid "+name)
	}
	return n, nil
}

func validIOCType(t string) bool {
	switch database.IOCType(t) {
	case database.IOCIP, database.IOCDomain, database.IOCURL, database.IOCSHA256:
		return true
	}
	return false
}

// GET /api/intel/status
func (s *Server) handleIntelStatus(c echo.Context) error {
	now := time.Now().UTC()
	total, active, err := s.DB.CountIOCs(now)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to count indicators")
	}
	out := echo.Map{"enabled": s.Intel != nil, "indicators_total": total, "indicators_active": active}
	if s.Intel != nil {
		out["matcher"] = s.Intel.Status()
	}
	if imps, err := s.DB.ListIOCImports(1); err == nil && len(imps) == 1 {
		out["last_import"] = imps[0]
	}
	return c.JSON(http.StatusOK, out)
}

// GET /api/intel/iocs
func (s *Server) handleListIOCs(c echo.Context) error {
	f := database.IOCFilter{Type: database.IOCType(c.QueryParam("type")), Source: c.QueryParam("source")}
	if f.Type != "" && !validIOCType(string(f.Type)) {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid type")
	}
	if v := c.QueryParam("value"); v != "" {
		if f.Type == "" {
			return echo.NewHTTPError(http.StatusBadRequest, "value filter requires type")
		}
		norm, err := intel.Normalize(f.Type, v)
		if err != nil {
			return echo.NewHTTPError(http.StatusBadRequest, "invalid value: "+err.Error())
		}
		f.Value = norm
	}
	switch c.QueryParam("state") {
	case "":
	case "active":
		f.ActiveAt = time.Now().UTC()
	case "disabled":
		off := false
		f.Enabled = &off
	default:
		return echo.NewHTTPError(http.StatusBadRequest, "state must be active or disabled")
	}
	var err error
	if f.Limit, err = atoiBounded(c, "limit", 100, 1, 500); err != nil {
		return err
	}
	if f.Offset, err = atoiBounded(c, "offset", 0, 0, 100000); err != nil {
		return err
	}
	rows, err := s.DB.ListIOCs(f)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to list indicators")
	}
	now := time.Now().UTC()
	views := make([]iocView, 0, len(rows))
	for _, r := range rows {
		views = append(views, viewOf(r, now))
	}
	return c.JSON(http.StatusOK, echo.Map{"indicators": views, "count": len(views)})
}

// GET /api/intel/iocs/:id
func (s *Server) handleGetIOC(c echo.Context) error {
	id, err := parseUintParam(c, "id")
	if err != nil {
		return err
	}
	ioc, err := s.DB.GetIOC(id)
	if err != nil {
		if errors.Is(err, database.ErrNotFound) {
			return echo.NewHTTPError(http.StatusNotFound, "indicator not found")
		}
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to fetch indicator")
	}
	var matches int64
	_ = s.DB.Model(&database.IOCMatch{}).Where("ioc_id = ?", id).Count(&matches).Error
	recent, _ := s.DB.HuntMatches(database.HuntFilter{IOCID: id, Limit: 10})
	return c.JSON(http.StatusOK, echo.Map{"indicator": viewOf(*ioc, time.Now().UTC()), "match_count": matches, "recent_matches": recent})
}

type iocPatch struct {
	Enabled *bool `json:"enabled"`
}

// PUT /api/intel/iocs/:id  (admin) -- enable/disable an indicator.
func (s *Server) handleUpdateIOC(c echo.Context) error {
	if err := requireAdmin(c); err != nil {
		return err
	}
	id, err := parseUintParam(c, "id")
	if err != nil {
		return err
	}
	var p iocPatch
	if err := c.Bind(&p); err != nil || p.Enabled == nil {
		return echo.NewHTTPError(http.StatusBadRequest, "body must be {\"enabled\": true|false}")
	}
	ioc, err := s.DB.SetIOCEnabled(id, *p.Enabled)
	if err != nil {
		if errors.Is(err, database.ErrNotFound) {
			return echo.NewHTTPError(http.StatusNotFound, "indicator not found")
		}
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to update indicator")
	}
	s.reloadIntel()
	return c.JSON(http.StatusOK, viewOf(*ioc, time.Now().UTC()))
}

// DELETE /api/intel/iocs/:id  (admin)
func (s *Server) handleDeleteIOC(c echo.Context) error {
	if err := requireAdmin(c); err != nil {
		return err
	}
	id, err := parseUintParam(c, "id")
	if err != nil {
		return err
	}
	if err := s.DB.DeleteIOC(id); err != nil {
		if errors.Is(err, database.ErrNotFound) {
			return echo.NewHTTPError(http.StatusNotFound, "indicator not found")
		}
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to delete indicator")
	}
	s.reloadIntel()
	return c.JSON(http.StatusOK, echo.Map{"message": "indicator deleted"})
}

func boolParam(c echo.Context, name string) bool {
	v := strings.ToLower(c.QueryParam(name))
	return v == "1" || v == "true" || v == "yes"
}

// POST /api/intel/import  (admin) -- body is the vanguard-ioc feed itself.
// The body is hard-limited; the feed is parsed as inert data only.
func (s *Server) handleImportIOCs(c echo.Context) error {
	if err := requireAdmin(c); err != nil {
		return err
	}
	body := http.MaxBytesReader(c.Response(), c.Request().Body, intel.MaxImportBytes+1)
	rep, err := intel.Import(s.DB, body, intel.ImportOptions{
		Source:        c.QueryParam("source"),
		Strict:        boolParam(c, "strict"),
		ReplaceSource: boolParam(c, "replace_source"),
		AllowShrink:   boolParam(c, "allow_shrink"),
	})
	if err != nil {
		if errors.Is(err, intel.ErrImportRejected) {
			return c.JSON(http.StatusUnprocessableEntity, rep)
		}
		return echo.NewHTTPError(http.StatusInternalServerError, "import failed")
	}
	s.reloadIntel()
	return c.JSON(http.StatusOK, rep)
}

// GET /api/intel/imports
func (s *Server) handleListIOCImports(c echo.Context) error {
	n, err := atoiBounded(c, "limit", 20, 1, database.MaxIOCImportRows)
	if err != nil {
		return err
	}
	rows, err := s.DB.ListIOCImports(n)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to list imports")
	}
	return c.JSON(http.StatusOK, echo.Map{"imports": rows, "count": len(rows)})
}

func parseTimeParam(c echo.Context, name string) (time.Time, error) {
	v := c.QueryParam(name)
	if v == "" {
		return time.Time{}, nil
	}
	t, err := time.Parse(time.RFC3339, v)
	if err != nil {
		return time.Time{}, echo.NewHTTPError(http.StatusBadRequest, name+" must be RFC3339")
	}
	return t.UTC(), nil
}

// GET /api/hunt/matches -- bounded, parameterized hunt over recorded IOC
// matches joined to their incidents. Filters: ioc_id, ioc_type, source,
// ip, context (exact matched value), kind (direct|enrichment), since/until
// (RFC3339) or since_hours, incident_type, incident_status, limit<=200,
// offset<=10000. Malformed filters are 400, never ignored.
func (s *Server) handleHuntMatches(c echo.Context) error {
	f := database.HuntFilter{
		IOCType: database.IOCType(c.QueryParam("ioc_type")), Source: c.QueryParam("source"),
		SourceIP: c.QueryParam("ip"), Context: c.QueryParam("context"), Kind: c.QueryParam("kind"),
		IncidentType: database.IncidentType(c.QueryParam("incident_type")), IncidentStatus: database.IncidentStatus(c.QueryParam("incident_status")),
	}
	if f.IOCType != "" && !validIOCType(string(f.IOCType)) {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid ioc_type")
	}
	if f.Kind != "" && f.Kind != "direct" && f.Kind != "enrichment" {
		return echo.NewHTTPError(http.StatusBadRequest, "kind must be direct or enrichment")
	}
	if f.IncidentStatus != "" && !database.IsKnownStatus(f.IncidentStatus) {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid incident_status")
	}
	if f.SourceIP != "" {
		ip, ok := intel.NormalizeObservedIP(f.SourceIP)
		if !ok {
			return echo.NewHTTPError(http.StatusBadRequest, "invalid ip")
		}
		f.SourceIP = ip
	}
	if v := c.QueryParam("ioc_id"); v != "" {
		n, err := strconv.ParseUint(v, 10, 64)
		if err != nil {
			return echo.NewHTTPError(http.StatusBadRequest, "invalid ioc_id")
		}
		f.IOCID = uint(n)
	}
	var err error
	if f.Since, err = parseTimeParam(c, "since"); err != nil {
		return err
	}
	if f.Until, err = parseTimeParam(c, "until"); err != nil {
		return err
	}
	if v := c.QueryParam("since_hours"); v != "" {
		h, herr := strconv.Atoi(v)
		if herr != nil || h <= 0 || h > 24*365 {
			return echo.NewHTTPError(http.StatusBadRequest, "invalid since_hours")
		}
		f.Since = time.Now().UTC().Add(-time.Duration(h) * time.Hour)
	}
	if f.Limit, err = atoiBounded(c, "limit", 50, 1, 200); err != nil {
		return err
	}
	if f.Offset, err = atoiBounded(c, "offset", 0, 0, 10000); err != nil {
		return err
	}
	var rows []database.HuntRow
	if err := s.guarded(c, func() (e error) { rows, e = s.DB.HuntMatches(f); return }); err != nil {
		return guardFailure(c, err, "hunt query failed")
	}
	if rows == nil {
		rows = []database.HuntRow{}
	}
	return c.JSON(http.StatusOK, echo.Map{
		"matches": rows, "count": len(rows), "limit": f.Limit, "offset": f.Offset,
		"note": "results are limited to recorded indicator matches (bounded history); VANGUARD does not retain raw events",
	})
}
