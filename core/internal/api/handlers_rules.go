package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/labstack/echo/v4"

	"vanguard/core/internal/rules"
	"vanguard/core/internal/tuning"
)

const maxTuningBody = 4 * 1024

func (s *Server) ruleContext() rules.Context {
	c := s.RuleCtx
	if s.Tuning != nil {
		c.Tuning, c.TuningRevision = s.Tuning.Current()
	} else {
		c.Tuning = tuning.Defaults()
	}
	return c
}

// GET /api/rules -- read-only inventory built from the implemented rules.
func (s *Server) handleListRules(c echo.Context) error {
	list := rules.Build(s.ruleContext())
	return c.JSON(http.StatusOK, echo.Map{
		"rules": list, "count": len(list),
		"notes": []string{
			"Rules cannot be disabled individually; whole subsystems are controlled by startup flags (see disabled_by).",
			"Only the settings marked tunable can be changed at runtime, within fixed ranges, via /api/rules/tuning.",
			"automated_response.possible is an upper-bound statement from the scoring formula, not a prediction.",
		},
	})
}

// GET /api/rules/tuning
func (s *Server) handleGetTuning(c echo.Context) error {
	if s.Tuning == nil {
		return echo.NewHTTPError(http.StatusServiceUnavailable, "rule tuning is not available on this instance")
	}
	cur, rev := s.Tuning.Current()
	hist, err := s.Tuning.History(20)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to read tuning history")
	}
	return c.JSON(http.StatusOK, echo.Map{
		"revision": rev, "values": cur, "defaults": tuning.Defaults(), "specs": tuning.Specs(),
		"load_error": s.Tuning.LoadError(), "history": hist,
	})
}

type tuningRequest struct {
	ExpectedRevision     uint         `json:"expected_revision"`
	Values               tuning.Patch `json:"values"`
	Reason               string       `json:"reason"`
	AcknowledgeWeakening bool         `json:"acknowledge_weakening"`
}

// decodeStrict rejects unknown fields and oversize bodies so a request can
// only ever carry the documented numbers.
func decodeStrict(c echo.Context, v any) error {
	b, err := io.ReadAll(io.LimitReader(c.Request().Body, maxTuningBody+1))
	if err != nil || len(b) > maxTuningBody {
		return echo.NewHTTPError(http.StatusRequestEntityTooLarge, "request body too large")
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid request body: "+err.Error())
	}
	return nil
}

// POST /api/rules/tuning/preview -- never mutates.
func (s *Server) handlePreviewTuning(c echo.Context) error {
	if s.Tuning == nil {
		return echo.NewHTTPError(http.StatusServiceUnavailable, "rule tuning is not available on this instance")
	}
	var req tuningRequest
	if err := decodeStrict(c, &req); err != nil {
		return err
	}
	return c.JSON(http.StatusOK, s.Tuning.Preview(req.Values))
}

func tuningErr(c echo.Context, err error) error {
	code, status := "error", http.StatusInternalServerError
	switch {
	case errors.Is(err, tuning.ErrConflict):
		code, status = "conflict", http.StatusConflict
	case errors.Is(err, tuning.ErrInvalid):
		code, status = "invalid", http.StatusUnprocessableEntity
	case errors.Is(err, tuning.ErrNeedsAck):
		code, status = "needs_acknowledgement", http.StatusConflict
	case errors.Is(err, tuning.ErrNoChange):
		code, status = "no_change", http.StatusConflict
	case errors.Is(err, tuning.ErrNothingToRevert):
		code, status = "nothing_to_revert", http.StatusConflict
	case errors.Is(err, tuning.ErrNoActor):
		code, status = "no_actor", http.StatusUnauthorized
	}
	msg := err.Error()
	if status == http.StatusInternalServerError {
		msg = "tuning operation failed"
	}
	return c.JSON(status, echo.Map{"error": msg, "code": code})
}

// PUT /api/rules/tuning (admin)
func (s *Server) handleApplyTuning(c echo.Context) error {
	if err := requireAdmin(c); err != nil {
		return err
	}
	if s.Tuning == nil {
		return echo.NewHTTPError(http.StatusServiceUnavailable, "rule tuning is not available on this instance")
	}
	var req tuningRequest
	if err := decodeStrict(c, &req); err != nil {
		return err
	}
	actor, err := authorOf(c)
	if err != nil {
		return err
	}
	rev, err := s.Tuning.Apply(req.ExpectedRevision, req.Values, actor, req.Reason, req.AcknowledgeWeakening)
	if err != nil {
		return tuningErr(c, err)
	}
	return c.JSON(http.StatusOK, echo.Map{"revision": rev, "applied": true})
}

type rollbackRequest struct {
	ExpectedRevision uint   `json:"expected_revision"`
	Reason           string `json:"reason"`
}

// POST /api/rules/tuning/rollback (admin)
func (s *Server) handleRollbackTuning(c echo.Context) error {
	if err := requireAdmin(c); err != nil {
		return err
	}
	if s.Tuning == nil {
		return echo.NewHTTPError(http.StatusServiceUnavailable, "rule tuning is not available on this instance")
	}
	var req rollbackRequest
	if err := decodeStrict(c, &req); err != nil {
		return err
	}
	actor, err := authorOf(c)
	if err != nil {
		return err
	}
	rev, err := s.Tuning.Rollback(req.ExpectedRevision, actor, req.Reason)
	if err != nil {
		return tuningErr(c, err)
	}
	return c.JSON(http.StatusOK, echo.Map{"revision": rev, "rolled_back": true})
}

// GET /api/rules/guidance -- descriptive observations, never applied.
func (s *Server) handleRuleGuidance(c echo.Context) error {
	cur := tuning.Defaults()
	if s.Tuning != nil {
		cur = s.Tuning.Values()
	}
	g, err := rules.BuildGuidance(s.DB, cur, time.Now().UTC())
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to build guidance")
	}
	return c.JSON(http.StatusOK, echo.Map{
		"guidance": g, "applied_automatically": false,
		"note": "Suggestions only. Nothing here is applied without an explicit operator action.",
	})
}
