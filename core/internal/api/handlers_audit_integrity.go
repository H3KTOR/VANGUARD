package api

import (
	"net/http"
	"strconv"

	"github.com/labstack/echo/v4"

	"vanguard/core/internal/database"
)

// GET /api/audit/integrity?from_seq=&max_entries= -- ADMIN-ONLY, read-only, bounded.
//
// Re-computes the audit ledger's hash chain and re-reads the sealed audit
// records (admin_audits, backup_audits, retention_runs, rule_tuning_revisions).
// It never writes. "ok": true means no inconsistency was found in the entries
// examined; it does NOT prove the database was not rewritten by someone who
// could also recompute the chain (only an external checkpoint can show that,
// see `vanguard audit checkpoint`), and it says nothing about tables the ledger
// does not cover (incident events, notes, IOC imports).
func (s *Server) handleAuditIntegrity(c echo.Context) error {
	if err := requireAdmin(c); err != nil {
		return err
	}
	from, err := strconv.ParseUint(c.QueryParam("from_seq"), 10, 64)
	if c.QueryParam("from_seq") != "" && err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid from_seq")
	}
	if c.QueryParam("from_seq") == "" {
		from = 0
	}
	max, err := atoiBounded(c, "max_entries", database.MaxVerifyEntries, 1, database.MaxVerifyEntries)
	if err != nil {
		return err
	}
	var rep *database.VerifyReport
	if err := s.guarded(c, func() (e error) {
		rep, e = s.DB.VerifyLedger(database.VerifyOptions{FromSeq: from, MaxEntries: max})
		return
	}); err != nil {
		return guardFailure(c, err, "audit verification could not run")
	}
	return c.JSON(http.StatusOK, echo.Map{
		"report":         rep,
		"covers":         database.LedgerKinds,
		"does_not_cover": []string{"incident_events", "incident_notes", "ioc_imports", "firewall_rules", "users"},
		"meaning":        "ok=true: no inconsistency found in the entries examined, under the assumptions in docs/PHASE15.md. It is not proof of authenticity, and records written in the last minute are not yet sealed.",
	})
}
