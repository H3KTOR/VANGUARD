package api

import (
	"errors"
	"net/http"
	"time"

	"github.com/labstack/echo/v4"

	"vanguard/core/internal/backup"
	"vanguard/core/internal/database"
)

// Backup API. All three endpoints are ADMIN-ONLY. By design:
//   - backups can be created and verified over the API, but never
//     downloaded (copy them from the host);
//   - restore is NOT available over the API: replacing the database under
//     a running daemon is unsafe, so it is an explicit offline CLI action;
//   - responses never contain filesystem paths, only backup names.

type createBackupRequest struct {
	Label        string `json:"label"`
	ExcludeUsers bool   `json:"exclude_users"`
}

func (s *Server) backupDisabled() error {
	if s.BackupDir == "" {
		return echo.NewHTTPError(http.StatusServiceUnavailable, "backups are not configured on this instance")
	}
	return nil
}

// GET /api/backup
func (s *Server) handleListBackups(c echo.Context) error {
	if err := requireAdmin(c); err != nil {
		return err
	}
	if err := s.backupDisabled(); err != nil {
		return err
	}
	l, err := backup.List(s.BackupDir)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "could not list backups")
	}
	audit, _ := s.DB.ListBackupAudit(10)
	last := ""
	if len(l) > 0 {
		last = l[0].CreatedAt
	}
	return c.JSON(http.StatusOK, echo.Map{
		"backups": l, "count": len(l), "max_backups": backup.MaxBackups, "last_backup_at": last, "recent_activity": audit,
		"note": "Restore is an offline CLI operation (vanguard backup restore); see docs/PHASE11.md. Checksums detect corruption, not tampering.",
	})
}

// POST /api/backup
func (s *Server) handleCreateBackup(c echo.Context) error {
	if err := requireAdmin(c); err != nil {
		return err
	}
	if err := s.backupDisabled(); err != nil {
		return err
	}
	var req createBackupRequest
	if err := decodeStrict(c, &req); err != nil {
		return err
	}
	actor, err := authorOf(c)
	if err != nil {
		return err
	}
	release, wait, ok := s.backupGate.enter()
	if !ok {
		return s.opLimited(c, "backup.create", wait)
	}
	defer release()
	name, m, cerr := backup.Create(s.DB, backup.CreateOptions{Dir: s.BackupDir, Label: req.Label, ExcludeUsers: req.ExcludeUsers, Actor: actor, Now: time.Now().UTC()})
	res, detail, sum := "ok", "", ""
	if cerr != nil {
		res, detail = "failed", cerr.Error()
	} else {
		sum = m.DBSHA256
	}
	_ = s.DB.RecordBackupAudit(&database.BackupAudit{Kind: "create", Actor: actor, BackupName: name, DBSHA256: sum, Result: res, Detail: detail})
	switch {
	case cerr == nil:
		return c.JSON(http.StatusCreated, echo.Map{"name": name, "manifest": m})
	case errors.Is(cerr, backup.ErrExists), errors.Is(cerr, backup.ErrTooManyBackups):
		return echo.NewHTTPError(http.StatusConflict, cerr.Error())
	case errors.Is(cerr, backup.ErrInvalidName):
		return echo.NewHTTPError(http.StatusBadRequest, cerr.Error())
	case errors.Is(cerr, backup.ErrTooLarge):
		return echo.NewHTTPError(http.StatusRequestEntityTooLarge, cerr.Error())
	}
	return echo.NewHTTPError(http.StatusInternalServerError, "backup failed (see server log)")
}

// GET /api/backup/:name/verify -- read-only.
func (s *Server) handleVerifyBackup(c echo.Context) error {
	if err := requireAdmin(c); err != nil {
		return err
	}
	if err := s.backupDisabled(); err != nil {
		return err
	}
	rep, err := backup.Verify(s.BackupDir, c.Param("name"))
	if err != nil {
		if errors.Is(err, backup.ErrInvalidName) {
			return echo.NewHTTPError(http.StatusBadRequest, "invalid backup name")
		}
		return echo.NewHTTPError(http.StatusInternalServerError, "verification failed")
	}
	res := auditOK
	if !rep.Valid {
		res = auditFailed // the verification RAN and reported the backup as not valid
	}
	s.audit(c, "backup.verify", c.Param("name"), res, "")
	return c.JSON(http.StatusOK, rep)
}
