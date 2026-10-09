package api

import (
	"net/http"

	"github.com/labstack/echo/v4"

	"vanguard/core/internal/hostsec"
)

// handleDetectorStatus reports each periodic scanner's last run, result and
// last clean scan. A scanner that failed, was skipped (e.g. package
// database absent) or timed out says so; it is never presented as a clean
// scan. When Host Security scanning is disabled the list is empty and
// enabled=false -- "no detectors" is not "no findings".
func (s *Server) handleDetectorStatus(c echo.Context) error {
	if s.Detectors == nil {
		return c.JSON(http.StatusOK, echo.Map{"enabled": false, "detectors": []hostsec.ScanStatus{}})
	}
	list := s.Detectors.Status()
	if list == nil {
		list = []hostsec.ScanStatus{}
	}
	return c.JSON(http.StatusOK, echo.Map{"enabled": true, "detectors": list})
}
