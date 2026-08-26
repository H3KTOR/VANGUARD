// frontend.go embeds the compiled Vite/React dashboard (core/frontend)
// directly into the vanguard binary and wires it onto the Echo instance
// built by internal/api.Server.NewEcho().
//
// Why this lives in cmd/vanguard rather than internal/api:
//   - internal/api is deliberately frontend-agnostic (see server.go's
//     doc comment) so it stays trivial to unit test with httptest without
//     needing a built dist/ directory on disk.
//   - Go's `//go:embed` directive can only reach files inside (or below)
//     the package directory containing the directive -- it cannot use
//     "../" to climb out to internal/api. Since the frontend build output
//     is physically produced at cmd/vanguard/dist (see
//     frontend/vite.config.js's outDir), the embed must live here too.
//
// Build order: `cd core/frontend && npm run build` must run BEFORE
// `go build ./cmd/vanguard` (see the root Makefile's `build` target),
// otherwise `dist/` won't exist and this file's embed directive will fail
// the Go build outright. A checked-in `dist/.gitkeep` placeholder (see
// below) keeps `go build` from failing on a fresh checkout before the
// first frontend build has ever run.
package main

import (
	"embed"
	"io"
	"io/fs"
	"net/http"

	"github.com/labstack/echo/v4"
)

//go:embed all:dist
var distFS embed.FS

// mountFrontend attaches the embedded dashboard's static assets and a
// client-side-routing-friendly catch-all to the given Echo instance.
// Must be called after every /api/* route is already registered (see
// NewEcho in internal/api/server.go), since the catch-all below matches
// everything Echo hasn't already routed.
func mountFrontend(e *echo.Echo) error {
	// Strip the embed's "dist" prefix so the FS root matches what
	// index.html/assets expect (i.e. distFS's "dist/index.html" becomes
	// "index.html" in distRoot).
	distRoot, err := fs.Sub(distFS, "dist")
	if err != nil {
		return err
	}
	assetHandler := http.FileServer(http.FS(distRoot))

	// Serve the Vite build's fingerprinted assets (dist/assets/*.js,
	// *.css) and top-level static files (favicon, etc.) directly.
	e.GET("/assets/*", echo.WrapHandler(assetHandler))
	e.GET("/vanguard.svg", echo.WrapHandler(assetHandler))
	e.GET("/vite.svg", echo.WrapHandler(assetHandler))

	// Single-page-app fallback: any GET that isn't already matched by an
	// /api/* route or a static asset above serves index.html, letting the
	// React app's own client-side page state (App.jsx's `page` state)
	// handle "routing" without needing real server-side routes per page.
	e.GET("/*", func(c echo.Context) error {
		index, err := distRoot.Open("index.html")
		if err != nil {
			return echo.NewHTTPError(http.StatusNotFound,
				"dashboard build not found -- run `npm run build` in core/frontend before building vanguard")
		}
		defer index.Close()

		c.Response().Header().Set(echo.HeaderContentType, "text/html; charset=utf-8")
		c.Response().WriteHeader(http.StatusOK)
		_, err = io.Copy(c.Response(), index)
		return err
	})

	return nil
}
