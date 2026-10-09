package api

import (
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"

	"vanguard/core/internal/intel"
)

// SecurityConfig is the browser/network trust configuration (Phase 13).
type SecurityConfig struct {
	// AllowedOrigins are exact origins (scheme://host[:port]) that may call
	// the API cross-origin. Empty = same-origin only, which is all the embedded
	// dashboard needs. "*" is never accepted.
	AllowedOrigins []string
	// AllowedHosts are additional DNS names the API may be reached by. IP
	// literals and "localhost" are always allowed. "*" disables the Host check.
	AllowedHosts []string
	// AllowRemoteBootstrap lets the first-run admin account be created from a
	// non-loopback address. Off by default.
	AllowRemoteBootstrap bool
}

// Request bounds.
const (
	// MaxBodyBytes bounds every request body except the IOC import.
	MaxBodyBytes = 64 * 1024
	// importBodySlack is added to intel.MaxImportBytes for the import route.
	importBodySlack = 64 * 1024

	maxHeaderBytes    = 64 * 1024
	readHeaderTimeout = 10 * time.Second
	readTimeout       = 30 * time.Second
	writeTimeout      = 90 * time.Second
	idleTimeout       = 120 * time.Second
)

// secCounters are cumulative, process-local counters of rejected requests,
// exposed by the runtime-health endpoint. They never contain request data.
type secCounters struct {
	hostRejected, originRejected, bodyRejected atomic.Uint64
	loginThrottled, loginFailed                atomic.Uint64
	opLimited                                  atomic.Uint64
	lastThrottle                               atomic.Int64 // unix seconds
}

func (s *Server) applySecurity(e *echo.Echo) {
	// No trusted-proxy model: the client address is the TCP peer, never a
	// forwarded header. (Echo's default would believe X-Forwarded-For, which
	// any client can forge - it feeds the login limiter and Panic Mode's
	// "keep this admin reachable" address.)
	e.IPExtractor = echo.ExtractIPDirect()

	if e.Server != nil {
		e.Server.ReadHeaderTimeout = readHeaderTimeout
		e.Server.ReadTimeout = readTimeout
		e.Server.WriteTimeout = writeTimeout
		e.Server.IdleTimeout = idleTimeout
		e.Server.MaxHeaderBytes = maxHeaderBytes
	}

	e.Use(s.hostCheck)
	e.Use(securityHeaders)
	if len(s.Security.AllowedOrigins) > 0 {
		e.Use(middleware.CORSWithConfig(middleware.CORSConfig{
			AllowOrigins: s.Security.AllowedOrigins,
			AllowMethods: []string{http.MethodGet, http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodOptions},
			AllowHeaders: []string{echo.HeaderOrigin, echo.HeaderContentType, echo.HeaderAuthorization},
		}))
	}
	e.Use(s.originCheck)
	e.Use(s.bodyLimit)
}

// hostOnly strips the port from a Host header value.
func hostOnly(h string) string {
	h = strings.TrimSpace(h)
	if host, _, err := net.SplitHostPort(h); err == nil {
		h = host
	}
	return strings.Trim(strings.ToLower(h), "[]")
}

func (s *Server) hostAllowed(h string) bool {
	host := hostOnly(h)
	if host == "" {
		return false
	}
	for _, a := range s.Security.AllowedHosts {
		if a == "*" || strings.EqualFold(strings.TrimSpace(a), host) {
			return true
		}
	}
	if host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return true
	}
	return net.ParseIP(host) != nil
}

// hostCheck refuses requests whose Host header names something the operator
// did not configure. This is what stops DNS-rebinding: a malicious page's
// rebound name arrives with its own Host value.
func (s *Server) hostCheck(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		if !s.hostAllowed(c.Request().Host) {
			s.sec.hostRejected.Add(1)
			return echo.NewHTTPError(http.StatusForbidden, "this Host is not allowed; add its name to -allowed-hosts")
		}
		return next(c)
	}
}

func securityHeaders(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		h := c.Response().Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		if strings.HasPrefix(c.Request().URL.Path, "/api/") {
			h.Set("Cache-Control", "no-store")
		}
		return next(c)
	}
}

func (s *Server) originAllowed(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true // not a browser cross-site request (curl, scripts, same-origin GET)
	}
	for _, a := range s.Security.AllowedOrigins {
		if strings.EqualFold(a, origin) {
			return true
		}
	}
	u, err := url.Parse(origin)
	if err != nil {
		return false
	}
	return strings.EqualFold(u.Host, r.Host)
}

// originCheck rejects state-changing requests that a browser marks as coming
// from another origin. The API authenticates with a bearer header, not an
// ambient cookie, so classic CSRF does not apply; this is defence in depth for
// the public first-run/login routes and for any future cookie use.
func (s *Server) originCheck(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		switch c.Request().Method {
		case http.MethodGet, http.MethodHead, http.MethodOptions:
			return next(c)
		}
		if !s.originAllowed(c.Request()) {
			s.sec.originRejected.Add(1)
			return echo.NewHTTPError(http.StatusForbidden, "cross-origin state-changing request refused")
		}
		return next(c)
	}
}

// bodyLimit bounds request bodies. Declared oversize bodies are refused with
// 413 up front; undeclared (chunked) ones fail when the limit is crossed.
func (s *Server) bodyLimit(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		r := c.Request()
		limit := int64(MaxBodyBytes)
		if r.URL.Path == "/api/intel/import" {
			limit = intel.MaxImportBytes + importBodySlack
		}
		if r.ContentLength > limit {
			s.sec.bodyRejected.Add(1)
			return echo.NewHTTPError(http.StatusRequestEntityTooLarge, "request body too large")
		}
		if r.Body != nil {
			r.Body = http.MaxBytesReader(c.Response(), r.Body, limit)
		}
		return next(c)
	}
}

// isLoopback reports whether the TCP peer is a loopback address.
func isLoopback(c echo.Context) bool {
	ip := net.ParseIP(c.RealIP())
	return ip != nil && ip.IsLoopback()
}
