package api

import (
	"net/http"
	"strings"

	"github.com/labstack/echo/v4"

	"vanguard/core/internal/auth"
)

// claimsContextKey is the echo.Context key handlers use to retrieve the
// authenticated user's claims after jwtMiddleware has run.
const claimsContextKey = "vanguard_claims"

// jwtMiddleware requires a valid "Authorization: Bearer <token>" header,
// verifies it via the injected auth.Manager, and stashes the resulting
// Claims on the request context for downstream handlers (see currentClaims).
func (s *Server) jwtMiddleware(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		header := c.Request().Header.Get(echo.HeaderAuthorization)
		if header == "" {
			return echo.NewHTTPError(http.StatusUnauthorized, "missing Authorization header")
		}
		parts := strings.SplitN(header, " ", 2)
		if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
			return echo.NewHTTPError(http.StatusUnauthorized, "Authorization header must be 'Bearer <token>'")
		}
		claims, err := s.Auth.Verify(strings.TrimSpace(parts[1]))
		if err != nil {
			return echo.NewHTTPError(http.StatusUnauthorized, "invalid or expired token")
		}
		c.Set(claimsContextKey, claims)
		return next(c)
	}
}

// currentClaims fetches the authenticated user's Claims, previously set by
// jwtMiddleware. Panics only if called on a route not protected by that
// middleware, which would be a programming error, not a runtime condition.
func currentClaims(c echo.Context) *auth.Claims {
	claims, _ := c.Get(claimsContextKey).(*auth.Claims)
	return claims
}

// requireAdmin is an extra per-handler guard for destructive/admin-only
// actions (manual block, panic mode, whitelist changes) on top of the
// baseline jwtMiddleware authentication.
func requireAdmin(c echo.Context) error {
	claims := currentClaims(c)
	if claims == nil {
		return echo.NewHTTPError(http.StatusUnauthorized, "authentication required")
	}
	// database.RoleAdmin comparison done as a string to avoid importing
	// database here just for the constant -- Claims.Role's underlying type
	// already matches.
	if string(claims.Role) != "admin" {
		return echo.NewHTTPError(http.StatusForbidden, "admin role required for this action")
	}
	return nil
}
