package api

import (
	"errors"
	"net/http"
	"strings"

	"github.com/labstack/echo/v4"

	"vanguard/core/internal/auth"
	"vanguard/core/internal/database"
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
		// A signed token is only a claim about the past. Re-check the live
		// account on every request so that disabling or demoting an account,
		// or restoring a backup that lacks it, takes effect immediately instead
		// of when the token expires. The role in force is the database's, not
		// the one frozen into the token. Fail closed if the check cannot run.
		user, uerr := s.DB.GetUserByID(claims.UserID)
		switch {
		case errors.Is(uerr, database.ErrNotFound):
			return echo.NewHTTPError(http.StatusUnauthorized, "invalid or expired token")
		case uerr != nil:
			// The one documented exception to failing closed: the read-only
			// runtime-health report must still answer when the database is down
			// (that is exactly when an operator needs it). It exposes component
			// states and counters only, and still requires a validly signed,
			// unexpired token.
			if c.Request().Method == http.MethodGet && c.Request().URL.Path == "/api/health/runtime" {
				c.Set(claimsContextKey, claims)
				return next(c)
			}
			return echo.NewHTTPError(http.StatusServiceUnavailable, "authentication backend unavailable")
		case !user.IsActive || !strings.EqualFold(user.Email, claims.Email):
			return echo.NewHTTPError(http.StatusUnauthorized, "invalid or expired token")
		}
		claims.Role = user.Role
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
