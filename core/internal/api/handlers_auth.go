package api

import (
	"net/http"

	"github.com/labstack/echo/v4"

	"vanguard/core/internal/auth"
	"vanguard/core/internal/database"
)

type loginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type loginResponse struct {
	Token     string         `json:"token"`
	ExpiresAt string         `json:"expires_at"`
	User      publicUserView `json:"user"`
}

type publicUserView struct {
	ID    uint          `json:"id"`
	Email string        `json:"email"`
	Role  database.Role `json:"role"`
}

func toPublicUser(u *database.User) publicUserView {
	return publicUserView{ID: u.ID, Email: u.Email, Role: u.Role}
}

// handleLogin verifies email+password against the stored bcrypt hash and,
// on success, issues a signed JWT the frontend stores and replays as
// "Authorization: Bearer <token>" on every subsequent request.
func (s *Server) handleLogin(c echo.Context) error {
	var req loginRequest
	if err := c.Bind(&req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid request body")
	}
	if req.Email == "" || req.Password == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "email and password are required")
	}

	user, err := s.DB.GetUserByEmail(req.Email)
	if err != nil {
		// Deliberately identical error for "no such user" and "bad password"
		// so login can't be used to enumerate valid accounts.
		return echo.NewHTTPError(http.StatusUnauthorized, "invalid email or password")
	}
	if !user.IsActive {
		return echo.NewHTTPError(http.StatusForbidden, "account is disabled")
	}
	if !auth.CheckPassword(user.PasswordHash, req.Password) {
		return echo.NewHTTPError(http.StatusUnauthorized, "invalid email or password")
	}

	token, expiresAt, err := s.Auth.IssueToken(user)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to issue token")
	}
	if err := s.DB.TouchLastLogin(user.ID); err != nil {
		c.Logger().Warnf("failed to touch last_login_at for user #%d: %v", user.ID, err)
	}

	return c.JSON(http.StatusOK, loginResponse{
		Token:     token,
		ExpiresAt: expiresAt.Format(rfc3339),
		User:      toPublicUser(user),
	})
}

type registerRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
	Role     string `json:"role"` // ignored unless the caller is an authenticated admin; see below
}

// handleRegister creates a new dashboard user. It is intentionally
// self-limiting: registration is open (no auth required) ONLY while the
// users table is empty, so the very first operator can bootstrap an admin
// account after deployment. Once at least one user exists, this endpoint
// requires a valid admin JWT (checked manually here since it sits on the
// public router group, before jwtMiddleware) -- preventing an attacker who
// finds the endpoint from ever self-registering an account.
func (s *Server) handleRegister(c echo.Context) error {
	var req registerRequest
	if err := c.Bind(&req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid request body")
	}
	if req.Email == "" || req.Password == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "email and password are required")
	}

	var userCount int64
	if err := s.DB.Model(&database.User{}).Count(&userCount).Error; err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to check existing users")
	}

	role := database.RoleViewer
	if userCount == 0 {
		// Bootstrap case: first account created is always an admin,
		// regardless of what the (unauthenticated, untrusted) request body
		// asked for.
		role = database.RoleAdmin
	} else {
		// Every subsequent registration must be performed by an
		// authenticated admin, verified by hand here (this route runs
		// before jwtMiddleware since it must stay reachable during
		// bootstrap when no token can exist yet).
		claims, err := s.claimsFromRequest(c)
		if err != nil || string(claims.Role) != string(database.RoleAdmin) {
			return echo.NewHTTPError(http.StatusForbidden, "registration is closed; ask an existing admin to create your account")
		}
		if req.Role == string(database.RoleAdmin) {
			role = database.RoleAdmin
		}
	}

	hash, err := auth.HashPassword(req.Password)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}

	user := &database.User{Email: req.Email, PasswordHash: hash, Role: role, IsActive: true}
	if err := s.DB.CreateUser(user); err != nil {
		return echo.NewHTTPError(http.StatusConflict, "a user with that email already exists")
	}

	return c.JSON(http.StatusCreated, toPublicUser(user))
}

// handleMe returns the profile of the currently authenticated user, letting
// the frontend render "logged in as ..." without re-decoding the JWT itself.
func (s *Server) handleMe(c echo.Context) error {
	claims := currentClaims(c)
	if claims == nil {
		return echo.NewHTTPError(http.StatusUnauthorized, "authentication required")
	}
	return c.JSON(http.StatusOK, echo.Map{
		"user_id": claims.UserID,
		"email":   claims.Email,
		"role":    claims.Role,
	})
}

// claimsFromRequest verifies the Authorization header outside the normal
// jwtMiddleware chain, used only by handleRegister's manual admin-gate
// (that route is public so bootstrap can happen, but still needs to check
// for an admin token on subsequent calls).
func (s *Server) claimsFromRequest(c echo.Context) (*auth.Claims, error) {
	header := c.Request().Header.Get(echo.HeaderAuthorization)
	const prefix = "Bearer "
	if len(header) <= len(prefix) || header[:len(prefix)] != prefix {
		return nil, echo.NewHTTPError(http.StatusUnauthorized, "missing bearer token")
	}
	return s.Auth.Verify(header[len(prefix):])
}

const rfc3339 = "2006-01-02T15:04:05Z07:00"
