package api

import (
	"errors"
	"log"
	"net/http"
	"strconv"
	"strings"
	"sync"

	"github.com/labstack/echo/v4"
	"gorm.io/gorm"

	"vanguard/core/internal/auth"
	"vanguard/core/internal/database"
)

// Credential bounds. bcrypt only uses the first 72 bytes, so a longer password
// would silently weaken to its prefix; it is refused instead.
const (
	maxEmailLen    = 254
	maxPasswordLen = 72
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

var (
	dummyHashOnce sync.Once
	dummyHash     string
)

// absentUserHash is a valid bcrypt hash of a random value, compared against
// when the account does not exist so that "no such user" costs the same CPU
// time as "wrong password" and login timing cannot enumerate accounts.
func absentUserHash() string {
	dummyHashOnce.Do(func() {
		h, err := auth.HashPassword("vanguard-absent-user-placeholder")
		if err != nil {
			h = ""
		}
		dummyHash = h
	})
	return dummyHash
}

// acquireHash takes one of the bounded password-hashing slots.
func (s *Server) acquireHash() (release func(), ok bool) {
	t := newTimer(bcryptWait)
	defer t.Stop()
	select {
	case s.hashSem <- struct{}{}:
		return func() { <-s.hashSem }, true
	case <-t.C:
		return nil, false
	}
}

func validEmail(e string) bool {
	if e == "" || len(e) > maxEmailLen {
		return false
	}
	at := strings.IndexByte(e, '@')
	if at < 1 || at == len(e)-1 || strings.Count(e, "@") != 1 {
		return false
	}
	for _, r := range e {
		if r <= ' ' || r == 0x7f {
			return false
		}
	}
	return true
}

func (s *Server) throttled(c echo.Context) error {
	if blocked, wait := s.loginLimiter.blocked(c.RealIP()); blocked {
		s.sec.loginThrottled.Add(1)
		s.sec.lastThrottle.Store(nowUnix())
		secs := int(wait.Seconds()) + 1
		c.Response().Header().Set("Retry-After", strconv.Itoa(secs))
		log.Printf("[api] authentication attempts from %s are throttled for %ds after repeated failures", c.RealIP(), secs)
		return echo.NewHTTPError(http.StatusTooManyRequests, "too many failed attempts; try again later")
	}
	return nil
}

func (s *Server) authFailed(c echo.Context) {
	s.sec.loginFailed.Add(1)
	s.loginLimiter.fail(c.RealIP())
}

// handleLogin verifies email+password against the stored bcrypt hash and,
// on success, issues a signed JWT the frontend stores and replays as
// "Authorization: Bearer <token>" on every subsequent request.
//
// Every credential failure - unknown account, wrong password, disabled
// account, malformed input - returns the same 401 after the same amount of
// hashing work, and counts toward the per-address throttle.
func (s *Server) handleLogin(c echo.Context) error {
	if err := s.throttled(c); err != nil {
		return err
	}
	var req loginRequest
	if err := c.Bind(&req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid request body")
	}
	if req.Email == "" || req.Password == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "email and password are required")
	}
	bad := echo.NewHTTPError(http.StatusUnauthorized, "invalid email or password")
	if len(req.Email) > maxEmailLen || len(req.Password) > maxPasswordLen {
		s.authFailed(c)
		return bad
	}

	user, uerr := s.DB.GetUserByEmail(req.Email)
	hash := absentUserHash()
	if uerr == nil {
		hash = user.PasswordHash
	} else if !errors.Is(uerr, gorm.ErrRecordNotFound) {
		return echo.NewHTTPError(http.StatusServiceUnavailable, "authentication backend unavailable")
	}
	release, ok := s.acquireHash()
	if !ok {
		return echo.NewHTTPError(http.StatusServiceUnavailable, "server is busy; retry shortly")
	}
	match := auth.CheckPassword(hash, req.Password)
	release()
	if uerr != nil || !match || !user.IsActive {
		s.authFailed(c)
		return bad
	}

	token, expiresAt, err := s.Auth.IssueToken(user)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to issue token")
	}
	s.loginLimiter.reset(c.RealIP())
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
// account after deployment, and then only from the host itself unless the
// operator opted in with -allow-remote-bootstrap. Once at least one user
// exists, this endpoint requires a valid admin JWT (checked manually here
// since it sits on the public router group, before jwtMiddleware).
//
// The count-then-create sequence is serialized so two simultaneous
// first-run requests cannot both become admin.
func (s *Server) handleRegister(c echo.Context) error {
	if err := s.throttled(c); err != nil {
		return err
	}
	var req registerRequest
	if err := c.Bind(&req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid request body")
	}
	if req.Email == "" || req.Password == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "email and password are required")
	}
	if !validEmail(req.Email) {
		return echo.NewHTTPError(http.StatusBadRequest, "email is not valid")
	}
	if len(req.Password) > maxPasswordLen {
		return echo.NewHTTPError(http.StatusBadRequest, "password must be at most 72 bytes")
	}

	s.registerMu.Lock()
	defer s.registerMu.Unlock()

	var userCount int64
	if err := s.DB.Model(&database.User{}).Count(&userCount).Error; err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to check existing users")
	}

	role := database.RoleViewer
	actor := "bootstrap"
	if userCount == 0 {
		if !s.Security.AllowRemoteBootstrap && !isLoopback(c) {
			s.authFailed(c)
			return echo.NewHTTPError(http.StatusForbidden,
				"first-run account creation is only allowed from the host itself; create the admin from localhost (or start with -allow-remote-bootstrap)")
		}
		// Bootstrap case: first account created is always an admin,
		// regardless of what the (unauthenticated, untrusted) request body
		// asked for.
		role = database.RoleAdmin
	} else {
		claims, err := s.claimsFromRequest(c)
		if err != nil || string(claims.Role) != string(database.RoleAdmin) {
			s.authFailed(c)
			return echo.NewHTTPError(http.StatusForbidden, "registration is closed; ask an existing admin to create your account")
		}
		// The token must still belong to a live, active admin.
		live, lerr := s.DB.GetUserByID(claims.UserID)
		if lerr != nil || !live.IsActive || live.Role != database.RoleAdmin {
			s.authFailed(c)
			return echo.NewHTTPError(http.StatusForbidden, "registration is closed; ask an existing admin to create your account")
		}
		actor = live.Email
		if req.Role == string(database.RoleAdmin) {
			role = database.RoleAdmin
		}
	}

	release, ok := s.acquireHash()
	if !ok {
		return echo.NewHTTPError(http.StatusServiceUnavailable, "server is busy; retry shortly")
	}
	hash, err := auth.HashPassword(req.Password)
	release()
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}

	user := &database.User{Email: req.Email, PasswordHash: hash, Role: role, IsActive: true}
	if err := s.DB.CreateUser(user); err != nil {
		return echo.NewHTTPError(http.StatusConflict, "a user with that email already exists")
	}
	_ = s.DB.RecordAdminAudit(&database.AdminAudit{Actor: actor, ActorRole: string(role), Action: "user.create",
		Target: "user:" + strconv.FormatUint(uint64(user.ID), 10), Result: auditOK, Detail: "role " + string(role)})

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
