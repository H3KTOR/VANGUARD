// Package auth implements password hashing and JWT issuance/verification
// for VANGUARD's REST API. Kept deliberately small and dependency-light:
// bcrypt for passwords (via golang.org/x/crypto, already a transitive dep
// of nothing else so this is the only crypto dependency added) and
// golang-jwt/jwt for stateless session tokens (no server-side session
// store needed, keeping with the zero-extra-services constraint).
package auth

import (
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"

	"vanguard/core/internal/database"
)

// ErrInvalidToken is returned by Verify for any malformed, expired, or
// signature-mismatched token.
var ErrInvalidToken = errors.New("auth: invalid or expired token")

// Claims is the JWT payload VANGUARD issues. Kept minimal: just enough to
// authorize API requests and render "logged in as X (role Y)" in the
// dashboard, without needing a DB round-trip on every request.
type Claims struct {
	UserID uint          `json:"user_id"`
	Email  string        `json:"email"`
	Role   database.Role `json:"role"`
	jwt.RegisteredClaims
}

// Manager issues and verifies JWTs using a single HMAC secret. In a real
// deployment the secret should be a long random value loaded from an
// environment variable / secrets file, never hardcoded -- see
// cmd/vanguard's flag/env wiring.
type Manager struct {
	secret   []byte
	tokenTTL time.Duration
	issuer   string
}

// NewManager constructs a Manager. secret must be non-empty; ttl defaults
// to 24h if <= 0.
func NewManager(secret string, ttl time.Duration) (*Manager, error) {
	if secret == "" {
		return nil, errors.New("auth: JWT secret must not be empty")
	}
	if ttl <= 0 {
		ttl = 24 * time.Hour
	}
	return &Manager{secret: []byte(secret), tokenTTL: ttl, issuer: "vanguard-core"}, nil
}

// HashPassword bcrypt-hashes a plaintext password for storage in
// User.PasswordHash. Uses bcrypt's default cost (10), which is a
// reasonable balance of security and CPU time on modest hardware -- this
// matters because VANGUARD explicitly targets low-resource hosts.
func HashPassword(plaintext string) (string, error) {
	if len(plaintext) < 8 {
		return "", errors.New("auth: password must be at least 8 characters")
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(plaintext), bcrypt.DefaultCost)
	if err != nil {
		return "", fmt.Errorf("auth: failed to hash password: %w", err)
	}
	return string(hash), nil
}

// CheckPassword reports whether plaintext matches the given bcrypt hash.
func CheckPassword(hash, plaintext string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(plaintext)) == nil
}

// IssueToken creates a signed JWT for the given user.
func (m *Manager) IssueToken(u *database.User) (string, time.Time, error) {
	now := time.Now().UTC()
	expiresAt := now.Add(m.tokenTTL)

	claims := Claims{
		UserID: u.ID,
		Email:  u.Email,
		Role:   u.Role,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    m.issuer,
			Subject:   fmt.Sprintf("%d", u.ID),
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(expiresAt),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString(m.secret)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("auth: failed to sign token: %w", err)
	}
	return signed, expiresAt, nil
}

// Verify parses and validates a JWT, returning its Claims if valid.
func (m *Manager) Verify(tokenString string) (*Claims, error) {
	claims := &Claims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("auth: unexpected signing method %v", t.Header["alg"])
		}
		return m.secret, nil
	})
	if err != nil || !token.Valid {
		return nil, ErrInvalidToken
	}
	return claims, nil
}
