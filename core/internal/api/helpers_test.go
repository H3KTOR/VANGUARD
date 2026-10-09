package api

import (
	"testing"

	"vanguard/core/internal/auth"
	"vanguard/core/internal/database"
)

// realUserToken stores an account and issues a token for it. Tokens are
// re-validated against the live account on every request, so a token for an
// account that does not exist (the old shortcut) is no longer accepted.
func realUserToken(t *testing.T, db *database.DB, mgr *auth.Manager, email string, role database.Role) string {
	t.Helper()
	hash, err := auth.HashPassword("a-test-password-123")
	if err != nil {
		t.Fatal(err)
	}
	u := &database.User{Email: email, PasswordHash: hash, Role: role, IsActive: true}
	if err := db.CreateUser(u); err != nil {
		t.Fatal(err)
	}
	jti, _ := database.NewSessionID()
	tok, exp, err := mgr.IssueSessionToken(u, jti)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.CreateSession(&database.Session{ID: jti, UserID: u.ID, ExpiresAt: exp}); err != nil {
		t.Fatal(err)
	}
	return tok
}
