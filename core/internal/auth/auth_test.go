package auth

import (
	"testing"
	"time"

	"vanguard/core/internal/database"
)

func TestPasswordHashRoundTrip(t *testing.T) {
	hash, err := HashPassword("correct-horse-battery")
	if err != nil {
		t.Fatalf("HashPassword failed: %v", err)
	}
	if !CheckPassword(hash, "correct-horse-battery") {
		t.Errorf("expected correct password to verify")
	}
	if CheckPassword(hash, "wrong-password") {
		t.Errorf("expected wrong password to fail verification")
	}
}

func TestHashPasswordRejectsShortPassword(t *testing.T) {
	if _, err := HashPassword("short"); err == nil {
		t.Errorf("expected an error for a password under 8 characters")
	}
}

func TestJWTIssueAndVerify(t *testing.T) {
	m, err := NewManager("test-secret-key-do-not-use-in-prod", time.Hour)
	if err != nil {
		t.Fatalf("NewManager failed: %v", err)
	}
	u := &database.User{ID: 42, Email: "admin@example.com", Role: database.RoleAdmin}

	token, expiresAt, err := m.IssueToken(u)
	if err != nil {
		t.Fatalf("IssueToken failed: %v", err)
	}
	if token == "" {
		t.Fatalf("expected a non-empty token")
	}
	if !expiresAt.After(time.Now()) {
		t.Errorf("expected expiresAt in the future")
	}

	claims, err := m.Verify(token)
	if err != nil {
		t.Fatalf("Verify failed: %v", err)
	}
	if claims.UserID != 42 || claims.Email != "admin@example.com" || claims.Role != database.RoleAdmin {
		t.Errorf("unexpected claims: %+v", claims)
	}
}

func TestJWTRejectsTamperedToken(t *testing.T) {
	m, _ := NewManager("secret-a", time.Hour)
	other, _ := NewManager("secret-b", time.Hour)
	u := &database.User{ID: 1, Email: "x@example.com", Role: database.RoleViewer}

	token, _, _ := m.IssueToken(u)
	if _, err := other.Verify(token); err == nil {
		t.Fatalf("expected verification with a different secret to fail")
	}
}

func TestJWTRejectsExpiredToken(t *testing.T) {
	m, _ := NewManager("secret", -time.Hour) // already-expired TTL
	u := &database.User{ID: 1, Email: "x@example.com", Role: database.RoleViewer}
	token, _, _ := m.IssueToken(u)

	// NewManager clamps ttl<=0 to 24h, so force an expired token directly.
	_ = token
	m2, _ := NewManager("secret", time.Millisecond)
	token2, _, _ := m2.IssueToken(u)
	time.Sleep(10 * time.Millisecond)
	if _, err := m2.Verify(token2); err == nil {
		t.Fatalf("expected verification of an expired token to fail")
	}
}
