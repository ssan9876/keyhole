package store

import (
	"context"
	"errors"
	"testing"
)

func TestCreatePendingUser(t *testing.T) {
	s := openTemp(t)
	ctx := context.Background()

	u, err := s.CreatePendingUser(ctx, "  Person@Example.com ", "Person", "user")
	if err != nil {
		t.Fatalf("CreatePendingUser: %v", err)
	}

	if u.Email != "person@example.com" {
		t.Errorf("Email = %q, want it normalized to %q", u.Email, "person@example.com")
	}
	if u.Status != "pending" {
		t.Errorf("Status = %q, want %q", u.Status, "pending")
	}
	if !hex32.MatchString(u.ID) {
		t.Errorf("ID = %q, want 32 hex characters", u.ID)
	}
	// A pending account holds no key material at all.
	if u.AuthHash.Valid || u.ProtectedUserKey.Valid || u.PublicKey.Valid {
		t.Error("a pending user must have no key material set")
	}
}

func TestCreatePendingUserRejectsDuplicateEmail(t *testing.T) {
	s := openTemp(t)
	ctx := context.Background()

	if _, err := s.CreatePendingUser(ctx, "person@example.com", "Person", "user"); err != nil {
		t.Fatalf("first create: %v", err)
	}
	_, err := s.CreatePendingUser(ctx, "PERSON@example.com", "Someone Else", "user")
	if !errors.Is(err, ErrEmailTaken) {
		t.Errorf("second create error = %v, want ErrEmailTaken", err)
	}
}

// TestCreatePendingUserDistinguishesIDCollisionFromEmailCollision guards
// against a regression to matching on the driver's error text: both a
// duplicate email and a duplicate id produce a message containing "UNIQUE
// constraint failed", but only the email case may map to ErrEmailTaken.
func TestCreatePendingUserDistinguishesIDCollisionFromEmailCollision(t *testing.T) {
	s := openTemp(t)
	ctx := context.Background()

	// End-to-end: a duplicate email through the public API is ErrEmailTaken.
	if _, err := s.CreatePendingUser(ctx, "person@example.com", "Person", "user"); err != nil {
		t.Fatalf("first create: %v", err)
	}
	if _, err := s.CreatePendingUser(ctx, "PERSON@example.com", "Someone Else", "user"); !errors.Is(err, ErrEmailTaken) {
		t.Errorf("duplicate email error = %v, want ErrEmailTaken", err)
	}

	// CreatePendingUser always generates its own random id, so a duplicate id
	// can't be provoked through the public API. Instead, provoke the raw
	// driver error the same way the insert inside CreatePendingUser would see
	// it, and confirm the classifier used by CreatePendingUser does not treat
	// it as a taken email.
	insert := `INSERT INTO users (id, email, name, role, status, revision, created_at, updated_at)
	           VALUES (?, ?, 'Someone Else', 'user', 'pending', 0, '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z')`
	if _, err := s.DB().Exec(insert, "dup-id", "first@example.com"); err != nil {
		t.Fatalf("seed insert: %v", err)
	}
	_, rawErr := s.DB().Exec(insert, "dup-id", "different@example.com")
	if rawErr == nil {
		t.Fatal("inserting a duplicate id succeeded; expected a primary key violation")
	}
	if got := classifyUserInsertError(rawErr); errors.Is(got, ErrEmailTaken) {
		t.Errorf("a duplicate id was misclassified as ErrEmailTaken: %v", got)
	}
}

func TestCreatePendingUserRejectsBadRole(t *testing.T) {
	s := openTemp(t)
	if _, err := s.CreatePendingUser(context.Background(), "x@example.com", "X", "superuser"); err == nil {
		t.Error("an unknown role was accepted")
	}
}

func TestCreatePendingUserRejectsInvalidEmailAndBlankName(t *testing.T) {
	s := openTemp(t)
	ctx := context.Background()

	if _, err := s.CreatePendingUser(ctx, "not-an-email", "Person", "user"); err == nil {
		t.Error("an email with no @ was accepted")
	}
	if _, err := s.CreatePendingUser(ctx, "", "Person", "user"); err == nil {
		t.Error("an empty email was accepted")
	}
	if _, err := s.CreatePendingUser(ctx, "person@example.com", "   ", "user"); err == nil {
		t.Error("a whitespace-only name was accepted")
	}
}

func TestUserByEmailNormalizesLookup(t *testing.T) {
	s := openTemp(t)
	ctx := context.Background()

	created, err := s.CreatePendingUser(ctx, "person@example.com", "Person", "admin")
	if err != nil {
		t.Fatalf("CreatePendingUser: %v", err)
	}

	found, err := s.UserByEmail(ctx, "  PERSON@EXAMPLE.COM  ")
	if err != nil {
		t.Fatalf("UserByEmail: %v", err)
	}
	if found.ID != created.ID {
		t.Errorf("UserByEmail returned %q, want %q", found.ID, created.ID)
	}
	if found.Role != "admin" {
		t.Errorf("Role = %q, want %q", found.Role, "admin")
	}
}

func TestUserLookupsReportNotFound(t *testing.T) {
	s := openTemp(t)
	ctx := context.Background()

	if _, err := s.UserByEmail(ctx, "nobody@example.com"); !errors.Is(err, ErrNotFound) {
		t.Errorf("UserByEmail error = %v, want ErrNotFound", err)
	}
	if _, err := s.UserByID(ctx, "0123456789abcdef0123456789abcdef"); !errors.Is(err, ErrNotFound) {
		t.Errorf("UserByID error = %v, want ErrNotFound", err)
	}
}

func TestCountUsers(t *testing.T) {
	s := openTemp(t)
	ctx := context.Background()

	if n, err := s.CountUsers(ctx); err != nil || n != 0 {
		t.Fatalf("CountUsers on empty database = %d, %v; want 0, nil", n, err)
	}
	if _, err := s.CreatePendingUser(ctx, "a@example.com", "A", "admin"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreatePendingUser(ctx, "b@example.com", "B", "user"); err != nil {
		t.Fatal(err)
	}
	if n, err := s.CountUsers(ctx); err != nil || n != 2 {
		t.Errorf("CountUsers = %d, %v; want 2, nil", n, err)
	}
}
