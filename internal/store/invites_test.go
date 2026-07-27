package store

import (
	"context"
	"errors"
	"testing"
	"time"
)

func makeUser(t *testing.T, s *Store, email string) User {
	t.Helper()
	u, err := s.CreatePendingUser(context.Background(), email, "Test", "user")
	if err != nil {
		t.Fatalf("CreatePendingUser: %v", err)
	}
	return u
}

func TestCreateInviteReturnsATokenStoredOnlyAsAHash(t *testing.T) {
	s := openTemp(t)
	ctx := context.Background()
	u := makeUser(t, s, "person@example.com")

	invite, token, err := s.CreateInvite(ctx, u.ID, 48*time.Hour)
	if err != nil {
		t.Fatalf("CreateInvite: %v", err)
	}
	if token == "" {
		t.Fatal("CreateInvite returned an empty token")
	}
	if invite.UserID != u.ID {
		t.Errorf("UserID = %q, want %q", invite.UserID, u.ID)
	}

	// The raw token must not be recoverable from the database.
	var stored string
	if err := s.DB().QueryRow(`SELECT token_hash FROM invites WHERE id = ?`, invite.ID).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if stored == token {
		t.Error("the invite token was stored in the clear")
	}
	if stored != HashToken(token) {
		t.Error("stored value is not the SHA-256 of the token")
	}
}

func TestInviteByTokenRoundTrips(t *testing.T) {
	s := openTemp(t)
	ctx := context.Background()
	u := makeUser(t, s, "person@example.com")

	created, token, err := s.CreateInvite(ctx, u.ID, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	found, err := s.InviteByToken(ctx, token)
	if err != nil {
		t.Fatalf("InviteByToken: %v", err)
	}
	if found.ID != created.ID {
		t.Errorf("InviteByToken returned %q, want %q", found.ID, created.ID)
	}
}

func TestInviteByTokenRejectsUnknownToken(t *testing.T) {
	s := openTemp(t)
	if _, err := s.InviteByToken(context.Background(), "not-a-real-token"); !errors.Is(err, ErrNotFound) {
		t.Errorf("error = %v, want ErrNotFound", err)
	}
}

func TestInviteByTokenRejectsUsedInvite(t *testing.T) {
	s := openTemp(t)
	ctx := context.Background()
	u := makeUser(t, s, "person@example.com")

	invite, token, err := s.CreateInvite(ctx, u.ID, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	// Marked used directly, because the only thing that consumes an invite in
	// production is CompleteEnrollment, inside its own transaction. This test
	// is about InviteByToken's treatment of a used row, not about how it got
	// that way.
	if _, err := s.DB().ExecContext(ctx,
		`UPDATE invites SET used_at = ? WHERE id = ?`,
		time.Now().UTC().Format(time.RFC3339), invite.ID); err != nil {
		t.Fatalf("mark used: %v", err)
	}
	// A one-time link must be exactly one time: a leaked URL in a chat log
	// cannot be replayed to seize an account that was already set up.
	if _, err := s.InviteByToken(ctx, token); !errors.Is(err, ErrNotFound) {
		t.Errorf("used invite error = %v, want ErrNotFound", err)
	}
}

func TestInviteByTokenRejectsExpiredInvite(t *testing.T) {
	s := openTemp(t)
	ctx := context.Background()
	u := makeUser(t, s, "person@example.com")

	_, token, err := s.CreateInvite(ctx, u.ID, -time.Minute) // already expired
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.InviteByToken(ctx, token); !errors.Is(err, ErrNotFound) {
		t.Errorf("expired invite error = %v, want ErrNotFound", err)
	}
}
