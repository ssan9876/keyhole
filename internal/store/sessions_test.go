package store

import (
	"context"
	"errors"
	"testing"
	"time"
)

// enrolledUser returns an active user, since sessions are only issued to those.
func enrolledUser(t *testing.T, s *Store, email string) User {
	t.Helper()
	ctx := context.Background()

	u := makeUser(t, s, email)
	_, token, err := s.CreateInvite(ctx, u.ID, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	enrolled, err := s.CompleteEnrollment(ctx, token, sampleEnrollment())
	if err != nil {
		t.Fatalf("CompleteEnrollment: %v", err)
	}
	return enrolled
}

func TestCreateSessionStoresOnlyHashes(t *testing.T) {
	s := openTemp(t)
	ctx := context.Background()
	u := enrolledUser(t, s, "person@example.com")

	sess, access, refresh, err := s.CreateSession(ctx, u.ID, "Firefox on Linux")
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	if access == "" || refresh == "" {
		t.Fatal("CreateSession returned an empty token")
	}
	if access == refresh {
		t.Error("the access and refresh tokens are identical")
	}

	var storedAccess, storedRefresh string
	err = s.DB().QueryRow(`SELECT token_hash, refresh_hash FROM sessions WHERE id = ?`, sess.ID).
		Scan(&storedAccess, &storedRefresh)
	if err != nil {
		t.Fatal(err)
	}
	if storedAccess == access || storedRefresh == refresh {
		t.Error("a session token was stored in the clear")
	}
	if storedAccess != HashToken(access) || storedRefresh != HashToken(refresh) {
		t.Error("stored values are not the SHA-256 of the tokens")
	}
}

func TestSessionByAccessTokenRoundTrips(t *testing.T) {
	s := openTemp(t)
	ctx := context.Background()
	u := enrolledUser(t, s, "person@example.com")

	created, access, _, err := s.CreateSession(ctx, u.ID, "cli")
	if err != nil {
		t.Fatal(err)
	}
	found, err := s.SessionByAccessToken(ctx, access)
	if err != nil {
		t.Fatalf("SessionByAccessToken: %v", err)
	}
	if found.ID != created.ID || found.UserID != u.ID {
		t.Errorf("got session %q for user %q, want %q for %q", found.ID, found.UserID, created.ID, u.ID)
	}
}

func TestSessionLookupRejectsUnknownRevokedAndExpired(t *testing.T) {
	s := openTemp(t)
	ctx := context.Background()
	u := enrolledUser(t, s, "person@example.com")

	t.Run("unknown", func(t *testing.T) {
		if _, err := s.SessionByAccessToken(ctx, "nope"); !errors.Is(err, ErrNotFound) {
			t.Errorf("error = %v, want ErrNotFound", err)
		}
	})

	t.Run("revoked", func(t *testing.T) {
		sess, access, _, err := s.CreateSession(ctx, u.ID, "cli")
		if err != nil {
			t.Fatal(err)
		}
		if err := s.RevokeSession(ctx, sess.ID); err != nil {
			t.Fatal(err)
		}
		// "Sign out this device" must take effect immediately, not at expiry.
		if _, err := s.SessionByAccessToken(ctx, access); !errors.Is(err, ErrNotFound) {
			t.Errorf("revoked session error = %v, want ErrNotFound", err)
		}
	})

	t.Run("expired", func(t *testing.T) {
		sess, access, _, err := s.CreateSession(ctx, u.ID, "cli")
		if err != nil {
			t.Fatal(err)
		}
		past := time.Now().UTC().Add(-time.Minute).Format(time.RFC3339)
		if _, err := s.DB().Exec(`UPDATE sessions SET expires_at = ? WHERE id = ?`, past, sess.ID); err != nil {
			t.Fatal(err)
		}
		if _, err := s.SessionByAccessToken(ctx, access); !errors.Is(err, ErrNotFound) {
			t.Errorf("expired session error = %v, want ErrNotFound", err)
		}
	})
}

func TestSessionByAccessTokenEnforcesTheAbsoluteLifetime(t *testing.T) {
	s := openTemp(t)
	ctx := context.Background()
	u := enrolledUser(t, s, "person@example.com")

	sess, access, _, err := s.CreateSession(ctx, u.ID, "cli")
	if err != nil {
		t.Fatal(err)
	}

	// created_at past the 30-day bound, expires_at deliberately left in the
	// FUTURE. That combination is the whole point: TouchSession pushes
	// expires_at to now+30min on every authenticated request, so a client that
	// makes any request more often than that never reaches its sliding expiry
	// and, without an absolute bound, stays signed in forever. A stolen access
	// token kept warm by a script polling every five minutes would never expire.
	// Backdating expires_at too would only re-test the sliding check.
	oldCreated := time.Now().UTC().Add(-RefreshTokenLifetime - time.Hour).Format(time.RFC3339)
	future := time.Now().UTC().Add(AccessTokenLifetime).Format(time.RFC3339)
	if _, err := s.DB().Exec(
		`UPDATE sessions SET created_at = ?, expires_at = ? WHERE id = ?`,
		oldCreated, future, sess.ID); err != nil {
		t.Fatal(err)
	}

	if _, err := s.SessionByAccessToken(ctx, access); !errors.Is(err, ErrNotFound) {
		t.Errorf("error = %v, want ErrNotFound: a session older than RefreshTokenLifetime is live despite a future expires_at", err)
	}
}

func TestRotateSessionInvalidatesTheOldTokens(t *testing.T) {
	s := openTemp(t)
	ctx := context.Background()
	u := enrolledUser(t, s, "person@example.com")

	sess, oldAccess, oldRefresh, err := s.CreateSession(ctx, u.ID, "cli")
	if err != nil {
		t.Fatal(err)
	}

	rotated, newAccess, newRefresh, err := s.RotateSession(ctx, oldRefresh)
	if err != nil {
		t.Fatalf("RotateSession: %v", err)
	}
	if rotated.ID != sess.ID {
		t.Errorf("rotation created a new session %q, want the same %q", rotated.ID, sess.ID)
	}
	if newAccess == oldAccess || newRefresh == oldRefresh {
		t.Error("rotation reissued the same token")
	}

	// A refresh token is single-use. A leaked one must not stay usable after
	// the legitimate client has rotated.
	if _, _, _, err := s.RotateSession(ctx, oldRefresh); !errors.Is(err, ErrNotFound) {
		t.Errorf("reused refresh token error = %v, want ErrNotFound", err)
	}
	if _, err := s.SessionByAccessToken(ctx, oldAccess); !errors.Is(err, ErrNotFound) {
		t.Error("the old access token still works after rotation")
	}
	if _, err := s.SessionByAccessToken(ctx, newAccess); err != nil {
		t.Errorf("the new access token does not work: %v", err)
	}
}

func TestScanSessionHandlesAPopulatedRevokedAt(t *testing.T) {
	s := openTemp(t)
	ctx := context.Background()
	u := enrolledUser(t, s, "person@example.com")

	sess, _, _, err := s.CreateSession(ctx, u.ID, "cli")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.RevokeSession(ctx, sess.ID); err != nil {
		t.Fatal(err)
	}

	// Both production lookups filter revoked_at IS NULL, so this is the only
	// way to put a populated revoked_at through scanSession — and therefore the
	// only test that can catch the column failing to scan at all.
	revoked, err := scanSession(s.DB().QueryRowContext(ctx,
		`SELECT `+sessionColumns+` FROM sessions WHERE id = ?`, sess.ID))
	if err != nil {
		t.Fatalf("scanning a revoked session failed: %v", err)
	}
	if !revoked.RevokedAt.Valid {
		t.Error("RevokedAt is not Valid on a revoked session")
	}
	if revoked.RevokedAt.Time.IsZero() {
		t.Error("RevokedAt.Time is zero on a revoked session")
	}
}

func TestTouchSessionExtendsExpiry(t *testing.T) {
	s := openTemp(t)
	ctx := context.Background()
	u := enrolledUser(t, s, "person@example.com")

	sess, _, _, err := s.CreateSession(ctx, u.ID, "cli")
	if err != nil {
		t.Fatal(err)
	}

	// Wind the clock back so the sliding extension is observable.
	near := time.Now().UTC().Add(time.Minute).Format(time.RFC3339)
	if _, err := s.DB().Exec(`UPDATE sessions SET expires_at = ? WHERE id = ?`, near, sess.ID); err != nil {
		t.Fatal(err)
	}
	if err := s.TouchSession(ctx, sess.ID); err != nil {
		t.Fatalf("TouchSession: %v", err)
	}

	var after string
	if err := s.DB().QueryRow(`SELECT expires_at FROM sessions WHERE id = ?`, sess.ID).Scan(&after); err != nil {
		t.Fatal(err)
	}
	extended, err := time.Parse(time.RFC3339, after)
	if err != nil {
		t.Fatal(err)
	}
	if !extended.After(time.Now().UTC().Add(20 * time.Minute)) {
		t.Errorf("expires_at = %s, want it pushed out by the full access lifetime", after)
	}
}
