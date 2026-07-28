package store

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ssan9876/keyhole/internal/auth"
)

// recoveryPasswordRotation and recoveryRecoveryRotation are the two halves of a
// completed recovery: a brand new master-password credential and a brand new
// recovery blob, exactly as the client uploads them.
func recoveryPasswordRotation() PasswordRotation {
	return PasswordRotation{
		KDFSalt:          "bmV3c2FsdG5ld3NhbHQxNg==",
		KDFParams:        auth.DefaultKDFParamsJSON,
		AuthHash:         "argon2id$AAAAAAAAAAAAAAAAAAAAAA==$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
		ProtectedUserKey: `{"v":1,"alg":"A256GCM","n":"bm9uY2U=","ct":"bmV3d3JhcA=="}`,
	}
}

func recoveryRecoveryRotation() RecoveryRotation {
	return RecoveryRotation{
		RecoverySalt:             "bmV3cmVjb3ZlcnlzYWx0MQ==",
		RecoveryKDFParams:        auth.DefaultKDFParamsJSON,
		RecoveryProtectedUserKey: `{"v":1,"alg":"A256GCM","n":"bm9uY2U=","ct":"bmV3cmVjb3Zlcnk="}`,
		RecoveryAuthHash:         "argon2id$BBBBBBBBBBBBBBBBBBBBBB==$BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=",
	}
}

// activeUser is a user in the state a completed recovery requires: enrolled,
// active, and holding key material to overwrite.
func activeUser(t *testing.T, s *Store, email string) User {
	t.Helper()
	ctx := context.Background()

	user := makeUser(t, s, email)
	_, token, err := s.CreateInvite(ctx, user.ID, time.Hour)
	if err != nil {
		t.Fatalf("CreateInvite: %v", err)
	}
	enrolled, err := s.CompleteEnrollment(ctx, token, sampleEnrollment())
	if err != nil {
		t.Fatalf("CompleteEnrollment: %v", err)
	}
	return enrolled
}

func TestCreateRecoveryTokenReturnsATokenStoredOnlyAsAHash(t *testing.T) {
	s := openTemp(t)
	ctx := context.Background()
	user := activeUser(t, s, "person@example.com")

	created, token, err := s.CreateRecoveryToken(ctx, user.ID, RecoveryTokenTTL)
	if err != nil {
		t.Fatalf("CreateRecoveryToken: %v", err)
	}
	if token == "" {
		t.Fatal("CreateRecoveryToken returned an empty token")
	}
	if created.UserID != user.ID {
		t.Errorf("UserID = %q, want %q", created.UserID, user.ID)
	}

	// The token authorizes rewriting an account's master password. A database
	// dump that handed it over in the clear would be a spare key to every
	// recovery in flight.
	var stored string
	if err := s.DB().QueryRowContext(ctx,
		`SELECT token_hash FROM recovery_tokens WHERE id = ?`, created.ID).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if stored == token {
		t.Error("the recovery token was stored in the clear")
	}
	if stored != HashToken(token) {
		t.Error("stored value is not the SHA-256 of the token")
	}
}

func TestRecoveryTokenByTokenRejectsAnUnknownOrExpiredToken(t *testing.T) {
	s := openTemp(t)
	ctx := context.Background()
	user := activeUser(t, s, "person@example.com")

	if _, err := s.RecoveryTokenByToken(ctx, "not-a-real-token"); !errors.Is(err, ErrNotFound) {
		t.Errorf("unknown token error = %v, want ErrNotFound", err)
	}

	_, expired, err := s.CreateRecoveryToken(ctx, user.ID, -time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	// Ten minutes is the whole point of the TTL: one left behind in a closed
	// laptop must not still be a way in.
	if _, err := s.RecoveryTokenByToken(ctx, expired); !errors.Is(err, ErrNotFound) {
		t.Errorf("expired token error = %v, want ErrNotFound", err)
	}
}

// TestCompleteRecoveryConsumesItsTokenAndRetiresTheAccountsOthers covers both
// halves of "single use". The token just spent is dead, and so is any other
// token minted for that account in the same window — a second redemption
// abandoned half way through must not leave a live spare behind.
func TestCompleteRecoveryConsumesItsTokenAndRetiresTheAccountsOthers(t *testing.T) {
	s := openTemp(t)
	ctx := context.Background()
	user := activeUser(t, s, "person@example.com")

	_, spent, err := s.CreateRecoveryToken(ctx, user.ID, RecoveryTokenTTL)
	if err != nil {
		t.Fatal(err)
	}
	_, spare, err := s.CreateRecoveryToken(ctx, user.ID, RecoveryTokenTTL)
	if err != nil {
		t.Fatal(err)
	}

	if err := s.CompleteRecovery(ctx, spent, recoveryPasswordRotation(), recoveryRecoveryRotation()); err != nil {
		t.Fatalf("CompleteRecovery: %v", err)
	}

	if _, err := s.RecoveryTokenByToken(ctx, spent); !errors.Is(err, ErrNotFound) {
		t.Errorf("the spent token is still live: err = %v, want ErrNotFound", err)
	}
	if _, err := s.RecoveryTokenByToken(ctx, spare); !errors.Is(err, ErrNotFound) {
		t.Errorf("a second token for the same account survived the recovery: err = %v, want ErrNotFound", err)
	}
	if err := s.CompleteRecovery(ctx, spent, recoveryPasswordRotation(), recoveryRecoveryRotation()); !errors.Is(err, ErrNotFound) {
		t.Errorf("replaying the spent token = %v, want ErrNotFound", err)
	}
}

// TestCompleteRecoveryWritesBothCredentialsAndRecordsIt is the store-level
// half: the columns actually change, and the action is auditable afterwards.
func TestCompleteRecoveryWritesBothCredentialsAndRecordsIt(t *testing.T) {
	s := openTemp(t)
	ctx := context.Background()
	user := activeUser(t, s, "person@example.com")

	_, token, err := s.CreateRecoveryToken(ctx, user.ID, RecoveryTokenTTL)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.CompleteRecovery(ctx, token, recoveryPasswordRotation(), recoveryRecoveryRotation()); err != nil {
		t.Fatalf("CompleteRecovery: %v", err)
	}

	after, err := s.UserByID(ctx, user.ID)
	if err != nil {
		t.Fatal(err)
	}
	password, recovery := recoveryPasswordRotation(), recoveryRecoveryRotation()
	for _, field := range []struct{ name, got, want string }{
		{"kdf_salt", after.KDFSalt.String, password.KDFSalt},
		{"auth_hash", after.AuthHash.String, password.AuthHash},
		{"protected_user_key", after.ProtectedUserKey.String, password.ProtectedUserKey},
		{"recovery_salt", after.RecoverySalt.String, recovery.RecoverySalt},
		{"recovery_protected_user_key", after.RecoveryProtectedUserKey.String, recovery.RecoveryProtectedUserKey},
		// The old code is invalidated by replacing what proves possession of it,
		// not by any separate revocation step.
		{"recovery_auth_hash", after.RecoveryAuthHash.String, recovery.RecoveryAuthHash},
	} {
		if field.got != field.want {
			t.Errorf("%s = %q, want %q", field.name, field.got, field.want)
		}
	}

	entries, err := s.AuditPage(ctx, 50, "")
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, entry := range entries {
		if entry.Action == "account.recovery.redeem" && entry.ActorUserID.String == user.ID {
			found = true
		}
	}
	if !found {
		t.Errorf("no account.recovery.redeem entry in the audit log after a completed recovery: %+v", entries)
	}
}

// TestCompleteRecoveryRefusesToWriteAnythingForAnIncompletePayload keeps a
// half-recovered account out of the database: a password written without the
// matching recovery blob would leave the user with a working sign-in and a
// recovery code that opens nothing.
func TestCompleteRecoveryRefusesToWriteAnythingForAnIncompletePayload(t *testing.T) {
	s := openTemp(t)
	ctx := context.Background()
	user := activeUser(t, s, "person@example.com")

	_, token, err := s.CreateRecoveryToken(ctx, user.ID, RecoveryTokenTTL)
	if err != nil {
		t.Fatal(err)
	}
	incomplete := recoveryRecoveryRotation()
	incomplete.RecoveryAuthHash = ""

	var validation *ValidationError
	if err := s.CompleteRecovery(ctx, token, recoveryPasswordRotation(), incomplete); !errors.As(err, &validation) {
		t.Fatalf("error = %v, want a *ValidationError", err)
	}

	after, err := s.UserByID(ctx, user.ID)
	if err != nil {
		t.Fatal(err)
	}
	if after.KDFSalt.String == recoveryPasswordRotation().KDFSalt {
		t.Error("the master password was rotated even though the recovery half was refused")
	}
	if _, err := s.RecoveryTokenByToken(ctx, token); err != nil {
		t.Errorf("the token was spent on a refused recovery: %v", err)
	}
}
