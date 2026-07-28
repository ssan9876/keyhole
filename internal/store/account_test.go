package store

import (
	"context"
	"errors"
	"testing"

	"github.com/ssan9876/keyhole/internal/auth"
)

func TestRotatePasswordReplacesTheCredentialAndTheWrappedKey(t *testing.T) {
	st := openTemp(t)
	ctx := context.Background()
	userID := enrolledUserID(t, st, "person@example.com")

	if err := st.RotatePassword(ctx, userID, PasswordRotation{
		KDFSalt:          "bmV3LXNhbHQtMTZieXRlcw==",
		KDFParams:        auth.DefaultKDFParamsJSON,
		AuthHash:         "argon2id$stored$hash",
		ProtectedUserKey: "new-protected-user-key",
	}, ""); err != nil {
		t.Fatalf("RotatePassword: %v", err)
	}

	user, err := st.UserByID(ctx, userID)
	if err != nil {
		t.Fatalf("UserByID: %v", err)
	}
	if user.ProtectedUserKey.String != "new-protected-user-key" {
		t.Errorf("ProtectedUserKey = %q", user.ProtectedUserKey.String)
	}
	if user.AuthHash.String != "argon2id$stored$hash" {
		t.Errorf("AuthHash = %q", user.AuthHash.String)
	}
	// The recovery blob is wrapped by the recovery code, not the master
	// password, so a password change must leave it entirely alone. Clearing it
	// here would silently destroy the user's last way back in.
	if !user.RecoveryProtectedUserKey.Valid || user.RecoveryProtectedUserKey.String == "" {
		t.Error("rotating the password destroyed the recovery blob")
	}
}

func TestRotatePasswordRevokesEveryOtherSession(t *testing.T) {
	st := openTemp(t)
	ctx := context.Background()
	userID := enrolledUserID(t, st, "person@example.com")

	keep, keepToken, _, err := st.CreateSession(ctx, userID, "this device")
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	_, otherToken, _, err := st.CreateSession(ctx, userID, "other device")
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}

	if err := st.RotatePassword(ctx, userID, PasswordRotation{
		KDFSalt:   "s",
		KDFParams: auth.DefaultKDFParamsJSON,
		AuthHash:  "h", ProtectedUserKey: "k",
	}, keep.ID); err != nil {
		t.Fatalf("RotatePassword: %v", err)
	}

	// Changing a master password is what a user does after suspecting a
	// compromise. Leaving other devices signed in makes the action mean far
	// less than the user believes it does.
	if _, err := st.SessionByAccessToken(ctx, otherToken); !errors.Is(err, ErrNotFound) {
		t.Errorf("the other session survived: %v", err)
	}
	// And the device that performed the change stays signed in, or the user is
	// logged out by their own successful action.
	if _, err := st.SessionByAccessToken(ctx, keepToken); err != nil {
		t.Errorf("the current session was revoked too: %v", err)
	}
}

func TestRotateRecoveryReplacesOnlyTheRecoveryBlob(t *testing.T) {
	st := openTemp(t)
	ctx := context.Background()
	userID := enrolledUserID(t, st, "person@example.com")

	before, err := st.UserByID(ctx, userID)
	if err != nil {
		t.Fatalf("UserByID: %v", err)
	}

	if err := st.RotateRecovery(ctx, userID, RecoveryRotation{
		RecoverySalt:             "new-recovery-salt",
		RecoveryKDFParams:        `{"algorithm":"argon2id","memoryKiB":65536,"iterations":3,"parallelism":4}`,
		RecoveryProtectedUserKey: "new-recovery-blob",
		RecoveryAuthHash:         "argon2id$new$authhash",
	}); err != nil {
		t.Fatalf("RotateRecovery: %v", err)
	}

	after, err := st.UserByID(ctx, userID)
	if err != nil {
		t.Fatalf("UserByID: %v", err)
	}
	if after.RecoveryProtectedUserKey.String != "new-recovery-blob" {
		t.Errorf("RecoveryProtectedUserKey = %q", after.RecoveryProtectedUserKey.String)
	}
	// Issuing a new recovery code must not disturb the master-password path.
	// A user who regenerates a code and then cannot sign in has lost both.
	if after.AuthHash.String != before.AuthHash.String {
		t.Error("regenerating a recovery code changed the login credential")
	}
	if after.ProtectedUserKey.String != before.ProtectedUserKey.String {
		t.Error("regenerating a recovery code changed the password-wrapped key")
	}
}

// TestRotateRecoveryStoresTheAuthHashAlongsideTheBlob is the point of the
// column: a blob and the proof-of-possession value that gates handing it back
// have to arrive and land together, or the row records a code the server still
// cannot check.
func TestRotateRecoveryStoresTheAuthHashAlongsideTheBlob(t *testing.T) {
	st := openTemp(t)
	ctx := context.Background()
	userID := enrolledUserID(t, st, "person@example.com")

	if err := st.RotateRecovery(ctx, userID, RecoveryRotation{
		RecoverySalt:             "rotated-salt",
		RecoveryKDFParams:        `{"algorithm":"argon2id","memoryKiB":65536,"iterations":3,"parallelism":4}`,
		RecoveryProtectedUserKey: "rotated-blob",
		RecoveryAuthHash:         "argon2id$rotated$authhash",
	}); err != nil {
		t.Fatalf("RotateRecovery: %v", err)
	}

	after, err := st.UserByID(ctx, userID)
	if err != nil {
		t.Fatalf("UserByID: %v", err)
	}
	if !after.RecoveryAuthHash.Valid {
		t.Fatal("recovery_auth_hash is NULL after a rotation; the new code can never be redeemed")
	}
	if after.RecoveryAuthHash.String != "argon2id$rotated$authhash" {
		t.Errorf("RecoveryAuthHash = %q, want the value the caller passed",
			after.RecoveryAuthHash.String)
	}
	// The pair has to move together. A rotation that wrote the new blob but kept
	// the previous auth hash would accept the old code and then hand back a blob
	// it cannot open.
	if after.RecoveryProtectedUserKey.String != "rotated-blob" {
		t.Errorf("RecoveryProtectedUserKey = %q, want the rotated blob",
			after.RecoveryProtectedUserKey.String)
	}
}

// TestRotateRecoveryRejectsAPayloadCarryingNoAuthHash is the guard that keeps
// an unredeemable blob out of the database. Every other recovery field is
// present here, so nothing but the missing auth hash can be what rejects it.
//
// Without this, a client could store a blob nothing is ever able to redeem —
// the exact state the recovery-redemption plan exists to eliminate — and the
// user would not find out until the code was their last resort.
func TestRotateRecoveryRejectsAPayloadCarryingNoAuthHash(t *testing.T) {
	st := openTemp(t)
	ctx := context.Background()
	userID := enrolledUserID(t, st, "person@example.com")

	err := st.RotateRecovery(ctx, userID, RecoveryRotation{
		RecoverySalt:             "salt",
		RecoveryKDFParams:        `{"algorithm":"argon2id","memoryKiB":65536,"iterations":3,"parallelism":4}`,
		RecoveryProtectedUserKey: "blob",
	})
	var validation *ValidationError
	if !errors.As(err, &validation) {
		t.Fatalf("err = %v, want a *ValidationError", err)
	}
	if validation.Field != "recoveryAuthHash" {
		t.Errorf("Field = %q, want %q", validation.Field, "recoveryAuthHash")
	}

	// And nothing landed: a rejected rotation must leave the previous, working
	// recovery record exactly as it was.
	after, err := st.UserByID(ctx, userID)
	if err != nil {
		t.Fatalf("UserByID: %v", err)
	}
	if after.RecoveryProtectedUserKey.String == "blob" {
		t.Error("the rejected payload's blob was written anyway")
	}
}

func TestRotateRecoveryRejectsAnIncompletePayload(t *testing.T) {
	st := openTemp(t)
	ctx := context.Background()
	userID := enrolledUserID(t, st, "person@example.com")

	// A half-written recovery record is worse than none: the UI would show the
	// user a code that cannot open anything.
	err := st.RotateRecovery(ctx, userID, RecoveryRotation{
		RecoverySalt: "salt", RecoveryProtectedUserKey: "blob",
	})
	var validation *ValidationError
	if !errors.As(err, &validation) {
		t.Fatalf("err = %v, want a *ValidationError", err)
	}
}

// TestRotateRecoveryRejectsNonDefaultRecoveryKDFParams pins the column every
// recovery blob records its parameters in.
//
// POST /api/auth/recover/prelogin returns recovery_kdf_params to an
// unauthenticated caller and answers an unknown address with
// auth.DefaultKDFParamsJSON. One account holding anything else there is one
// address an attacker can confirm exists, so this path — shared by the settings
// rotation and by a completed recovery — pins it byte for byte.
func TestRotateRecoveryRejectsNonDefaultRecoveryKDFParams(t *testing.T) {
	st := openTemp(t)
	ctx := context.Background()
	userID := enrolledUserID(t, st, "person@example.com")

	err := st.RotateRecovery(ctx, userID, RecoveryRotation{
		RecoverySalt: "new-recovery-salt",
		// Semantically identical to the default, byte-different. Byte equality
		// is the standard because the decoy emits one exact string.
		RecoveryKDFParams:        `{"algorithm":"argon2id","iterations":3,"memoryKiB":65536,"parallelism":4}`,
		RecoveryProtectedUserKey: "divergent-blob",
		RecoveryAuthHash:         "argon2id$new$authhash",
	})
	var validation *ValidationError
	if !errors.As(err, &validation) {
		t.Fatalf("err = %v, want a *ValidationError", err)
	}
	if validation.Field != "recoveryKdfParams" {
		t.Errorf("Field = %q, want %q", validation.Field, "recoveryKdfParams")
	}

	after, err := st.UserByID(ctx, userID)
	if err != nil {
		t.Fatalf("UserByID: %v", err)
	}
	if after.RecoveryProtectedUserKey.String == "divergent-blob" {
		t.Error("the rejected rotation wrote its blob anyway")
	}
}

func TestSessionsForUserListsLiveSessionsOnly(t *testing.T) {
	st := openTemp(t)
	ctx := context.Background()
	userID := enrolledUserID(t, st, "person@example.com")
	otherID := enrolledUserID(t, st, "other@example.com")

	if _, _, _, err := st.CreateSession(ctx, userID, "laptop"); err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	revoked, _, _, err := st.CreateSession(ctx, userID, "old phone")
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	if err := st.RevokeSession(ctx, revoked.ID); err != nil {
		t.Fatalf("RevokeSession: %v", err)
	}
	if _, _, _, err := st.CreateSession(ctx, otherID, "someone else"); err != nil {
		t.Fatalf("CreateSession: %v", err)
	}

	sessions, err := st.SessionsForUser(ctx, userID)
	if err != nil {
		t.Fatalf("SessionsForUser: %v", err)
	}
	if len(sessions) != 1 {
		t.Fatalf("got %d sessions, want 1 live one", len(sessions))
	}
	if sessions[0].DeviceLabel != "laptop" {
		t.Errorf("DeviceLabel = %q", sessions[0].DeviceLabel)
	}
}

func TestRevokeSessionForUserRefusesAnotherUsersSession(t *testing.T) {
	st := openTemp(t)
	ctx := context.Background()
	mine := enrolledUserID(t, st, "mine@example.com")
	theirs := enrolledUserID(t, st, "theirs@example.com")

	session, token, _, err := st.CreateSession(ctx, theirs, "their laptop")
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}

	// Session ids are opaque, but "sign out my other device" must not become
	// "sign out anyone's device" for a caller who guesses or observes one.
	if err := st.RevokeSessionForUser(ctx, session.ID, mine); !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
	if _, err := st.SessionByAccessToken(ctx, token); err != nil {
		t.Errorf("another user's session was revoked: %v", err)
	}
}
