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
