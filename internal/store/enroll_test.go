package store

import (
	"context"
	"errors"
	"testing"
	"time"
)

func sampleEnrollment() EnrollmentInput {
	return EnrollmentInput{
		KDFSalt:                  "c2FsdHNhbHRzYWx0c2E=",
		KDFParams:                `{"algorithm":"argon2id","memoryKiB":65536,"iterations":3,"parallelism":4}`,
		AuthHash:                 "argon2id$c2FsdA==$ZGlnZXN0",
		ProtectedUserKey:         `{"v":1,"alg":"A256GCM","n":"bm9uY2U=","ct":"Y2lwaGVy"}`,
		PublicKey:                "cHVibGljS2V5MzJieXRlc2xvbmdoZXJl",
		EncryptedPrivateKey:      `{"v":1,"alg":"A256GCM","n":"bm9uY2U=","ct":"cHJpdg=="}`,
		RecoverySalt:             "cmVjb3ZlcnlzYWx0MTY=",
		RecoveryProtectedUserKey: `{"v":1,"alg":"A256GCM","n":"bm9uY2U=","ct":"cmVjb3Zlcnk="}`,
		RecoveryKDFParams:        `{"algorithm":"argon2id","memoryKiB":65536,"iterations":3,"parallelism":4}`,
	}
}

func TestCompleteEnrollmentActivatesTheAccount(t *testing.T) {
	s := openTemp(t)
	ctx := context.Background()

	user := makeUser(t, s, "person@example.com")
	_, token, err := s.CreateInvite(ctx, user.ID, time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	enrolled, err := s.CompleteEnrollment(ctx, token, sampleEnrollment())
	if err != nil {
		t.Fatalf("CompleteEnrollment: %v", err)
	}

	if enrolled.Status != "active" {
		t.Errorf("Status = %q, want %q", enrolled.Status, "active")
	}
	if enrolled.ID != user.ID {
		t.Errorf("enrolled a different user: %q, want %q", enrolled.ID, user.ID)
	}
	in := sampleEnrollment()
	if enrolled.ProtectedUserKey.String != in.ProtectedUserKey {
		t.Error("protected_user_key was not stored verbatim")
	}
	// recovery_kdf_params is its own column precisely so a later params change
	// cannot orphan the recovery blob.
	if enrolled.RecoveryKDFParams.String != in.RecoveryKDFParams {
		t.Error("recovery_kdf_params was not stored")
	}
}

func TestCompleteEnrollmentConsumesTheInvite(t *testing.T) {
	s := openTemp(t)
	ctx := context.Background()

	user := makeUser(t, s, "person@example.com")
	_, token, err := s.CreateInvite(ctx, user.ID, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.CompleteEnrollment(ctx, token, sampleEnrollment()); err != nil {
		t.Fatal(err)
	}

	// A replayed link must not overwrite an account that is already set up —
	// otherwise anyone who saw the invite URL could seize the vault later.
	if _, err := s.CompleteEnrollment(ctx, token, sampleEnrollment()); !errors.Is(err, ErrNotFound) {
		t.Errorf("second enrollment error = %v, want ErrNotFound", err)
	}
}

func TestCompleteEnrollmentRejectsUnknownToken(t *testing.T) {
	s := openTemp(t)
	if _, err := s.CompleteEnrollment(context.Background(), "no-such-token", sampleEnrollment()); !errors.Is(err, ErrNotFound) {
		t.Errorf("error = %v, want ErrNotFound", err)
	}
}

func TestCompleteEnrollmentRejectsIncompleteInput(t *testing.T) {
	s := openTemp(t)
	ctx := context.Background()

	user := makeUser(t, s, "person@example.com")

	// Each field is separately required. A client that forgets one — most
	// consequentially the recovery blob — must be told, not silently accepted
	// into a state where recovery is impossible.
	for _, field := range []string{
		"KDFSalt", "KDFParams", "AuthHash", "ProtectedUserKey", "PublicKey",
		"EncryptedPrivateKey", "RecoverySalt", "RecoveryProtectedUserKey", "RecoveryKDFParams",
	} {
		t.Run(field, func(t *testing.T) {
			_, token, err := s.CreateInvite(ctx, user.ID, time.Hour)
			if err != nil {
				t.Fatal(err)
			}
			in := sampleEnrollment()
			switch field {
			case "KDFSalt":
				in.KDFSalt = ""
			case "KDFParams":
				in.KDFParams = ""
			case "AuthHash":
				in.AuthHash = ""
			case "ProtectedUserKey":
				in.ProtectedUserKey = ""
			case "PublicKey":
				in.PublicKey = ""
			case "EncryptedPrivateKey":
				in.EncryptedPrivateKey = ""
			case "RecoverySalt":
				in.RecoverySalt = ""
			case "RecoveryProtectedUserKey":
				in.RecoveryProtectedUserKey = ""
			case "RecoveryKDFParams":
				in.RecoveryKDFParams = ""
			}
			if _, err := s.CompleteEnrollment(ctx, token, in); err == nil {
				t.Errorf("enrollment succeeded with %s empty", field)
			}
		})
	}
}

func TestCompleteEnrollmentLeavesNothingBehindOnFailure(t *testing.T) {
	s := openTemp(t)
	ctx := context.Background()

	user := makeUser(t, s, "person@example.com")
	_, token, err := s.CreateInvite(ctx, user.ID, time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	bad := sampleEnrollment()
	bad.PublicKey = ""
	if _, err := s.CompleteEnrollment(ctx, token, bad); err == nil {
		t.Fatal("expected the enrollment to fail")
	}

	// The invite must still work: a client that sent a bad body should be able
	// to retry rather than be locked out of its own setup link.
	if _, err := s.InviteByToken(ctx, token); err != nil {
		t.Errorf("invite was consumed by a failed enrollment: %v", err)
	}
	after, err := s.UserByID(ctx, user.ID)
	if err != nil {
		t.Fatal(err)
	}
	if after.Status != "pending" {
		t.Errorf("Status = %q after a failed enrollment, want %q", after.Status, "pending")
	}
}
