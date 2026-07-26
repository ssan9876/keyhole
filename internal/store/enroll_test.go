package store

import (
	"context"
	"errors"
	"sync"
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

func TestCompleteEnrollmentIsSafeUnderAConcurrentRace(t *testing.T) {
	s := openTemp(t)
	ctx := context.Background()

	user := makeUser(t, s, "person@example.com")
	_, token, err := s.CreateInvite(ctx, user.ID, time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	// Both goroutines pass InviteByToken before either commits, so this is the
	// only test that reaches the mid-transaction used_at IS NULL guard — the
	// actual protection against a replayed setup link.
	const racers = 2
	start := make(chan struct{})
	results := make(chan error, racers)

	var wg sync.WaitGroup
	for i := 0; i < racers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_, err := s.CompleteEnrollment(ctx, token, sampleEnrollment())
			results <- err
		}()
	}
	close(start)
	wg.Wait()
	close(results)

	var succeeded, rejected int
	for err := range results {
		switch {
		case err == nil:
			succeeded++
		case errors.Is(err, ErrNotFound):
			rejected++
		default:
			t.Errorf("unexpected error from a racing enrollment: %v", err)
		}
	}
	if succeeded != 1 {
		t.Errorf("%d enrollments succeeded, want exactly 1", succeeded)
	}
	if rejected != racers-1 {
		t.Errorf("%d enrollments were rejected, want %d", rejected, racers-1)
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

// TestCompleteEnrollmentRejectsInvalidInputBeforeTouchingTheDatabase proves
// that validate() runs before BeginTx: a malformed payload never opens a
// transaction, so it cannot touch the invite or the user row. It does not
// exercise the transaction's rollback path — validate() rejects the input
// before any write is attempted, let alone rolled back.
func TestCompleteEnrollmentRejectsInvalidInputBeforeTouchingTheDatabase(t *testing.T) {
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

// TestCompleteEnrollmentRollsBackAMidTransactionFailure forces the second
// UPDATE inside the transaction — the one that activates the user — to
// affect zero rows after the first UPDATE (consuming the invite) has already
// succeeded within the same transaction. That is the one place a real
// rollback matters: an invite that legitimately validates, and a user row
// that turns out not to be enrollable anymore.
//
// To provoke it without reaching into unexported internals, two invites are
// issued for the same user. The first enrollment succeeds and activates the
// account. The second invite is still fresh and unused, so InviteByToken and
// the invites UPDATE both succeed for it — but the users UPDATE's
// `WHERE status = 'pending'` matches nothing, because the account is already
// active. That is a genuine mid-transaction zero-rows failure, not a
// pre-transaction rejection.
func TestCompleteEnrollmentRollsBackAMidTransactionFailure(t *testing.T) {
	s := openTemp(t)
	ctx := context.Background()

	user := makeUser(t, s, "person@example.com")
	_, firstToken, err := s.CreateInvite(ctx, user.ID, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	_, secondToken, err := s.CreateInvite(ctx, user.ID, time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	first := sampleEnrollment()
	if _, err := s.CompleteEnrollment(ctx, firstToken, first); err != nil {
		t.Fatalf("first CompleteEnrollment: %v", err)
	}

	second := sampleEnrollment()
	second.ProtectedUserKey = `{"v":1,"alg":"A256GCM","n":"c2Vjb25k","ct":"c2Vjb25k"}`
	if _, err := s.CompleteEnrollment(ctx, secondToken, second); !errors.Is(err, ErrNotFound) {
		t.Errorf("second enrollment error = %v, want ErrNotFound", err)
	}

	// The account's key material must still be exactly what the first,
	// successful enrollment wrote — the failed second attempt's payload must
	// never have landed, and the rollback must not have touched it either.
	after, err := s.UserByID(ctx, user.ID)
	if err != nil {
		t.Fatal(err)
	}
	if after.Status != "active" {
		t.Errorf("Status = %q, want %q", after.Status, "active")
	}
	if after.ProtectedUserKey.String != first.ProtectedUserKey {
		t.Error("protected_user_key was overwritten by the failed second enrollment")
	}
}
