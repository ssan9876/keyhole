package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ssan9876/keyhole/internal/auth"
	"github.com/ssan9876/keyhole/internal/store"
)

func enrollBody() map[string]string {
	return map[string]string{
		// The crypto package fixes real KDF salts at 16 bytes; this fixture
		// matches that length even though this package never validates it.
		"kdfSalt":                  "c2FsdHNhbHRzYWx0c2FsdA==",
		"params":                   `{"algorithm":"argon2id","memoryKiB":65536,"iterations":3,"parallelism":4}`,
		"authHash":                 "YXV0aC1oYXNoLTMyLWJ5dGVzLWJhc2U2NA==",
		"protectedUserKey":         `{"v":1,"alg":"A256GCM","n":"bm9uY2U=","ct":"Y2lwaGVy"}`,
		"publicKey":                "cHVibGljS2V5MzJieXRlc2xvbmdoZXJl",
		"encryptedPrivateKey":      `{"v":1,"alg":"A256GCM","n":"bm9uY2U=","ct":"cHJpdg=="}`,
		"recoverySalt":             "cmVjb3ZlcnlzYWx0MTY=",
		"recoveryProtectedUserKey": `{"v":1,"alg":"A256GCM","n":"bm9uY2U=","ct":"cmVjb3Zlcnk="}`,
		"recoveryKdfParams":        `{"algorithm":"argon2id","memoryKiB":65536,"iterations":3,"parallelism":4}`,
	}
}

// seedInvite creates a pending user and returns its one-time token.
func seedInvite(t *testing.T, srv *Server, email string) (store.User, string) {
	t.Helper()
	ctx := context.Background()

	user, err := srv.store.CreatePendingUser(ctx, email, "Test Person", "user")
	if err != nil {
		t.Fatalf("CreatePendingUser: %v", err)
	}
	_, token, err := srv.store.CreateInvite(ctx, user.ID, time.Hour)
	if err != nil {
		t.Fatalf("CreateInvite: %v", err)
	}
	return user, token
}

func postJSON(t *testing.T, srv *Server, path string, payload any) *httptest.ResponseRecorder {
	t.Helper()
	// httptest.NewRequest's own default. Named here because several tests care
	// which source address an attempt is attributed to.
	return postJSONFrom(t, srv, "192.0.2.1:1234", path, payload)
}

// postJSONFrom is postJSON with an explicit peer address, for tests that need
// the per-IP and per-account rate limits to be told apart.
func postJSONFrom(t *testing.T, srv *Server, remoteAddr, path string, payload any) *httptest.ResponseRecorder {
	t.Helper()
	encoded, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(string(encoded)))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = remoteAddr
	srv.Handler().ServeHTTP(rec, req)
	return rec
}

func TestEnrollActivatesAndHashesTheAuthHash(t *testing.T) {
	srv := newTestServer(t)
	user, token := seedInvite(t, srv, "person@example.com")

	rec := postJSON(t, srv, "/api/enroll/"+token, enrollBody())
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body %s", rec.Code, http.StatusOK, rec.Body.String())
	}

	stored, err := srv.store.UserByID(context.Background(), user.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.Status != "active" {
		t.Errorf("Status = %q, want %q", stored.Status, "active")
	}

	// The client's auth hash is a login credential. Storing it as received
	// would mean a database dump grants login to every account.
	sent := enrollBody()["authHash"]
	if stored.AuthHash.String == sent {
		t.Error("the auth hash was stored verbatim instead of being hashed")
	}
	if !auth.VerifyAuthHash(sent, stored.AuthHash.String) {
		t.Error("the stored auth hash does not verify against the value sent")
	}
}

func TestEnrollResponseLeaksNoKeyMaterial(t *testing.T) {
	srv := newTestServer(t)
	_, token := seedInvite(t, srv, "person@example.com")

	rec := postJSON(t, srv, "/api/enroll/"+token, enrollBody())
	body := rec.Body.String()

	for _, secret := range []string{
		enrollBody()["authHash"],
		enrollBody()["protectedUserKey"],
		enrollBody()["recoveryProtectedUserKey"],
	} {
		if strings.Contains(body, secret) {
			t.Errorf("the enrollment response echoed key material: %s", body)
		}
	}
}

func TestEnrollRejectsAReplayedToken(t *testing.T) {
	srv := newTestServer(t)
	_, token := seedInvite(t, srv, "person@example.com")

	if rec := postJSON(t, srv, "/api/enroll/"+token, enrollBody()); rec.Code != http.StatusOK {
		t.Fatalf("first enrollment failed: %d %s", rec.Code, rec.Body.String())
	}
	rec := postJSON(t, srv, "/api/enroll/"+token, enrollBody())
	if rec.Code != http.StatusNotFound {
		t.Errorf("replayed token status = %d, want %d", rec.Code, http.StatusNotFound)
	}
}

func TestEnrollRejectsUnknownToken(t *testing.T) {
	srv := newTestServer(t)

	rec := postJSON(t, srv, "/api/enroll/does-not-exist", enrollBody())
	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusNotFound)
	}
}

func TestEnrollDoesNotHashBeforeTheTokenIsKnownGood(t *testing.T) {
	srv := newTestServer(t)

	before := auth.Argon2Calls()
	rec := postJSON(t, srv, "/api/enroll/does-not-exist", enrollBody())
	spent := auth.Argon2Calls() - before

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusNotFound)
	}
	// /api/enroll/{token} is unauthenticated and takes a caller-chosen token.
	// Hashing before the token is checked means anyone can spend 64 MiB and
	// ~50 ms of the server per request, with no account and no credential. An
	// invalid token must cost one indexed SELECT.
	if spent != 0 {
		t.Errorf("an unknown setup link cost %d Argon2id computations, want 0", spent)
	}
}

func TestEnrollRejectsAnEmptyAuthHashWithoutHashing(t *testing.T) {
	srv := newTestServer(t)
	_, token := seedInvite(t, srv, "person@example.com")

	body := enrollBody()
	body["authHash"] = ""

	before := auth.Argon2Calls()
	rec := postJSON(t, srv, "/api/enroll/"+token, body)
	spent := auth.Argon2Calls() - before

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d; body %s", rec.Code, http.StatusBadRequest, rec.Body.String())
	}
	// Hashing an empty string succeeds and costs exactly as much as hashing a
	// real one, so the check has to come first or the cheapest possible garbage
	// request is also the most expensive to serve.
	if spent != 0 {
		t.Errorf("an empty authHash cost %d Argon2id computations, want 0", spent)
	}
}

func TestEnrollHashesOnceForALiveToken(t *testing.T) {
	srv := newTestServer(t)
	_, token := seedInvite(t, srv, "person@example.com")

	before := auth.Argon2Calls()
	rec := postJSON(t, srv, "/api/enroll/"+token, enrollBody())
	spent := auth.Argon2Calls() - before

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body %s", rec.Code, http.StatusOK, rec.Body.String())
	}
	// The counterpart to the two tests above: they would also pass if the
	// handler had simply stopped hashing altogether, which would store the
	// client's login credential in the clear.
	if spent != 1 {
		t.Errorf("a successful enrollment ran %d Argon2id computations, want exactly 1", spent)
	}
}

func TestEnrollIsRateLimitedPerIP(t *testing.T) {
	srv := newTestServer(t)

	// Enrollment was the only unauthenticated route with no limiter at all.
	// Every attempt here uses the same source address and an invalid token, so
	// the per-IP key is the only thing that can stop it.
	var last int
	for i := 0; i < 8; i++ {
		last = postJSONFrom(t, srv, "198.51.100.7:5555",
			"/api/enroll/does-not-exist", enrollBody()).Code
	}
	if last != http.StatusTooManyRequests {
		t.Errorf("status = %d after 8 invalid setup links from one address, want %d",
			last, http.StatusTooManyRequests)
	}

	// A different address must not inherit the block: setup links are handed to
	// real people, and one abusive host cannot be allowed to stop them enrolling.
	if got := postJSONFrom(t, srv, "198.51.100.8:5555",
		"/api/enroll/does-not-exist", enrollBody()).Code; got == http.StatusTooManyRequests {
		t.Errorf("a different source address was throttled by the first one's failures")
	}
}

func TestEnrollRejectsAMissingRecoveryBlob(t *testing.T) {
	srv := newTestServer(t)
	_, token := seedInvite(t, srv, "person@example.com")

	body := enrollBody()
	delete(body, "recoveryProtectedUserKey")

	// Accepting this would produce an account with no recovery path — a fact
	// nobody discovers until the user has forgotten their master password.
	rec := postJSON(t, srv, "/api/enroll/"+token, body)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d; body %s", rec.Code, http.StatusBadRequest, rec.Body.String())
	}
}

func TestEnrollRejectsAnUnknownField(t *testing.T) {
	srv := newTestServer(t)
	_, token := seedInvite(t, srv, "person@example.com")

	body := enrollBody()
	body["recoveryKdfParms"] = body["recoveryKdfParams"] // plausible typo

	rec := postJSON(t, srv, "/api/enroll/"+token, body)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
}
