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
	encoded, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(string(encoded)))
	req.Header.Set("Content-Type", "application/json")
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
