package httpapi

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ssan9876/keyhole/internal/store"
)

// loginTestUser enrolls an account and signs in, returning the user and a live
// access token. Every vault endpoint is behind requireAuth, so this is the
// starting point of nearly every test from here on.
func loginTestUser(t *testing.T, srv *Server, email string) (store.User, string) {
	t.Helper()

	user, authHash := enrollTestUser(t, srv, email)
	rec := postJSON(t, srv, "/api/auth/login", map[string]string{
		"email":       email,
		"authHash":    authHash,
		"deviceLabel": "test device",
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("login failed: %d %s", rec.Code, rec.Body.String())
	}

	var body struct {
		AccessToken string `json:"accessToken"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("login body: %v", err)
	}
	if body.AccessToken == "" {
		t.Fatal("login returned no access token")
	}
	return user, body.AccessToken
}

// doJSON sends an authenticated request. A blank token sends no Authorization
// header at all, which is how the unauthenticated cases are exercised.
func doJSON(t *testing.T, srv *Server, method, path, token string, payload any) *httptest.ResponseRecorder {
	t.Helper()

	var body *bytes.Reader
	if payload == nil {
		body = bytes.NewReader(nil)
	} else {
		encoded, err := json.Marshal(payload)
		if err != nil {
			t.Fatalf("marshal payload: %v", err)
		}
		body = bytes.NewReader(encoded)
	}

	req := httptest.NewRequest(method, path, body)
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	return rec
}

func decodeInto(t *testing.T, rec *httptest.ResponseRecorder, dst any) {
	t.Helper()
	if err := json.Unmarshal(rec.Body.Bytes(), dst); err != nil {
		t.Fatalf("response is not valid JSON (%d): %s", rec.Code, rec.Body.String())
	}
}
