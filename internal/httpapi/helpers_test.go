package httpapi

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
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

// keyMaterialFields are the columns no endpoint may ever return for anyone.
// public_key is deliberately absent: it is public by design (spec 3.9).
var keyMaterialFields = []string{
	"protectedUserKey", "encryptedPrivateKey", "recoveryProtectedUserKey",
	"authHash", "kdfSalt", "kdfParams", "recoverySalt", "recoveryKdfParams",
}

// normalizeFieldNames lowercases and strips underscores so one needle catches
// every spelling a field can reach the wire as.
//
// This is not fussiness. A struct with no JSON tags marshals PascalCase, so a
// handler that accidentally returns store.User instead of its own wire type
// emits "ProtectedUserKey" — which a check for "protectedUserKey" or
// "protected_user_key" sails straight past. Measured: with handleAdminListUsers
// mutated to marshal store.UserSummary directly, the response carried every
// wrapped key and an exact-match assertion still passed.
func normalizeFieldNames(s string) string {
	return strings.ReplaceAll(strings.ToLower(s), "_", "")
}

// assertNoKeyMaterial fails if a response body mentions any wrapped-key field
// under any spelling. Spec section 10 requires this of every endpoint that
// returns user records.
func assertNoKeyMaterial(t *testing.T, what, body string) {
	t.Helper()
	assertNoKeyMaterialExcept(t, what, body)
}

// assertNoKeyMaterialExcept is assertNoKeyMaterial for the one endpoint that is
// supposed to return some: the recovery redeem path, which hands back the blob
// the recovery code opens and the encrypted private key, and nothing else.
//
// The allowed names are cut out of the body before the search, because these
// field names nest. Normalized, "recoveryprotecteduserkey" *contains*
// "protecteduserkey" — so without the removal, a response carrying only the
// recovery blob would report the master-password blob as present, and the
// obvious fix for that false positive is to drop the needle that matters most.
func assertNoKeyMaterialExcept(t *testing.T, what, body string, allowed ...string) {
	t.Helper()

	normalized := normalizeFieldNames(body)
	for _, field := range allowed {
		normalized = strings.ReplaceAll(normalized, normalizeFieldNames(field), "")
	}
	for _, field := range keyMaterialFields {
		if slices.Contains(allowed, field) {
			continue
		}
		if strings.Contains(normalized, normalizeFieldNames(field)) {
			t.Errorf("%s carries %q: %s", what, field, body)
		}
	}
}
