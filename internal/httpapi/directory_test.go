package httpapi

import (
	"net/http"
	"strings"
	"testing"
)

type directoryEntry struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Email     string `json:"email"`
	PublicKey string `json:"publicKey"`
}

func TestDirectoryListsActiveUsersAndTheirPublicKeys(t *testing.T) {
	srv := newTestServer(t)
	_, token := loginTestUser(t, srv, "person@example.com")
	loginTestUser(t, srv, "other@example.com")

	rec := doJSON(t, srv, http.MethodGet, "/api/directory", token, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d: %s", rec.Code, http.StatusOK, rec.Body.String())
	}
	var body struct {
		Users []directoryEntry `json:"users"`
	}
	decodeInto(t, rec, &body)
	if len(body.Users) != 2 {
		t.Fatalf("got %d users, want 2", len(body.Users))
	}
	// Without a public key there is nothing to seal a collection key to, so
	// sharing would be impossible. This is why the endpoint exists.
	for _, user := range body.Users {
		if user.PublicKey == "" {
			t.Errorf("user %s has no public key", user.Email)
		}
	}
}

func TestDirectoryNeverCarriesKeyMaterial(t *testing.T) {
	srv := newTestServer(t)
	_, token := loginTestUser(t, srv, "person@example.com")

	rec := doJSON(t, srv, http.MethodGet, "/api/directory", token, nil)
	body := rec.Body.String()

	// Spec section 10 names this as a security test: no endpoint may return
	// another user's wrapped keys. The public key is public by design; every
	// one of these is not.
	for _, field := range []string{
		"protectedUserKey", "protected_user_key",
		"encryptedPrivateKey", "encrypted_private_key",
		"recoveryProtectedUserKey", "recovery_protected_user_key",
		"authHash", "auth_hash", "kdfSalt", "kdf_salt",
		"recoverySalt", "recovery_salt",
	} {
		if strings.Contains(body, field) {
			t.Errorf("directory response contains %q: %s", field, body)
		}
	}
}

func TestDirectoryOmitsPendingAndDisabledAccounts(t *testing.T) {
	srv := newTestServer(t)
	_, token := loginTestUser(t, srv, "person@example.com")
	seedInvite(t, srv, "pending@example.com") // never enrolled

	rec := doJSON(t, srv, http.MethodGet, "/api/directory", token, nil)
	var body struct {
		Users []directoryEntry `json:"users"`
	}
	decodeInto(t, rec, &body)

	// A pending account has no public key at all, so listing it would offer a
	// share target that can never receive one.
	for _, user := range body.Users {
		if user.Email == "pending@example.com" {
			t.Error("the directory lists an account that has never enrolled")
		}
	}
	if len(body.Users) != 1 {
		t.Errorf("got %d users, want 1", len(body.Users))
	}
}

func TestDirectoryRequiresAuthentication(t *testing.T) {
	srv := newTestServer(t)

	rec := doJSON(t, srv, http.MethodGet, "/api/directory", "", nil)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d — the user list is not public",
			rec.Code, http.StatusUnauthorized)
	}
}
