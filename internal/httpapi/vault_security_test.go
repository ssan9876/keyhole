package httpapi

import (
	"net/http"
	"strings"
	"testing"
)

// vaultRoutes is every route this plan added. Keeping the list in one place
// means a new endpoint that forgets requireAuth fails these tests rather than
// shipping.
var vaultRoutes = []struct {
	method string
	path   string
	body   any
}{
	{http.MethodGet, "/api/sync", nil},
	{http.MethodPost, "/api/items", map[string]string{"ciphertext": "c", "wrappedItemKey": "k"}},
	{http.MethodPost, "/api/items/bulk", map[string]any{"items": []map[string]string{{"ciphertext": "c", "wrappedItemKey": "k"}}}},
	{http.MethodPut, "/api/items/abc", map[string]any{"ciphertext": "c", "wrappedItemKey": "k", "revision": 1}},
	{http.MethodDelete, "/api/items/abc", nil},
	{http.MethodPost, "/api/folders", map[string]string{"encryptedName": "n"}},
	{http.MethodPut, "/api/folders/abc", map[string]any{"encryptedName": "n", "revision": 1}},
	{http.MethodDelete, "/api/folders/abc", nil},
	{http.MethodGet, "/api/collections", nil},
	{http.MethodPost, "/api/collections", map[string]string{"name": "n", "sealedCollectionKey": "s"}},
	{http.MethodGet, "/api/collections/pending-grants", nil},
	{http.MethodDelete, "/api/collections/abc", nil},
	{http.MethodGet, "/api/collections/abc/members", nil},
	{http.MethodPost, "/api/collections/abc/members", map[string]string{"userId": "u"}},
	{http.MethodDelete, "/api/collections/abc/members/u", nil},
	{http.MethodPost, "/api/collections/abc/grants", map[string]string{"userId": "u", "sealedCollectionKey": "s"}},
	{http.MethodGet, "/api/directory", nil},
	{http.MethodGet, "/api/account", nil},
	{http.MethodPost, "/api/account/password", map[string]string{"currentAuthHash": "h"}},
	{http.MethodPost, "/api/account/recovery", map[string]string{"currentAuthHash": "h"}},
	{http.MethodGet, "/api/account/sessions", nil},
	{http.MethodDelete, "/api/account/sessions/abc", nil},
	{http.MethodGet, "/api/admin/users", nil},
	{http.MethodPost, "/api/admin/users", map[string]string{"email": "a@b.c", "name": "n"}},
	{http.MethodPost, "/api/admin/users/abc/invite", nil},
	{http.MethodPatch, "/api/admin/users/abc", map[string]string{"status": "disabled"}},
	{http.MethodPost, "/api/admin/users/abc/reset", map[string]string{"confirmEmail": "a@b.c"}},
	{http.MethodDelete, "/api/admin/users/abc", nil},
	{http.MethodGet, "/api/admin/audit", nil},
	{http.MethodGet, "/api/admin/collections", nil},
}

func TestEveryVaultRouteRejectsAnUnauthenticatedCaller(t *testing.T) {
	srv := newTestServer(t)

	for _, route := range vaultRoutes {
		rec := doJSON(t, srv, route.method, route.path, "", route.body)
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("%s %s = %d without a token, want %d",
				route.method, route.path, rec.Code, http.StatusUnauthorized)
		}
	}
}

func TestEveryVaultRouteRejectsADisabledAccount(t *testing.T) {
	srv := newTestServer(t)
	_, adminToken := loginAdmin(t, srv, "admin@example.com")
	target, targetToken := loginTestUser(t, srv, "person@example.com")

	if rec := doJSON(t, srv, http.MethodPatch, "/api/admin/users/"+target.ID, adminToken,
		map[string]string{"status": "disabled"}); rec.Code != http.StatusOK {
		t.Fatalf("disable: %d %s", rec.Code, rec.Body.String())
	}

	// "Disable this account" has to mean it everywhere at once. One route that
	// still answers is the one an attacker finds.
	for _, route := range vaultRoutes {
		rec := doJSON(t, srv, route.method, route.path, targetToken, route.body)
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("%s %s = %d for a disabled account, want %d",
				route.method, route.path, rec.Code, http.StatusUnauthorized)
		}
	}
}

func TestNoEndpointReturnsAnotherUsersWrappedKeys(t *testing.T) {
	srv := newTestServer(t)
	_, adminToken := loginAdmin(t, srv, "admin@example.com")
	loginTestUser(t, srv, "person@example.com")

	// Spec section 10 requires this assertion by name. assertNoKeyMaterial
	// normalizes case and underscores, so it catches a handler that marshals a
	// store struct directly — which emits PascalCase field names an exact-match
	// list misses entirely. That is not hypothetical: it is what the admin user
	// list test failed to catch until it was fixed in Task 7.
	readRoutes := []string{
		"/api/sync",
		"/api/collections",
		"/api/collections/pending-grants",
		"/api/directory",
		"/api/account",
		"/api/account/sessions",
		"/api/admin/users",
		"/api/admin/audit",
		"/api/admin/collections",
	}
	for _, path := range readRoutes {
		rec := doJSON(t, srv, http.MethodGet, path, adminToken, nil)
		if rec.Code != http.StatusOK {
			t.Fatalf("GET %s = %d: %s", path, rec.Code, rec.Body.String())
		}
		assertNoKeyMaterial(t, "GET "+path, rec.Body.String())

		// Session and invite tokens are stored hashed and must never come back
		// out under any name either.
		normalized := normalizeFieldNames(rec.Body.String())
		for _, field := range []string{"tokenHash", "refreshHash", "accessTokenHash"} {
			if strings.Contains(normalized, normalizeFieldNames(field)) {
				t.Errorf("GET %s carries %q", path, field)
			}
		}
	}
}

func TestTheContentSecurityPolicyIsRestrictive(t *testing.T) {
	srv := newTestServer(t)

	rec := doJSON(t, srv, http.MethodGet, "/healthz", "", nil)
	policy := rec.Header().Get("Content-Security-Policy")

	// Plan 2a's review found the existing assertion only checked the header was
	// non-empty, so replacing the policy with any weaker non-empty string
	// passed. These are the directives that actually matter for a page that
	// handles a master password.
	for _, directive := range []string{
		"default-src 'self'",
		"script-src 'self'",
		"object-src 'none'",
		"frame-ancestors 'none'",
		"base-uri 'none'",
	} {
		if !strings.Contains(policy, directive) {
			t.Errorf("CSP is missing %q: %s", directive, policy)
		}
	}
	// 'unsafe-inline' or 'unsafe-eval' in script-src would defeat the policy
	// entirely for the one page that must not be defeated. Matched as quoted
	// source-expression tokens, not bare substrings: 'wasm-unsafe-eval' — which
	// the policy DOES carry so Argon2id's WebAssembly can compile — ends in the
	// bytes "unsafe-eval'", and a bare-substring check would wrongly flag it.
	// 'wasm-unsafe-eval' permits only WASM, never eval() of JavaScript, so it is
	// not one of the policy-defeating tokens; the exact-token forms below still
	// reject a real 'unsafe-eval' or 'unsafe-inline'.
	for _, unsafe := range []string{"'unsafe-inline'", "'unsafe-eval'", "*"} {
		if strings.Contains(policy, unsafe) {
			t.Errorf("CSP contains %q: %s", unsafe, policy)
		}
	}
}

func TestAnItemIdFromAnotherVaultIsIndistinguishableFromANonexistentOne(t *testing.T) {
	srv := newTestServer(t)
	_, ownerToken := loginTestUser(t, srv, "owner@example.com")
	_, otherToken := loginTestUser(t, srv, "other@example.com")

	created := doJSON(t, srv, http.MethodPost, "/api/items", ownerToken, map[string]string{
		"ciphertext": "c", "wrappedItemKey": "k",
	})
	var item itemResponse
	decodeInto(t, created, &item)

	real := doJSON(t, srv, http.MethodDelete, "/api/items/"+item.ID, otherToken, nil)
	fake := doJSON(t, srv, http.MethodDelete, "/api/items/0123456789abcdef0123456789abcdef", otherToken, nil)

	// Different answers here would let anyone enumerate which item ids exist
	// across the whole installation, one request at a time.
	if real.Code != fake.Code {
		t.Errorf("existing-but-forbidden = %d, nonexistent = %d; they must match",
			real.Code, fake.Code)
	}
	if real.Body.String() != fake.Body.String() {
		t.Errorf("bodies differ:\n forbidden: %s\n missing:   %s", real.Body.String(), fake.Body.String())
	}
}
