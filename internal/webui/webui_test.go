package webui

import (
	"io/fs"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func get(t *testing.T, h http.Handler, path string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
	return rec
}

// someAssetName returns the name of an embedded hashed asset, skipping the
// test with a clear message when the app has not been built. The name is
// never hard-coded: it changes on every build.
func someAssetName(t *testing.T) string {
	t.Helper()
	files, err := dist()
	if err != nil {
		t.Fatalf("dist: %v", err)
	}
	entries, err := fs.ReadDir(files, "assets")
	if err != nil || len(entries) == 0 {
		t.Skip("dist/assets is empty; run `pnpm --filter @keyhole/web build`")
	}
	return entries[0].Name()
}

func TestHandlerServesTheIndexAtRoot(t *testing.T) {
	h, err := Handler()
	if err != nil {
		t.Fatalf("Handler: %v", err)
	}
	rec := get(t, h, "/")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET / = %d, want 200", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct == "" {
		t.Error("no Content-Type on the index")
	}
}

// The invite link is the first URL a new user ever opens, and it is a client
// route with no file behind it. Without the fallback it 404s and the account
// can never be set up.
func TestHandlerServesTheIndexForAClientRoute(t *testing.T) {
	h, _ := Handler()
	rec := get(t, h, "/enroll/tok_abc123")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /enroll/tok_abc123 = %d, want 200", rec.Code)
	}
	root := get(t, h, "/")
	if rec.Body.String() != root.Body.String() {
		t.Error("client route did not return the same document as /")
	}
}

// A missing asset must NOT fall back to the index: a bundle referencing a file
// that no longer exists would receive HTML with a 200 and fail with an opaque
// syntax error instead of a 404 anyone can diagnose.
func TestHandlerReturnsNotFoundForAMissingAsset(t *testing.T) {
	h, _ := Handler()
	if rec := get(t, h, "/assets/does-not-exist.js"); rec.Code != http.StatusNotFound {
		t.Fatalf("GET /assets/does-not-exist.js = %d, want 404", rec.Code)
	}
}

func TestHashedAssetsAreCacheableAndTheIndexIsNot(t *testing.T) {
	h, _ := Handler()

	index := get(t, h, "/")
	if cc := index.Header().Get("Cache-Control"); cc != "no-store" {
		t.Errorf("index Cache-Control = %q, want no-store", cc)
	}

	// The index names the hashed bundles, so caching it would pin a browser to
	// an old build forever. The bundles themselves carry a content hash in the
	// name, so they can be cached for a year.
	asset := get(t, h, "/assets/"+someAssetName(t))
	if cc := asset.Header().Get("Cache-Control"); cc != "public, max-age=31536000, immutable" {
		t.Errorf("asset Cache-Control = %q, want a year and immutable", cc)
	}
}

// The manifest must be served as application/manifest+json, not the text/plain
// Go's FileServer would content-sniff a JSON body to. A wrong type makes some
// browsers refuse to install the PWA and logs a console warning on the rest.
func TestManifestHasTheCorrectContentType(t *testing.T) {
	files, err := dist()
	if err != nil {
		t.Fatalf("dist: %v", err)
	}
	if _, err := fs.Stat(files, "manifest.webmanifest"); err != nil {
		t.Skip("no built manifest; run `pnpm --filter @keyhole/web build`")
	}
	h, _ := Handler()
	rec := get(t, h, "/manifest.webmanifest")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /manifest.webmanifest = %d, want 200", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/manifest+json" {
		t.Errorf("manifest Content-Type = %q, want application/manifest+json", ct)
	}
}

// When the app has not been built, dist holds only placeholder.html and there
// is no real index.html. Handler must still answer "/" with 200 and the
// placeholder's explanation, not a bare 404 that leaves an operator guessing.
func TestHandlerServesThePlaceholderWhenTheAppWasNotBuilt(t *testing.T) {
	if Built() {
		t.Skip("dist holds a real build; this only exercises the unbuilt path")
	}
	h, _ := Handler()
	rec := get(t, h, "/")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET / = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "without the web app") {
		t.Errorf("body does not look like the placeholder: %q", rec.Body.String())
	}
}
