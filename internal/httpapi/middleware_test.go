package httpapi

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestClientIPIgnoresCFHeaderFromNonLoopback(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "203.0.113.9:5555"
	req.Header.Set("CF-Connecting-IP", "198.51.100.1")

	// Trusting this header from an arbitrary peer would let anyone forge their
	// own source address and walk straight past the rate limiter.
	if got := ClientIP(req); got != "203.0.113.9" {
		t.Errorf("ClientIP = %q, want the real peer %q", got, "203.0.113.9")
	}
}

func TestClientIPHonoursCFHeaderFromLoopback(t *testing.T) {
	for _, remote := range []string{"127.0.0.1:41000", "[::1]:41000"} {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = remote
		req.Header.Set("CF-Connecting-IP", "198.51.100.1")

		if got := ClientIP(req); got != "198.51.100.1" {
			t.Errorf("ClientIP with remote %s = %q, want %q", remote, got, "198.51.100.1")
		}
	}
}

func TestClientIPFallsBackToPeerWhenHeaderAbsent(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "127.0.0.1:41000"

	if got := ClientIP(req); got != "127.0.0.1" {
		t.Errorf("ClientIP = %q, want %q", got, "127.0.0.1")
	}
}

func TestClientIPRejectsAMalformedCFHeader(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "127.0.0.1:41000"
	req.Header.Set("CF-Connecting-IP", "not-an-ip")

	if got := ClientIP(req); got != "127.0.0.1" {
		t.Errorf("ClientIP = %q, want the peer %q when the header is not an IP", got, "127.0.0.1")
	}
}

func TestSecurityHeadersAreSet(t *testing.T) {
	handler := securityHeaders(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))

	want := map[string]string{
		"X-Content-Type-Options": "nosniff",
		"Referrer-Policy":        "no-referrer",
		"X-Frame-Options":        "DENY",
	}
	for header, value := range want {
		if got := rec.Header().Get(header); got != value {
			t.Errorf("%s = %q, want %q", header, got, value)
		}
	}
	if csp := rec.Header().Get("Content-Security-Policy"); csp == "" {
		t.Error("Content-Security-Policy is not set")
	}
}

func TestRequestIDIsGeneratedAndReturned(t *testing.T) {
	var seen string
	handler := requestID(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = RequestIDFrom(r.Context())
		w.WriteHeader(http.StatusOK)
	}))

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))

	if seen == "" {
		t.Error("no request ID was placed in the context")
	}
	if got := rec.Header().Get("X-Request-Id"); got != seen {
		t.Errorf("X-Request-Id header = %q, want the context value %q", got, seen)
	}
}

func TestRequestIDIsNotTakenFromTheClient(t *testing.T) {
	var seen string
	handler := requestID(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = RequestIDFrom(r.Context())
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Request-Id", "attacker-supplied-value")

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	// Echoing a client-chosen ID lets a caller forge or collide log entries.
	if seen == "attacker-supplied-value" {
		t.Error("the client-supplied request ID was adopted")
	}
}
