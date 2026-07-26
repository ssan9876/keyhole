package httpapi

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestLoginIsThrottledAfterRepeatedFailures(t *testing.T) {
	srv := newTestServer(t)
	enrollTestUser(t, srv, "person@example.com")

	var lastCode int
	for i := 0; i < 8; i++ {
		rec := postJSON(t, srv, "/api/auth/login", map[string]string{
			"email": "person@example.com", "authHash": "wrong",
		})
		lastCode = rec.Code
	}
	if lastCode != http.StatusTooManyRequests {
		t.Errorf("after 8 failures the status was %d, want %d", lastCode, http.StatusTooManyRequests)
	}
}

func TestThrottleResponseCarriesRetryAfter(t *testing.T) {
	srv := newTestServer(t)
	enrollTestUser(t, srv, "person@example.com")

	var throttled *httptest.ResponseRecorder
	for i := 0; i < 10; i++ {
		rec := postJSON(t, srv, "/api/auth/login", map[string]string{
			"email": "person@example.com", "authHash": "wrong",
		})
		if rec.Code == http.StatusTooManyRequests {
			throttled = rec
			break
		}
	}
	if throttled == nil {
		t.Fatal("never got throttled")
	}
	if throttled.Header().Get("Retry-After") == "" {
		t.Error("Retry-After is not set on a throttled response")
	}
}

func TestSuccessfulLoginClearsTheThrottle(t *testing.T) {
	srv := newTestServer(t)
	_, authHash := enrollTestUser(t, srv, "person@example.com")

	// Four failures — under the five-attempt allowance.
	for i := 0; i < 4; i++ {
		postJSON(t, srv, "/api/auth/login", map[string]string{
			"email": "person@example.com", "authHash": "wrong",
		})
	}
	if rec := postJSON(t, srv, "/api/auth/login", map[string]string{
		"email": "person@example.com", "authHash": authHash,
	}); rec.Code != http.StatusOK {
		t.Fatalf("the correct credential was rejected: %d %s", rec.Code, rec.Body.String())
	}

	// A user who mistypes a few times and then succeeds must not still be
	// throttled the next time they sign in.
	for i := 0; i < 4; i++ {
		rec := postJSON(t, srv, "/api/auth/login", map[string]string{
			"email": "person@example.com", "authHash": "wrong",
		})
		if rec.Code == http.StatusTooManyRequests {
			t.Fatalf("throttled again after %d failures; the success did not reset the counter", i+1)
		}
	}
}

func TestASpoofedCFHeaderCannotEvadeTheIPLimit(t *testing.T) {
	srv := newTestServer(t)
	enrollTestUser(t, srv, "person@example.com")

	attempt := func(forwarded string) int {
		body := `{"email":"other@example.com","authHash":"wrong"}`
		req := httptest.NewRequest(http.MethodPost, "/api/auth/login", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.RemoteAddr = "203.0.113.50:5555" // NOT loopback
		req.Header.Set("CF-Connecting-IP", forwarded)
		rec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, req)
		return rec.Code
	}

	// Every request claims a different source address. Because the peer is not
	// loopback the header must be ignored, so all of them count against the one
	// real address and the throttle still bites. If the header were trusted,
	// each attempt would look like a fresh client and this would never throttle.
	var last int
	for i := 0; i < 10; i++ {
		last = attempt(fmt.Sprintf("198.51.100.%d", i))
	}
	if last != http.StatusTooManyRequests {
		t.Errorf("status = %d after 10 attempts with rotating spoofed IPs, want %d",
			last, http.StatusTooManyRequests)
	}
}

func TestALoopbackPeerIsRateLimitedPerForwardedAddress(t *testing.T) {
	srv := newTestServer(t)
	enrollTestUser(t, srv, "person@example.com")

	// Each attempt varies BOTH the forwarded address and the account, so the
	// per-account limiter cannot be what produces the result. Holding the email
	// fixed would throttle the account key and make this test pass for entirely
	// the wrong reason.
	attempt := func(forwarded, email string) int {
		body := fmt.Sprintf(`{"email":%q,"authHash":"wrong"}`, email)
		req := httptest.NewRequest(http.MethodPost, "/api/auth/login", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.RemoteAddr = "127.0.0.1:5555" // the tunnel, which we do trust
		req.Header.Set("CF-Connecting-IP", forwarded)
		rec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, req)
		return rec.Code
	}

	// The mirror of the test above. Behind the tunnel every request genuinely
	// arrives from loopback, so if we keyed on the peer instead of the
	// forwarded address, one abusive client would lock out the whole household.
	for i := 0; i < 8; i++ {
		attempt("198.51.100.1", fmt.Sprintf("victim%d@example.com", i))
	}

	// Same forwarded address, an account that has never been touched: only the
	// IP key can be responsible for this.
	if got := attempt("198.51.100.1", "fresh-account@example.com"); got != http.StatusTooManyRequests {
		t.Errorf("the abusive forwarded address got %d, want %d", got, http.StatusTooManyRequests)
	}
	// A different forwarded address, also a fresh account: neither key is spent,
	// so the household is not locked out by one bad client behind the tunnel.
	if got := attempt("198.51.100.99", "bystander@example.com"); got == http.StatusTooManyRequests {
		t.Error("a different forwarded address was throttled by the first one's failures")
	}
}

func TestUnknownAndRealAccountsAreTimingComparable(t *testing.T) {
	srv := newTestServer(t)
	enrollTestUser(t, srv, "person@example.com")

	measure := func(email string) time.Duration {
		start := time.Now()
		postJSON(t, srv, "/api/auth/login", map[string]string{
			"email": email, "authHash": "definitely-wrong",
		})
		return time.Since(start)
	}

	// One measurement each, before either key is throttled.
	real := measure("person@example.com")
	unknown := measure("ghost@example.com")

	// The unknown-account path must still pay the Argon2id cost. Returning
	// early would make it dramatically faster and turn login into an oracle for
	// which addresses have accounts here. The bound is loose on purpose: this
	// catches "no hashing at all", not microsecond differences, which a network
	// hides anyway.
	ratio := float64(real) / float64(unknown)
	if ratio > 5 || ratio < 0.2 {
		t.Errorf("timing differs too much: real %v, unknown %v (ratio %.2f)", real, unknown, ratio)
	}
}

func TestLoginResponseNeverLeaksStoredCredentialMaterial(t *testing.T) {
	srv := newTestServer(t)
	user, authHash := enrollTestUser(t, srv, "person@example.com")

	rec := postJSON(t, srv, "/api/auth/login", map[string]string{
		"email": "person@example.com", "authHash": authHash,
	})
	body := rec.Body.String()

	// The stored auth hash is a verifier. Echoing it would let anyone who saw
	// one response mount an offline attack against it.
	if strings.Contains(body, user.AuthHash.String) {
		t.Error("the login response contains the stored auth hash")
	}
	// Login does not need the recovery blob, so it must not hand one out.
	if strings.Contains(body, user.RecoveryProtectedUserKey.String) {
		t.Error("the login response contains the recovery blob, which login does not need")
	}
}

func TestPreloginSharesTheIPBudgetWithLogin(t *testing.T) {
	srv := newTestServer(t)

	// Prelogin records no failures itself — every address gets an answer, so it
	// has no notion of failure — but it must not be a free enumeration probe
	// either. It spends the same per-IP budget that failed logins consume.
	if rec := postJSON(t, srv, "/api/auth/prelogin", map[string]string{
		"email": "probe@example.com",
	}); rec.Code != http.StatusOK {
		t.Fatalf("prelogin was throttled before any budget was spent: %d", rec.Code)
	}

	for i := 0; i < 8; i++ {
		postJSON(t, srv, "/api/auth/login", map[string]string{
			"email": "probe@example.com", "authHash": "wrong",
		})
	}

	rec := postJSON(t, srv, "/api/auth/prelogin", map[string]string{"email": "another@example.com"})
	if rec.Code != http.StatusTooManyRequests {
		t.Errorf("prelogin status = %d after the IP budget was spent, want %d",
			rec.Code, http.StatusTooManyRequests)
	}
}

func TestErrorResponsesAreAlwaysTheEnvelope(t *testing.T) {
	srv := newTestServer(t)

	cases := []struct {
		name   string
		method string
		path   string
		body   string
	}{
		{"unknown route", http.MethodGet, "/api/nope", ""},
		{"bad json", http.MethodPost, "/api/auth/login", "{not json"},
		{"unknown enroll token", http.MethodPost, "/api/enroll/nope", "{}"},
		{"missing bearer token", http.MethodPost, "/api/auth/logout", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, tc.path, strings.NewReader(tc.body))
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()
			srv.Handler().ServeHTTP(rec, req)

			if rec.Code < 400 {
				t.Fatalf("expected an error status, got %d", rec.Code)
			}

			var body struct {
				Error struct {
					Code    string `json:"code"`
					Message string `json:"message"`
				} `json:"error"`
			}
			if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
				t.Fatalf("response is not the error envelope: %q", rec.Body.String())
			}
			if body.Error.Code == "" || body.Error.Message == "" {
				t.Errorf("envelope is incomplete: %q", rec.Body.String())
			}
		})
	}
}
