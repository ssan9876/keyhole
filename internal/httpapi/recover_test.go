package httpapi

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/ssan9876/keyhole/internal/auth"
	"github.com/ssan9876/keyhole/internal/store"
)

const recoverPreloginPath = "/api/auth/recover/prelogin"

// decodeObject returns a response body as a plain map together with a sorted
// "field:gotype" rendering of it.
//
// The shape is what the parity test compares. Picking fields out by name can
// only ever catch a field that changed value; an endpoint that starts leaking
// does it by growing an *extra* field, and only a whole-body comparison sees
// that.
func decodeObject(t *testing.T, rec *httptest.ResponseRecorder) (map[string]any, []string) {
	t.Helper()

	var body map[string]any
	decodeInto(t, rec, &body)

	shape := make([]string, 0, len(body))
	for name, value := range body {
		shape = append(shape, fmt.Sprintf("%s:%T", name, value))
	}
	sort.Strings(shape)
	return body, shape
}

// decodedSaltLen is the byte length a salt carries, not the length of its
// base64 text. Two salts of different byte lengths could still print at the
// same width, and it is the byte length a real client cares about.
func decodedSaltLen(t *testing.T, what string, salt any) int {
	t.Helper()

	text, ok := salt.(string)
	if !ok {
		t.Fatalf("%s is %T, want a string", what, salt)
	}
	raw, err := base64.StdEncoding.DecodeString(text)
	if err != nil {
		t.Fatalf("%s is not standard base64: %v", what, err)
	}
	return len(raw)
}

// TestRecoverPreloginAnswersIdenticallyForUnknownAndRedeemableAccounts is the
// test that matters most in this plan.
//
// The endpoint is unauthenticated and takes an email address. If anything at
// all in its answer differs between an address that has a redeemable account
// and one that has no account, it is a way to ask this installation who banks
// here — and the answer is a list of people to phish.
func TestRecoverPreloginAnswersIdenticallyForUnknownAndRedeemableAccounts(t *testing.T) {
	srv := newTestServer(t)
	enrollTestUser(t, srv, "person@example.com")

	known := postJSON(t, srv, recoverPreloginPath, map[string]string{"email": "person@example.com"})
	unknown := postJSON(t, srv, recoverPreloginPath, map[string]string{"email": "ghost@example.com"})

	if known.Code != unknown.Code {
		t.Fatalf("status: redeemable account %d, unknown address %d — the status alone answers "+
			"\"does this address have an account here\"", known.Code, unknown.Code)
	}
	if known.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body %s", known.Code, http.StatusOK, known.Body.String())
	}

	knownBody, knownShape := decodeObject(t, known)
	unknownBody, unknownShape := decodeObject(t, unknown)

	if !slices.Equal(knownShape, unknownShape) {
		t.Fatalf("body shape differs: redeemable %v, unknown %v", knownShape, unknownShape)
	}
	if knownBody["recoveryKdfParams"] != unknownBody["recoveryKdfParams"] {
		t.Errorf("recoveryKdfParams differs: redeemable %v, unknown %v",
			knownBody["recoveryKdfParams"], unknownBody["recoveryKdfParams"])
	}

	knownSalt, unknownSalt := knownBody["recoverySalt"], unknownBody["recoverySalt"]
	if got, want := decodedSaltLen(t, "decoy recoverySalt", unknownSalt),
		decodedSaltLen(t, "real recoverySalt", knownSalt); got != want {
		t.Errorf("recoverySalt is %d bytes for an unknown address and %d for a redeemable "+
			"account; the length alone distinguishes them", got, want)
	}
	if len(knownSalt.(string)) != len(unknownSalt.(string)) {
		t.Errorf("recoverySalt is %d characters for a redeemable account and %d for an unknown "+
			"address", len(knownSalt.(string)), len(unknownSalt.(string)))
	}
}

// TestRecoverPreloginAnswersAnOldFormatBlobLikeAnUnknownAddress covers the
// account that has a recovery blob but no auth hash to check it against —
// everything enrolled before migration 0004. It cannot be redeemed, so the
// only safe answer is the one an unknown address gets. Handing back the real
// salt and refusing at the redeem step would say the account exists.
func TestRecoverPreloginAnswersAnOldFormatBlobLikeAnUnknownAddress(t *testing.T) {
	srv := newTestServer(t)
	user, _ := enrollTestUser(t, srv, "person@example.com")

	if _, err := srv.store.DB().ExecContext(context.Background(),
		`UPDATE users SET recovery_auth_hash = NULL WHERE id = ?`, user.ID); err != nil {
		t.Fatalf("blank the recovery auth hash: %v", err)
	}

	rec := postJSON(t, srv, recoverPreloginPath, map[string]string{"email": "person@example.com"})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body %s", rec.Code, http.StatusOK, rec.Body.String())
	}

	body, _ := decodeObject(t, rec)
	if got, want := body["recoverySalt"], auth.DecoyRecoverySalt(srv.secret, "person@example.com"); got != want {
		t.Errorf("recoverySalt = %v, want the decoy %q", got, want)
	}
	if got := body["recoveryKdfParams"]; got != auth.DefaultKDFParamsJSON {
		t.Errorf("recoveryKdfParams = %v, want the decoy %q", got, auth.DefaultKDFParamsJSON)
	}
	// Independent of what the decoy happens to be: the real salt must not be in
	// there under any field name.
	if strings.Contains(rec.Body.String(), enrollBody()["recoverySalt"]) {
		t.Errorf("the response carries the account's real recovery salt: %s", rec.Body.String())
	}
}

// TestRecoverPreloginAnswersADisabledAccountLikeAnUnknownAddress is the other
// half of the "not redeemable" family: the row has a perfectly good auth hash,
// and an admin has turned the account off. Status is checked as well as the
// hash, or a disabled account is still a redeemable one.
func TestRecoverPreloginAnswersADisabledAccountLikeAnUnknownAddress(t *testing.T) {
	srv := newTestServer(t)
	user, _ := enrollTestUser(t, srv, "person@example.com")

	if _, err := srv.store.DB().ExecContext(context.Background(),
		`UPDATE users SET status = 'disabled' WHERE id = ?`, user.ID); err != nil {
		t.Fatalf("disable the account: %v", err)
	}

	rec := postJSON(t, srv, recoverPreloginPath, map[string]string{"email": "person@example.com"})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body %s", rec.Code, http.StatusOK, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), enrollBody()["recoverySalt"]) {
		t.Errorf("a disabled account handed back its real recovery salt: %s", rec.Body.String())
	}
}

// TestRecoverPreloginIsDeterministicForTheSameUnknownAddress pins the decoy
// down. A salt generated per call would be identical in shape and still
// announce, by changing, that nothing is stored behind the address.
func TestRecoverPreloginIsDeterministicForTheSameUnknownAddress(t *testing.T) {
	srv := newTestServer(t)

	first := postJSON(t, srv, recoverPreloginPath, map[string]string{"email": "ghost@example.com"})
	second := postJSON(t, srv, recoverPreloginPath, map[string]string{"email": "ghost@example.com"})

	if first.Code != http.StatusOK || second.Code != http.StatusOK {
		t.Fatalf("statuses = %d and %d, want %d", first.Code, second.Code, http.StatusOK)
	}
	if first.Body.String() != second.Body.String() {
		t.Errorf("two calls for one unknown address differ:\n%s\n%s",
			first.Body.String(), second.Body.String())
	}
}

// TestRecoverPreloginReturnsTheRealSaltAndParamsForARedeemableAccount uses a
// stored recoveryKdfParams that is deliberately *not* the default, because
// that is the only way to tell "returns what the blob was made with" apart
// from "returns the constant it would have returned anyway".
func TestRecoverPreloginReturnsTheRealSaltAndParamsForARedeemableAccount(t *testing.T) {
	srv := newTestServer(t)
	user, _ := enrollTestUser(t, srv, "person@example.com")

	const (
		storedSalt   = "ZGlmZmVyZW50c2FsdDQxNg=="
		storedParams = `{"algorithm":"argon2id","memoryKiB":131072,"iterations":4,"parallelism":2}`
	)
	if err := srv.store.RotateRecovery(context.Background(), user.ID, store.RecoveryRotation{
		RecoverySalt:             storedSalt,
		RecoveryKDFParams:        storedParams,
		RecoveryProtectedUserKey: `{"v":1,"alg":"A256GCM","n":"bm9uY2U=","ct":"cmVjb3Zlcnk="}`,
		RecoveryAuthHash:         "argon2id$AAAAAAAAAAAAAAAAAAAAAA==$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
	}); err != nil {
		t.Fatalf("RotateRecovery: %v", err)
	}

	rec := postJSON(t, srv, recoverPreloginPath, map[string]string{"email": "PERSON@example.com"})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body %s", rec.Code, http.StatusOK, rec.Body.String())
	}

	body, _ := decodeObject(t, rec)
	if got := body["recoverySalt"]; got != storedSalt {
		t.Errorf("recoverySalt = %v, want the stored %q", got, storedSalt)
	}
	// Deriving the recovery key with parameters other than the ones the blob was
	// wrapped under yields a different key, and the user would find that out at
	// the moment recovery was their last resort.
	if got := body["recoveryKdfParams"]; got != storedParams {
		t.Errorf("recoveryKdfParams = %v, want the stored %q", got, storedParams)
	}
}

// TestTheTwoPreloginEndpointsGiveDifferentSaltsWhetherOrNotTheAccountExists
// closes the correlation oracle.
//
// A real account's kdf_salt and recovery_salt are two independent random
// values, so its two prelogin answers differ. If both endpoints decoyed an
// unknown address with the *same* derived value, then "ask both, compare" would
// answer "does this address have an account here" — the one question the
// decoys exist to refuse. The decoys must therefore be domain-separated.
func TestTheTwoPreloginEndpointsGiveDifferentSaltsWhetherOrNotTheAccountExists(t *testing.T) {
	srv := newTestServer(t)
	enrollTestUser(t, srv, "person@example.com")

	for _, email := range []string{"person@example.com", "ghost@example.com"} {
		loginBody, _ := decodeObject(t, postJSON(t, srv, "/api/auth/prelogin",
			map[string]string{"email": email}))
		recoverBody, _ := decodeObject(t, postJSON(t, srv, recoverPreloginPath,
			map[string]string{"email": email}))

		// Both must actually be there. Two absent fields compare unequal to
		// nothing at all, so without this the comparison below passes happily
		// against an endpoint that does not exist.
		loginSalt, ok := loginBody["kdfSalt"].(string)
		if !ok || loginSalt == "" {
			t.Fatalf("%s: prelogin returned no kdfSalt: %v", email, loginBody)
		}
		recoverSalt, ok := recoverBody["recoverySalt"].(string)
		if !ok || recoverSalt == "" {
			t.Fatalf("%s: recovery prelogin returned no recoverySalt: %v", email, recoverBody)
		}

		if loginSalt == recoverSalt {
			t.Errorf("%s: both prelogin endpoints answered with %q; comparing them tells a "+
				"caller whether the account exists", email, loginSalt)
		}
	}
}

// TestRecoverPreloginIsRateLimited bounds abuse of an unauthenticated endpoint
// that does a database lookup and an HMAC per call. It has no notion of
// failure — every address gets an answer — so the budget has to be recorded
// against on every call, not only on a failure that never happens.
func TestRecoverPreloginIsRateLimited(t *testing.T) {
	srv := newTestServer(t)

	var last int
	for i := 0; i < 30; i++ {
		last = postJSON(t, srv, recoverPreloginPath,
			map[string]string{"email": fmt.Sprintf("probe%d@example.com", i)}).Code
	}
	if last != http.StatusTooManyRequests {
		t.Errorf("status = %d after 30 calls, want %d — the endpoint is not bounded at all",
			last, http.StatusTooManyRequests)
	}
}

// TestRecoverPreloginSharesTheEnumerationBudgetWithLoginPrelogin keeps the
// throttle from being sidestepped. Both endpoints answer the same question for
// the same address list. On separate budgets, an attacker throttled on one
// simply walks the rest of the list on the other.
func TestRecoverPreloginSharesTheEnumerationBudgetWithLoginPrelogin(t *testing.T) {
	srv := newTestServer(t)

	for i := 0; i < 25; i++ {
		postJSON(t, srv, "/api/auth/prelogin",
			map[string]string{"email": fmt.Sprintf("probe%d@example.com", i)})
	}

	rec := postJSON(t, srv, recoverPreloginPath, map[string]string{"email": "probe99@example.com"})
	if rec.Code != http.StatusTooManyRequests {
		t.Errorf("status = %d after 25 login prelogins from the same address, want %d",
			rec.Code, http.StatusTooManyRequests)
	}
}
