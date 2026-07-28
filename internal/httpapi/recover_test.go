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
	"time"

	"github.com/ssan9876/keyhole/internal/auth"
	"github.com/ssan9876/keyhole/internal/store"
)

const (
	recoverPreloginPath = "/api/auth/recover/prelogin"
	recoverPath         = "/api/auth/recover"
	recoverCompletePath = "/api/auth/recover/complete"
)

// recoverCompleteBody is what a client uploads once it has unwrapped its
// userKey with the recovery code: a complete new master-password credential and
// a complete new recovery blob, because redeeming a code retires it.
func recoverCompleteBody(token string) map[string]string {
	return map[string]string{
		"recoveryToken":            token,
		"kdfSalt":                  "bmV3c2FsdG5ld3NhbHQxNg==",
		"params":                   auth.DefaultKDFParamsJSON,
		"authHash":                 "bmV3LWF1dGgtaGFzaC0zMi1ieXRlcy1iNg==",
		"protectedUserKey":         `{"v":1,"alg":"A256GCM","n":"bm9uY2U=","ct":"bmV3d3JhcA=="}`,
		"recoverySalt":             "bmV3cmVjb3ZlcnlzYWx0MQ==",
		"recoveryKdfParams":        auth.DefaultKDFParamsJSON,
		"recoveryProtectedUserKey": `{"v":1,"alg":"A256GCM","n":"bm9uY2U=","ct":"bmV3cmVjb3Zlcnk="}`,
		"recoveryAuthHash":         "bmV3LXJlY292ZXJ5LWF1dGgtaGFzaA==",
	}
}

// redeemRecoveryCode runs the redeem step with the enrolled account's real
// recovery auth hash and returns the one-time token it mints.
func redeemRecoveryCode(t *testing.T, srv *Server, email string) string {
	t.Helper()

	rec := postJSON(t, srv, recoverPath, map[string]string{
		"email":            email,
		"recoveryAuthHash": enrollBody()["recoveryAuthHash"],
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("redeem failed: %d %s", rec.Code, rec.Body.String())
	}
	var body struct {
		RecoveryToken string `json:"recoveryToken"`
	}
	decodeInto(t, rec, &body)
	if body.RecoveryToken == "" {
		t.Fatalf("redeem returned no recoveryToken: %s", rec.Body.String())
	}
	return body.RecoveryToken
}

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
//
// The divergent value is written straight to the column, because no write path
// will accept one any more: every endpoint that writes recovery_kdf_params now
// pins it byte-equal to auth.DefaultKDFParamsJSON. What is simulated here is a
// row from before that pin, or one left mid-migration by a future parameter
// bump — the cases this read path still has to serve correctly, since deriving
// a recovery key under any other parameters yields a different key and the user
// would discover that at the moment recovery was their last resort.
func TestRecoverPreloginReturnsTheRealSaltAndParamsForARedeemableAccount(t *testing.T) {
	srv := newTestServer(t)
	user, _ := enrollTestUser(t, srv, "person@example.com")

	const (
		storedSalt   = "ZGlmZmVyZW50c2FsdDQxNg=="
		storedParams = `{"algorithm":"argon2id","memoryKiB":131072,"iterations":4,"parallelism":2}`
	)
	if err := srv.store.RotateRecovery(context.Background(), user.ID, store.RecoveryRotation{
		RecoverySalt:             storedSalt,
		RecoveryKDFParams:        auth.DefaultKDFParamsJSON,
		RecoveryProtectedUserKey: `{"v":1,"alg":"A256GCM","n":"bm9uY2U=","ct":"cmVjb3Zlcnk="}`,
		RecoveryAuthHash:         "argon2id$AAAAAAAAAAAAAAAAAAAAAA==$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
	}); err != nil {
		t.Fatalf("RotateRecovery: %v", err)
	}
	if _, err := srv.store.DB().ExecContext(context.Background(),
		`UPDATE users SET recovery_kdf_params = ? WHERE id = ?`, storedParams, user.ID); err != nil {
		t.Fatalf("seed a legacy recovery_kdf_params: %v", err)
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

func TestRecoverReturnsTheBlobsForACorrectRecoveryAuthHash(t *testing.T) {
	srv := newTestServer(t)
	enrollTestUser(t, srv, "person@example.com")

	rec := postJSON(t, srv, recoverPath, map[string]string{
		"email":            "PERSON@example.com",
		"recoveryAuthHash": enrollBody()["recoveryAuthHash"],
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body %s", rec.Code, http.StatusOK, rec.Body.String())
	}

	var body struct {
		RecoveryProtectedUserKey string  `json:"recoveryProtectedUserKey"`
		EncryptedPrivateKey      string  `json:"encryptedPrivateKey"`
		RecoveryToken            string  `json:"recoveryToken"`
		ExpiresIn                float64 `json:"expiresIn"`
	}
	decodeInto(t, rec, &body)

	// The blob the recovery code opens, and the private key wrapped by the
	// userKey inside it. Both are useless to anyone who cannot derive the
	// recovery wrap key, which is why proving possession of the auth half is
	// enough to be handed them.
	if body.RecoveryProtectedUserKey != enrollBody()["recoveryProtectedUserKey"] {
		t.Errorf("recoveryProtectedUserKey = %q, want the enrolled blob", body.RecoveryProtectedUserKey)
	}
	if body.EncryptedPrivateKey != enrollBody()["encryptedPrivateKey"] {
		t.Errorf("encryptedPrivateKey = %q, want the enrolled one", body.EncryptedPrivateKey)
	}
	if body.RecoveryToken == "" {
		t.Error("no recoveryToken; the caller has no way to finish the recovery")
	}
	if want := store.RecoveryTokenTTL.Seconds(); body.ExpiresIn != want {
		t.Errorf("expiresIn = %v, want %v", body.ExpiresIn, want)
	}
}

func TestRecoverRejectsAWrongRecoveryAuthHash(t *testing.T) {
	srv := newTestServer(t)
	enrollTestUser(t, srv, "person@example.com")

	wrong := postJSON(t, srv, recoverPath, map[string]string{
		"email":            "person@example.com",
		"recoveryAuthHash": "bm90LXRoZS1yaWdodC1jb2Rl",
	})
	if wrong.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d; body %s", wrong.Code, http.StatusUnauthorized, wrong.Body.String())
	}

	// Byte-identical to the answer an address with no account gets. A distinct
	// message for "that account exists, the code is wrong" would say out loud
	// which addresses are worth grinding.
	unknown := postJSON(t, srv, recoverPath, map[string]string{
		"email":            "ghost@example.com",
		"recoveryAuthHash": "bm90LXRoZS1yaWdodC1jb2Rl",
	})
	if wrong.Code != unknown.Code || wrong.Body.String() != unknown.Body.String() {
		t.Errorf("a wrong code answers %d %s but an unknown address answers %d %s",
			wrong.Code, wrong.Body.String(), unknown.Code, unknown.Body.String())
	}
}

// TestRecoverRejectsAnAccountWithNoRecoveryAuthHash covers every blob written
// before migration 0004. There is nothing to check possession against, so the
// account cannot be redeemed — and it has to be refused in exactly the words an
// unknown address is refused in, or the refusal itself confirms the account.
func TestRecoverRejectsAnAccountWithNoRecoveryAuthHash(t *testing.T) {
	srv := newTestServer(t)
	user, _ := enrollTestUser(t, srv, "person@example.com")

	if _, err := srv.store.DB().ExecContext(context.Background(),
		`UPDATE users SET recovery_auth_hash = NULL WHERE id = ?`, user.ID); err != nil {
		t.Fatalf("blank the recovery auth hash: %v", err)
	}

	oldFormat := postJSON(t, srv, recoverPath, map[string]string{
		"email":            "person@example.com",
		"recoveryAuthHash": enrollBody()["recoveryAuthHash"],
	})
	if oldFormat.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d; body %s",
			oldFormat.Code, http.StatusUnauthorized, oldFormat.Body.String())
	}
	if strings.Contains(oldFormat.Body.String(), enrollBody()["recoveryProtectedUserKey"]) {
		t.Error("the refusal carried the recovery blob anyway")
	}

	unknown := postJSON(t, srv, recoverPath, map[string]string{
		"email":            "ghost@example.com",
		"recoveryAuthHash": enrollBody()["recoveryAuthHash"],
	})
	if oldFormat.Body.String() != unknown.Body.String() {
		t.Errorf("an old-format account answers %s but an unknown address answers %s",
			oldFormat.Body.String(), unknown.Body.String())
	}
}

// TestRecoverRefusesADisabledAccountHoldingACorrectRecoveryAuthHash is the one
// failure the auth hash alone cannot catch: the code is right, and an admin has
// turned the account off. Redeeming it would hand the vault back to exactly the
// person the account was disabled to keep out.
func TestRecoverRefusesADisabledAccountHoldingACorrectRecoveryAuthHash(t *testing.T) {
	srv := newTestServer(t)
	user, _ := enrollTestUser(t, srv, "person@example.com")

	if _, err := srv.store.DB().ExecContext(context.Background(),
		`UPDATE users SET status = 'disabled' WHERE id = ?`, user.ID); err != nil {
		t.Fatalf("disable the account: %v", err)
	}

	rec := postJSON(t, srv, recoverPath, map[string]string{
		"email":            "person@example.com",
		"recoveryAuthHash": enrollBody()["recoveryAuthHash"],
	})
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d; body %s", rec.Code, http.StatusUnauthorized, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), enrollBody()["recoveryProtectedUserKey"]) {
		t.Errorf("a disabled account was handed its recovery blob: %s", rec.Body.String())
	}
}

// TestRecoverNeverReturnsTheProtectedUserKeyWrappedByTheMasterPassword pins the
// one blob that has no business on this path.
//
// The caller has proved possession of the recovery code, not the master
// password, and cannot open a master-password-wrapped blob — so shipping it
// only widens what a stolen response is worth. The field-name check normalizes
// case and underscores because Go marshals a struct with no JSON tags in
// PascalCase, which is how this class of test has silently passed before.
func TestRecoverNeverReturnsTheProtectedUserKeyWrappedByTheMasterPassword(t *testing.T) {
	srv := newTestServer(t)
	enrollTestUser(t, srv, "person@example.com")

	rec := postJSON(t, srv, recoverPath, map[string]string{
		"email":            "person@example.com",
		"recoveryAuthHash": enrollBody()["recoveryAuthHash"],
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body %s", rec.Code, http.StatusOK, rec.Body.String())
	}

	body := rec.Body.String()
	assertNoKeyMaterialExcept(t, "the redeem response", body,
		"recoveryProtectedUserKey", "encryptedPrivateKey")
	// And by value as well as by name, so renaming the field on the way out
	// does not slip past.
	if strings.Contains(body, enrollBody()["protectedUserKey"]) {
		t.Errorf("the redeem response carries the master-password-wrapped blob: %s", body)
	}
	if strings.Contains(body, enrollBody()["authHash"]) {
		t.Errorf("the redeem response carries the login auth hash: %s", body)
	}
}

// TestRecoverPaysTheSameArgon2idForAnUnknownAddressAsForAWrongCode keeps the
// two refusals apart in words only. Returning before the hash when the address
// is unknown would make it about 50 ms faster, and a timing difference is an
// enumeration oracle that no amount of identical response bodies hides.
func TestRecoverPaysTheSameArgon2idForAnUnknownAddressAsForAWrongCode(t *testing.T) {
	srv := newTestServer(t)
	enrollTestUser(t, srv, "person@example.com")

	before := auth.Argon2Calls()
	postJSON(t, srv, recoverPath, map[string]string{
		"email": "ghost@example.com", "recoveryAuthHash": "bm90LXJpZ2h0",
	})
	unknown := auth.Argon2Calls() - before

	before = auth.Argon2Calls()
	postJSON(t, srv, recoverPath, map[string]string{
		"email": "person@example.com", "recoveryAuthHash": "bm90LXJpZ2h0",
	})
	wrong := auth.Argon2Calls() - before

	if unknown != wrong {
		t.Errorf("an unknown address cost %d Argon2id computations and a wrong code cost %d",
			unknown, wrong)
	}
	if wrong != 1 {
		t.Errorf("a failed redemption ran %d Argon2id computations, want exactly 1", wrong)
	}
}

// TestRecoverIsRateLimitedOnTheAccountAcrossSourceAddresses is the half a
// per-IP limiter cannot do. Every attempt below comes from a different address,
// so only a key on the account itself can stop them.
func TestRecoverIsRateLimitedOnTheAccountAcrossSourceAddresses(t *testing.T) {
	srv := newTestServer(t)
	enrollTestUser(t, srv, "person@example.com")

	var last int
	for i := 0; i < 8; i++ {
		last = postJSONFrom(t, srv, fmt.Sprintf("198.51.100.%d:5555", i+1), recoverPath,
			map[string]string{
				"email": "person@example.com", "recoveryAuthHash": "bm90LXJpZ2h0",
			}).Code
	}
	if last != http.StatusTooManyRequests {
		t.Errorf("status = %d after 8 wrong codes for one account from 8 addresses, want %d",
			last, http.StatusTooManyRequests)
	}
}

// TestRecoverIsRateLimitedOnTheSourceAddressAcrossAccounts is the other half.
// Every attempt below names a different account, so only a key on the source
// address can stop one host grinding through an address list.
func TestRecoverIsRateLimitedOnTheSourceAddressAcrossAccounts(t *testing.T) {
	srv := newTestServer(t)

	var last int
	for i := 0; i < 8; i++ {
		last = postJSONFrom(t, srv, "198.51.100.200:5555", recoverPath, map[string]string{
			"email": fmt.Sprintf("probe%d@example.com", i), "recoveryAuthHash": "bm90LXJpZ2h0",
		}).Code
	}
	if last != http.StatusTooManyRequests {
		t.Errorf("status = %d after 8 attempts on 8 accounts from one address, want %d",
			last, http.StatusTooManyRequests)
	}
}

// TestRecoverRedemptionClearsThePreloginBudgetAsASignInDoes keeps the two
// success paths symmetrical.
//
// handleLogin resets "prelogin:<ip>" on a successful sign-in, with a reason
// written down beside it: that budget is per source address and is spent on
// every call, so a household behind one NAT address is throttled after twenty
// and told nothing about why. A redeemed recovery code is at least as strong a
// proof that the traffic is real. Twenty free calls makes this a hard corner to
// reach, which is exactly why the asymmetry would have sat there unnoticed.
func TestRecoverRedemptionClearsThePreloginBudgetAsASignInDoes(t *testing.T) {
	srv := newTestServer(t)
	enrollTestUser(t, srv, "person@example.com")

	// Spend the address's budget. This endpoint records on every call rather
	// than only on failure, so no failures are needed to exhaust it.
	for i := 0; i < 25; i++ {
		postJSON(t, srv, recoverPreloginPath,
			map[string]string{"email": fmt.Sprintf("probe%d@example.com", i)})
	}
	// Non-vacuity, and it is not optional: if the budget were not actually
	// exhausted here, the assertion after the redemption would pass with the
	// reset line deleted.
	spent := postJSON(t, srv, recoverPreloginPath, map[string]string{"email": "person@example.com"})
	if spent.Code != http.StatusTooManyRequests {
		t.Fatalf("prelogin status = %d before the redemption, want %d — the budget was never "+
			"spent, so nothing below is being tested", spent.Code, http.StatusTooManyRequests)
	}

	redeemRecoveryCode(t, srv, "person@example.com")

	rec := postJSON(t, srv, recoverPreloginPath, map[string]string{"email": "person@example.com"})
	if rec.Code != http.StatusOK {
		t.Errorf("prelogin status = %d after a correct recovery code was redeemed, want %d; "+
			"handleLogin clears this budget on a successful sign-in and this path has the "+
			"same claim to", rec.Code, http.StatusOK)
	}
}

// TestRecoverCompleteRotatesBothCredentialsAndRevokesEverySession is the whole
// point of the flow: the user is back in, under a password they chose, holding
// a code that opens the new blob, and every device that was signed in before is
// not.
func TestRecoverCompleteRotatesBothCredentialsAndRevokesEverySession(t *testing.T) {
	srv := newTestServer(t)
	ctx := context.Background()
	user, laptopToken := loginTestUser(t, srv, "person@example.com")

	phone := postJSON(t, srv, "/api/auth/login", map[string]string{
		"email": "person@example.com", "authHash": enrollBody()["authHash"], "deviceLabel": "phone",
	})
	if phone.Code != http.StatusOK {
		t.Fatalf("second sign-in: %d %s", phone.Code, phone.Body.String())
	}
	var phoneBody struct {
		AccessToken string `json:"accessToken"`
	}
	decodeInto(t, phone, &phoneBody)

	body := recoverCompleteBody(redeemRecoveryCode(t, srv, "person@example.com"))
	if rec := postJSON(t, srv, recoverCompletePath, body); rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d; body %s", rec.Code, http.StatusNoContent, rec.Body.String())
	}

	stored, err := srv.store.UserByID(ctx, user.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.KDFSalt.String != body["kdfSalt"] {
		t.Errorf("kdf_salt = %q, want %q", stored.KDFSalt.String, body["kdfSalt"])
	}
	if stored.ProtectedUserKey.String != body["protectedUserKey"] {
		t.Errorf("protected_user_key = %q, want the re-wrapped blob", stored.ProtectedUserKey.String)
	}
	if !auth.VerifyAuthHash(body["authHash"], stored.AuthHash.String) {
		t.Error("the new master password does not verify against the stored auth hash")
	}
	if auth.VerifyAuthHash(enrollBody()["authHash"], stored.AuthHash.String) {
		t.Error("the old master password still verifies")
	}
	if stored.RecoverySalt.String != body["recoverySalt"] {
		t.Errorf("recovery_salt = %q, want %q", stored.RecoverySalt.String, body["recoverySalt"])
	}
	if stored.RecoveryProtectedUserKey.String != body["recoveryProtectedUserKey"] {
		t.Errorf("recovery_protected_user_key = %q, want the new blob", stored.RecoveryProtectedUserKey.String)
	}
	if !auth.VerifyAuthHash(body["recoveryAuthHash"], stored.RecoveryAuthHash.String) {
		t.Error("the new recovery code does not verify against the stored recovery auth hash")
	}
	// Spec 3.6's "invalidate the old": the code just used must not still work.
	if auth.VerifyAuthHash(enrollBody()["recoveryAuthHash"], stored.RecoveryAuthHash.String) {
		t.Error("the recovery code that was just redeemed still verifies")
	}

	// Someone who has just proved they lost their password should not leave a
	// session alive on a device they may no longer control.
	sessions, err := srv.store.SessionsForUser(ctx, user.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(sessions) != 0 {
		t.Errorf("%d sessions survived the recovery, want 0", len(sessions))
	}
	for name, token := range map[string]string{"laptop": laptopToken, "phone": phoneBody.AccessToken} {
		if rec := doJSON(t, srv, http.MethodGet, "/api/account", token, nil); rec.Code != http.StatusUnauthorized {
			t.Errorf("the %s access token still works: %d", name, rec.Code)
		}
	}

	// And the user can actually get back in with what they just set.
	if rec := postJSON(t, srv, "/api/auth/login", map[string]string{
		"email": "person@example.com", "authHash": body["authHash"], "deviceLabel": "after recovery",
	}); rec.Code != http.StatusOK {
		t.Errorf("sign-in with the new master password = %d %s", rec.Code, rec.Body.String())
	}
}

func TestRecoverCompleteRejectsAReusedToken(t *testing.T) {
	srv := newTestServer(t)
	ctx := context.Background()
	user, _ := enrollTestUser(t, srv, "person@example.com")

	token := redeemRecoveryCode(t, srv, "person@example.com")
	first := recoverCompleteBody(token)
	if rec := postJSON(t, srv, recoverCompletePath, first); rec.Code != http.StatusNoContent {
		t.Fatalf("first completion: %d %s", rec.Code, rec.Body.String())
	}

	replay := recoverCompleteBody(token)
	replay["kdfSalt"] = "cmVwbGF5c2FsdHJlcGxheQ=="
	rec := postJSON(t, srv, recoverCompletePath, replay)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d; body %s", rec.Code, http.StatusUnauthorized, rec.Body.String())
	}

	// Status alone would also pass if the write had landed and only the response
	// was wrong. This is what proves the replay changed nothing.
	stored, err := srv.store.UserByID(ctx, user.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.KDFSalt.String != first["kdfSalt"] {
		t.Errorf("kdf_salt = %q, want the first completion's %q — the replay was applied",
			stored.KDFSalt.String, first["kdfSalt"])
	}
}

func TestRecoverCompleteRejectsAnExpiredToken(t *testing.T) {
	srv := newTestServer(t)
	ctx := context.Background()
	user, _ := enrollTestUser(t, srv, "person@example.com")

	_, expired, err := srv.store.CreateRecoveryToken(ctx, user.ID, -time.Minute)
	if err != nil {
		t.Fatalf("CreateRecoveryToken: %v", err)
	}
	rec := postJSON(t, srv, recoverCompletePath, recoverCompleteBody(expired))
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d; body %s", rec.Code, http.StatusUnauthorized, rec.Body.String())
	}
	stored, err := srv.store.UserByID(ctx, user.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.KDFSalt.String == recoverCompleteBody("")["kdfSalt"] {
		t.Error("an expired token rotated the master password")
	}

	// A live token minted exactly the same way completes, so the refusal above
	// was the expiry and not the fixture.
	_, live, err := srv.store.CreateRecoveryToken(ctx, user.ID, store.RecoveryTokenTTL)
	if err != nil {
		t.Fatal(err)
	}
	if rec := postJSON(t, srv, recoverCompletePath, recoverCompleteBody(live)); rec.Code != http.StatusNoContent {
		t.Errorf("a live token was refused: %d %s", rec.Code, rec.Body.String())
	}
}

// TestRecoverCompletePinsTheKDFParams keeps every account's kdf_params equal to
// the string the login prelogin decoy emits. The moment one account differs,
// asking prelogin for an address and comparing that field answers "does this
// address have an account here".
func TestRecoverCompletePinsTheKDFParams(t *testing.T) {
	srv := newTestServer(t)
	ctx := context.Background()
	user, _ := enrollTestUser(t, srv, "person@example.com")

	body := recoverCompleteBody(redeemRecoveryCode(t, srv, "person@example.com"))
	body["params"] = `{"algorithm":"argon2id","memoryKiB":16384,"iterations":2,"parallelism":1}`

	before := auth.Argon2Calls()
	rec := postJSON(t, srv, recoverCompletePath, body)
	spent := auth.Argon2Calls() - before

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d; body %s", rec.Code, http.StatusBadRequest, rec.Body.String())
	}
	// Byte equality is checkable before anything expensive happens, and this is
	// an unauthenticated endpoint that otherwise runs two 64 MiB Argon2id
	// computations per call.
	if spent != 0 {
		t.Errorf("unpinned params cost %d Argon2id computations, want 0", spent)
	}
	stored, err := srv.store.UserByID(ctx, user.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.KDFParams.String != auth.DefaultKDFParamsJSON {
		t.Errorf("kdf_params = %q, want %q", stored.KDFParams.String, auth.DefaultKDFParamsJSON)
	}
}

// TestRecoverCompletePinsTheRecoveryKDFParams is the kdf_params pin's twin for
// the column this endpoint's own prelogin hands out.
//
// handleRecoverPrelogin answers an unknown address with
// auth.DefaultKDFParamsJSON. A completed recovery writes a fresh recovery blob,
// so it is a place a divergent value could enter — and one account whose
// recovery_kdf_params differs makes that address answerable by comparison, which
// is precisely the oracle the decoy exists to close.
func TestRecoverCompletePinsTheRecoveryKDFParams(t *testing.T) {
	srv := newTestServer(t)
	ctx := context.Background()
	user, _ := enrollTestUser(t, srv, "person@example.com")

	body := recoverCompleteBody(redeemRecoveryCode(t, srv, "person@example.com"))
	// Semantically identical to the default, byte-different.
	body["recoveryKdfParams"] = `{"algorithm":"argon2id","iterations":3,"memoryKiB":65536,"parallelism":4}`

	before := auth.Argon2Calls()
	rec := postJSON(t, srv, recoverCompletePath, body)
	spent := auth.Argon2Calls() - before

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d; body %s", rec.Code, http.StatusBadRequest, rec.Body.String())
	}
	// Same reasoning as the params pin above: this is an unauthenticated
	// endpoint that otherwise runs two 64 MiB Argon2id computations per call,
	// and a byte comparison is checkable before any of that.
	if spent != 0 {
		t.Errorf("unpinned recoveryKdfParams cost %d Argon2id computations, want 0", spent)
	}
	stored, err := srv.store.UserByID(ctx, user.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.RecoveryKDFParams.String != auth.DefaultKDFParamsJSON {
		t.Errorf("recovery_kdf_params = %q, want %q",
			stored.RecoveryKDFParams.String, auth.DefaultKDFParamsJSON)
	}
	if stored.RecoveryProtectedUserKey.String == body["recoveryProtectedUserKey"] {
		t.Error("the rejected completion wrote its recovery blob anyway")
	}
}

// TestRecoverCompleteRewritesOnlyTheAccountItsTokenWasMintedFor is the plan's
// "a token minted for one user must not complete a recovery for another". The
// request names no user, so the property is that the token alone decides whose
// account is rewritten — and everyone else's credentials and sessions survive.
func TestRecoverCompleteRewritesOnlyTheAccountItsTokenWasMintedFor(t *testing.T) {
	srv := newTestServer(t)
	ctx := context.Background()

	recovering, _ := enrollTestUser(t, srv, "recovering@example.com")
	bystander, bystanderToken := loginTestUser(t, srv, "bystander@example.com")

	body := recoverCompleteBody(redeemRecoveryCode(t, srv, "recovering@example.com"))
	if rec := postJSON(t, srv, recoverCompletePath, body); rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d; body %s", rec.Code, http.StatusNoContent, rec.Body.String())
	}

	rewritten, err := srv.store.UserByID(ctx, recovering.ID)
	if err != nil {
		t.Fatal(err)
	}
	if rewritten.KDFSalt.String != body["kdfSalt"] {
		t.Fatalf("the token's own account was not rewritten: kdf_salt = %q", rewritten.KDFSalt.String)
	}

	untouched, err := srv.store.UserByID(ctx, bystander.ID)
	if err != nil {
		t.Fatal(err)
	}
	if untouched.KDFSalt.String != enrollBody()["kdfSalt"] {
		t.Errorf("a bystander's kdf_salt changed: %q", untouched.KDFSalt.String)
	}
	if !auth.VerifyAuthHash(enrollBody()["authHash"], untouched.AuthHash.String) {
		t.Error("a bystander's master password stopped verifying")
	}
	if !auth.VerifyAuthHash(enrollBody()["recoveryAuthHash"], untouched.RecoveryAuthHash.String) {
		t.Error("a bystander's recovery code stopped verifying")
	}
	// One household member recovering must not sign the rest of the house out.
	if rec := doJSON(t, srv, http.MethodGet, "/api/account", bystanderToken, nil); rec.Code != http.StatusOK {
		t.Errorf("a bystander's session was revoked: %d", rec.Code)
	}
}

// TestRecoverCompleteRefusesAnUnknownTokenWithoutHashing keeps the endpoint
// from being a free Argon2id oracle: it is unauthenticated, its only input is a
// caller-chosen token, and it hashes two credentials per call.
func TestRecoverCompleteRefusesAnUnknownTokenWithoutHashing(t *testing.T) {
	srv := newTestServer(t)

	before := auth.Argon2Calls()
	rec := postJSON(t, srv, recoverCompletePath, recoverCompleteBody("not-a-real-token"))
	spent := auth.Argon2Calls() - before

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d; body %s", rec.Code, http.StatusUnauthorized, rec.Body.String())
	}
	if spent != 0 {
		t.Errorf("an unknown recovery token cost %d Argon2id computations, want 0", spent)
	}
}
