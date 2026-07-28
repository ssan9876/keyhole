package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
)

const sessionTokenBytes = 32

// NewToken returns a 256-bit opaque token, base64url encoded without padding.
// Opaque rather than a JWT: revocation is a DELETE instead of a blocklist, and
// the token carries no claims a client could read or an attacker could forge.
func NewToken() (string, error) {
	buf := make([]byte, sessionTokenBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generate token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// DefaultKDFParamsJSON is what prelogin reports for an address with no
// account. It must match what a real enrollment would use, or the shape of the
// response would itself distinguish real accounts from decoys.
const DefaultKDFParamsJSON = `{"algorithm":"argon2id","memoryKiB":65536,"iterations":3,"parallelism":4}`

// DecoySalt derives a stable fake salt for an unknown address.
//
// It must be deterministic: an address that returned one salt and then another
// on retry would reveal, by inconsistency, that no account exists. Keying it
// with the server secret stops an attacker computing the decoy offline and
// comparing it against a live response.
func DecoySalt(serverSecret []byte, normalizedEmail string) string {
	return decoySalt(serverSecret, "keyhole:decoy-salt:v1", normalizedEmail)
}

// DecoyRecoverySalt is DecoySalt for the recovery prelogin endpoint.
//
// It is a separate value on purpose. A real account holds two independent
// random salts — one for the master password, one for the recovery blob — so
// its two prelogin answers differ. Were both endpoints to decoy an unknown
// address with the same derived value, asking both and comparing them would
// answer "does this address have an account here", which is the one question
// the decoys exist to refuse. The domain string below is what keeps them apart.
func DecoyRecoverySalt(serverSecret []byte, normalizedEmail string) string {
	return decoySalt(serverSecret, "keyhole:decoy-recovery-salt:v1", normalizedEmail)
}

func decoySalt(serverSecret []byte, domain, normalizedEmail string) string {
	mac := hmac.New(sha256.New, serverSecret)
	mac.Write([]byte(domain))
	mac.Write([]byte(normalizedEmail))
	// 16 bytes, matching a real salt exactly.
	return base64.StdEncoding.EncodeToString(mac.Sum(nil)[:16])
}
