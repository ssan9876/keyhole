package auth

import (
	"encoding/base64"
	"testing"
)

func TestNewTokenIs256BitsOfBase64URL(t *testing.T) {
	token, err := NewToken()
	if err != nil {
		t.Fatalf("NewToken: %v", err)
	}
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		t.Fatalf("token is not raw base64url: %v", err)
	}
	if len(raw) != 32 {
		t.Errorf("decoded length = %d, want 32", len(raw))
	}
}

func TestNewTokenDoesNotRepeat(t *testing.T) {
	seen := make(map[string]bool, 500)
	for i := 0; i < 500; i++ {
		token, err := NewToken()
		if err != nil {
			t.Fatal(err)
		}
		if seen[token] {
			t.Fatalf("NewToken returned a duplicate")
		}
		seen[token] = true
	}
}

func TestDecoySaltIsStableForTheSameAddress(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789abcdef")

	// Stability across calls is the whole point: an address that answered with
	// one salt and then another would announce, by that inconsistency alone,
	// that no account exists behind it.
	first := DecoySalt(secret, "ghost@example.com")
	second := DecoySalt(secret, "ghost@example.com")
	if first != second {
		t.Errorf("DecoySalt is not deterministic: %q then %q", first, second)
	}
}

func TestDecoySaltDiffersByAddressAndBySecret(t *testing.T) {
	secretA := []byte("0123456789abcdef0123456789abcdef")
	secretB := []byte("fedcba9876543210fedcba9876543210")

	if DecoySalt(secretA, "a@example.com") == DecoySalt(secretA, "b@example.com") {
		t.Error("two addresses produced the same decoy salt")
	}
	// Keying by the server secret stops an attacker computing the decoy
	// offline and comparing it against a live response.
	if DecoySalt(secretA, "a@example.com") == DecoySalt(secretB, "a@example.com") {
		t.Error("the decoy salt does not depend on the server secret")
	}
}

func TestDecoySaltIsIndistinguishableFromARealSaltByLength(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789abcdef")

	raw, err := base64.StdEncoding.DecodeString(DecoySalt(secret, "ghost@example.com"))
	if err != nil {
		t.Fatalf("decoy salt is not standard base64: %v", err)
	}
	// A real KDF salt is 16 bytes. A decoy of any other length would let a
	// caller distinguish real accounts from absent ones by inspection.
	if len(raw) != 16 {
		t.Errorf("decoy salt decodes to %d bytes, want 16 to match a real KDF salt", len(raw))
	}
}

func TestDefaultKDFParamsJSONMatchesTheSpec(t *testing.T) {
	want := `{"algorithm":"argon2id","memoryKiB":65536,"iterations":3,"parallelism":4}`
	// If this drifts from what a real enrollment stores, the params field
	// itself distinguishes a decoy response from a real one.
	if DefaultKDFParamsJSON != want {
		t.Errorf("DefaultKDFParamsJSON = %q, want %q", DefaultKDFParamsJSON, want)
	}
}
