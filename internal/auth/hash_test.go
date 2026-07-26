package auth

import (
	"strings"
	"testing"
)

const sampleAuthHash = "eXQ1Zm9vYmFyYmF6cXV4MTIzNDU2Nzg5MGFiY2RlZg=="

func TestHashAuthHashShape(t *testing.T) {
	encoded, err := HashAuthHash(sampleAuthHash)
	if err != nil {
		t.Fatalf("HashAuthHash: %v", err)
	}
	parts := strings.Split(encoded, "$")
	if len(parts) != 3 {
		t.Fatalf("encoded = %q, want three $-separated parts", encoded)
	}
	if parts[0] != "argon2id" {
		t.Errorf("algorithm = %q, want %q", parts[0], "argon2id")
	}
	// The client's auth hash must not be recoverable from what we store.
	if strings.Contains(encoded, sampleAuthHash) {
		t.Error("the encoded form contains the auth hash verbatim")
	}
}

func TestHashAuthHashUsesAFreshSaltEveryTime(t *testing.T) {
	first, err := HashAuthHash(sampleAuthHash)
	if err != nil {
		t.Fatal(err)
	}
	second, err := HashAuthHash(sampleAuthHash)
	if err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Error("two hashes of the same input are identical; the salt is not random")
	}
}

func TestVerifyAuthHashAcceptsTheOriginal(t *testing.T) {
	encoded, err := HashAuthHash(sampleAuthHash)
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyAuthHash(sampleAuthHash, encoded) {
		t.Error("VerifyAuthHash rejected the value it just hashed")
	}
}

func TestVerifyAuthHashRejectsAnythingElse(t *testing.T) {
	encoded, err := HashAuthHash(sampleAuthHash)
	if err != nil {
		t.Fatal(err)
	}
	for name, candidate := range map[string]string{
		"different value": "not-the-auth-hash",
		"empty":           "",
		"prefix":          sampleAuthHash[:len(sampleAuthHash)-1],
	} {
		t.Run(name, func(t *testing.T) {
			if VerifyAuthHash(candidate, encoded) {
				t.Error("VerifyAuthHash accepted a value it should not have")
			}
		})
	}
}

func TestVerifyAuthHashRejectsMalformedStoredValues(t *testing.T) {
	// A corrupted or empty column must fail closed, never panic and never
	// accidentally accept.
	for name, encoded := range map[string]string{
		"empty":             "",
		"no separators":     "argon2id",
		"wrong algorithm":   "bcrypt$c2FsdA==$aGFzaA==",
		"bad base64 salt":   "argon2id$!!!$aGFzaA==",
		"bad base64 digest": "argon2id$c2FsdA==$!!!",
		"too many parts":    "argon2id$a$b$c",
	} {
		t.Run(name, func(t *testing.T) {
			if VerifyAuthHash(sampleAuthHash, encoded) {
				t.Errorf("VerifyAuthHash accepted a malformed stored value %q", encoded)
			}
		})
	}
}
