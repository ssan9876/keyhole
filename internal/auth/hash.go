// Package auth handles credential verification and session tokens.
//
// The value it hashes is the client's auth hash, not a password: the master
// password never reaches the server. Hashing it again server-side means a
// database dump yields nothing a caller could present at the login endpoint.
package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

// Server-side Argon2id parameters. Unrelated to the per-user client KDF
// params, which the server only stores and echoes back at prelogin.
const (
	argonTime    = 3
	argonMemory  = 64 * 1024 // KiB
	argonThreads = 4
	argonKeyLen  = 32
	argonSaltLen = 16
)

// HashAuthHash returns "argon2id$<base64 salt>$<base64 digest>".
func HashAuthHash(authHash string) (string, error) {
	salt := make([]byte, argonSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("generate salt: %w", err)
	}
	digest := argon2.IDKey([]byte(authHash), salt, argonTime, argonMemory, argonThreads, argonKeyLen)

	return fmt.Sprintf("argon2id$%s$%s",
		base64.StdEncoding.EncodeToString(salt),
		base64.StdEncoding.EncodeToString(digest),
	), nil
}

// VerifyAuthHash reports whether authHash produces the stored digest.
//
// It returns false for every malformed stored value rather than reporting a
// parse error: a caller that distinguished "wrong credential" from "corrupt
// row" would leak which accounts exist.
func VerifyAuthHash(authHash, encoded string) bool {
	parts := strings.Split(encoded, "$")
	if len(parts) != 3 || parts[0] != "argon2id" {
		return false
	}
	salt, err := base64.StdEncoding.DecodeString(parts[1])
	if err != nil || len(salt) == 0 {
		return false
	}
	want, err := base64.StdEncoding.DecodeString(parts[2])
	if err != nil || len(want) == 0 {
		return false
	}

	got := argon2.IDKey([]byte(authHash), salt, argonTime, argonMemory, argonThreads, uint32(len(want)))
	return subtle.ConstantTimeCompare(got, want) == 1
}
