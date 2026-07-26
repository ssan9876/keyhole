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
	"runtime"
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

// argon2Semaphore bounds how many Argon2id computations run at once.
//
// Every call to argon2.IDKey allocates argonMemory — 64 MiB — for its lifetime,
// and net/http imposes no ceiling on concurrent handlers. Unbounded, a few
// hundred simultaneous requests to an unauthenticated endpoint are roughly
// 12 GB of live allocation and an OOM kill on the household machine that is the
// only way to reach the vault. No amount of rate limiting closes this on its
// own: a limiter's Allow runs before the hash and its RecordFailure after, so N
// requests arriving together all pass before any of them records anything.
//
// Queuing, rather than rejecting, is the right behaviour for a deliberately
// slow function. Callers already expect to wait ~50 ms; under load they wait
// longer, and peak memory stays at NumCPU x 64 MiB whatever the request volume.
// Sizing at NumCPU also means the machine is never asked to run more of a
// CPU-bound computation than it has cores to run it on.
//
// This is package-level on purpose: every Argon2id entry point in the server
// must share one budget, or a second endpoint reintroduces the whole problem.
var argon2Semaphore = make(chan struct{}, runtime.NumCPU())

// argon2Key is the single point at which this package performs Argon2id, so the
// bound above cannot be bypassed by a new caller forgetting to take a slot.
func argon2Key(password, salt []byte, keyLen uint32) []byte {
	argon2Semaphore <- struct{}{}
	defer func() { <-argon2Semaphore }()
	return argon2.IDKey(password, salt, argonTime, argonMemory, argonThreads, keyLen)
}

// HashAuthHash returns "argon2id$<base64 salt>$<base64 digest>".
func HashAuthHash(authHash string) (string, error) {
	salt := make([]byte, argonSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("generate salt: %w", err)
	}
	digest := argon2Key([]byte(authHash), salt, argonKeyLen)

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

	got := argon2Key([]byte(authHash), salt, uint32(len(want)))
	return subtle.ConstantTimeCompare(got, want) == 1
}
