package store

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

// ErrNotFound means the row does not exist, or exists in a state the caller
// should treat as absent (a used or expired invite, for instance).
var ErrNotFound = errors.New("not found")

// ErrEmailTaken means an account already exists for that address.
var ErrEmailTaken = errors.New("email already registered")

// ErrRevisionConflict means the caller edited from a revision that is no
// longer current. The write is refused rather than applied: the losing edit
// still exists on the client that made it, which is what lets it become a
// conflicted copy instead of silently vanishing.
var ErrRevisionConflict = errors.New("row was modified by someone else")

const idBytes = 16

// NewID returns a 32-character lowercase hex identifier from 16 random bytes.
func NewID() (string, error) {
	buf := make([]byte, idBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generate id: %w", err)
	}
	return hex.EncodeToString(buf), nil
}

// NormalizeEmail is the single definition of "the same address". Used both
// before storage and before lookup, so the two can never disagree.
func NormalizeEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}

// HashToken is the at-rest form of session and invite tokens. A database dump
// must not yield anything a caller could present as a credential.
func HashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// ErrUserReferenced means the account cannot be deleted because other records
// point at it — a collection it created, or a membership it granted. Those
// references have no ON DELETE action on purpose: deleting an admin must not
// cascade into destroying a shared collection's key material, which nobody
// could reconstruct.
var ErrUserReferenced = errors.New("user is referenced by other records")

// ErrLastAdmin means the action would leave the installation with no
// administrator, and therefore no way to create one.
var ErrLastAdmin = errors.New("this is the last administrator")
