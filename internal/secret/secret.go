// Package secret manages the server's long-lived secret key.
//
// It is used only for keyed hashing that must stay stable across restarts —
// today, the decoy KDF salts that make prelogin useless for account
// enumeration. It is never a vault key: no amount of access to it lets anyone
// decrypt anything a user stored.
package secret

import (
	"crypto/rand"
	"fmt"
	"os"
	"path/filepath"
)

const secretBytes = 32

// LoadOrCreate reads the secret at path, generating one on first run.
//
// A short or unreadable file is an error rather than a prompt to regenerate:
// a new secret changes every decoy salt the server issues, and doing that
// silently would turn a corrupted file into a subtle behaviour change nobody
// notices.
func LoadOrCreate(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	switch {
	case err == nil:
		if len(data) != secretBytes {
			return nil, fmt.Errorf("server secret at %s is %d bytes, want %d; refusing to regenerate", path, len(data), secretBytes)
		}
		return data, nil
	case !os.IsNotExist(err):
		return nil, fmt.Errorf("read server secret: %w", err)
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("create secret directory: %w", err)
	}

	buf := make([]byte, secretBytes)
	if _, err := rand.Read(buf); err != nil {
		return nil, fmt.Errorf("generate server secret: %w", err)
	}
	if err := os.WriteFile(path, buf, 0o600); err != nil {
		return nil, fmt.Errorf("write server secret: %w", err)
	}
	return buf, nil
}
