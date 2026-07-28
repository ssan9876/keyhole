// Package release implements `keyhole update`: fetching the latest published
// release, verifying it against a signed checksum list, and installing it
// with an automatic rollback if the new binary does not come up healthy.
//
// Everything that touches the outside world -- the network, systemd, the
// running server's health -- sits behind an interface (Source, Service,
// Health). That is what lets the riskiest part of this package, Update's
// rollback path, be driven entirely by fakes in a test: no network, no
// systemd, no real binary.
package release

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	"aead.dev/minisign"
)

// Release describes one published Keyhole release.
type Release struct {
	Version string
	Notes   string
	// Assets maps a published filename (e.g. "keyhole-linux-amd64",
	// "SHA256SUMS", "SHA256SUMS.minisig") to the URL it can be downloaded
	// from.
	Assets map[string]string
}

// Source fetches release metadata and downloads release assets. The only
// implementation that talks to the network is githubSource in
// cmd/keyhole/update.go; every test drives Update with a fake.
type Source interface {
	Latest(ctx context.Context) (Release, error)
	Download(ctx context.Context, url string) ([]byte, error)
}

// Verify checks a downloaded binary against a signed checksum list.
//
// The signature covers SHA256SUMS rather than the binary itself, which is
// what lets one signature cover every architecture in a release. That only
// holds if both halves are checked: the signature proves the checksum list
// is ours, and the list's line for this exact filename proves these bytes
// are the ones we published. Either check alone is worthless -- a valid
// signature over a list that never mentions this file says nothing about
// it, and a checksum matched against an unsigned list proves nothing at
// all. So the signature is checked first, then the checksum line, and a
// missing line is a hard error rather than a pass-through.
func Verify(binary []byte, checksums string, signature []byte, publicKey string, filename string) error {
	var key minisign.PublicKey
	if err := key.UnmarshalText([]byte(publicKey)); err != nil {
		return fmt.Errorf("parse public key: %w", err)
	}
	if !minisign.Verify(key, []byte(checksums), signature) {
		return errors.New("the release signature is not valid for these checksums")
	}

	want, ok := checksumFor(checksums, filename)
	if !ok {
		return fmt.Errorf("the signed checksum list has no entry for %s", filename)
	}

	sum := sha256.Sum256(binary)
	got := hex.EncodeToString(sum[:])
	if subtle.ConstantTimeCompare([]byte(got), []byte(want)) != 1 {
		return fmt.Errorf("checksum mismatch for %s", filename)
	}
	return nil
}

// checksumFor parses the standard `sha256sum` output format -- 64 hex
// characters, then a separator ("  " for text mode or " *" for binary
// mode), then the filename, one entry per line -- and returns the checksum
// for the line whose basename matches filename's basename.
//
// Lines that do not fit that shape are ignored rather than treated as an
// error: a signed SHA256SUMS legitimately lists one line per architecture,
// and this file only cares about its own. A checksum list that never
// mentions filename at all returns ok=false; Verify turns that into a hard
// error rather than treating "nothing to compare" as "fine."
func checksumFor(checksums, filename string) (sum string, ok bool) {
	base := filepath.Base(filename)
	for _, raw := range strings.Split(checksums, "\n") {
		line := strings.TrimRight(raw, "\r")
		if len(line) < 64+2+1 {
			continue
		}
		hexPart := line[:64]
		if !isHexDigits(hexPart) {
			continue
		}
		sep := line[64:66]
		if sep != "  " && sep != " *" {
			continue
		}
		name := line[66:]
		if filepath.Base(name) == base {
			return strings.ToLower(hexPart), true
		}
	}
	return "", false
}

func isHexDigits(s string) bool {
	for _, r := range s {
		switch {
		case r >= '0' && r <= '9':
		case r >= 'a' && r <= 'f':
		case r >= 'A' && r <= 'F':
		default:
			return false
		}
	}
	return true
}
