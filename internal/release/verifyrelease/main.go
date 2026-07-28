// Command verifyrelease checks a directory of built release assets with the
// exact code an installed server will run against them: internal/release.Verify,
// backed by whatever version of aead.dev/minisign go.mod pins.
//
// The release workflow's other self-check, `minisign -Vm`, proves that C
// minisign accepts C minisign's own output. That is not the question. The
// verifier that decides whether a release is installable is this one -- a
// different implementation, in a different language, on its own release
// schedule. A C minisign that changed its default signature algorithm, or an
// aead.dev/minisign bump that tightened a parser, would sail past every other
// step in the workflow and then be rejected by `keyhole update` on every
// installed server, months later, mid-update, with the service already
// stopped. Running the shipped verifier over the real bytes before publishing
// them is what turns that into a failed release job instead.
//
// Usage:
//
//	KEYHOLE_RELEASE_DIR=dist MINISIGN_PUBLIC_KEY=<base64 line> \
//	  go run ./internal/release/verifyrelease keyhole-linux-amd64 keyhole-linux-arm64
//
// The public key comes from the environment in the single-line form -ldflags
// embeds into the binaries, so this checks the same key text the shipped
// binary will hold, not a prettier variant of it. Every failure -- a missing
// asset, an unparseable key, a bad signature, a checksum mismatch -- exits
// non-zero on the spot.
package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/ssan9876/keyhole/internal/release"
)

// The names internal/release looks up in a published release. They are an
// interface, not a convention: install.go's checksumsAsset and signatureAsset
// hold the same two strings, and the release workflow uploads them under
// these names. Renaming any of them breaks every existing installation's
// `keyhole update`, so this program hard-codes them on purpose -- if the
// workflow ever produces something else, this step is where it shows up.
const (
	checksumsName = "SHA256SUMS"
	signatureName = "SHA256SUMS.minisig"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "verifyrelease: %v\n", err)
		os.Exit(1)
	}
}

func run(names []string) error {
	dir := os.Getenv("KEYHOLE_RELEASE_DIR")
	if dir == "" {
		return errors.New("set KEYHOLE_RELEASE_DIR to the directory holding the built release assets")
	}
	publicKey := os.Getenv("MINISIGN_PUBLIC_KEY")
	if publicKey == "" {
		return errors.New("set MINISIGN_PUBLIC_KEY to the public key the release was signed with")
	}
	// A run with no asset names would verify nothing and exit 0 -- exactly
	// the shape of guard this program exists to replace.
	if len(names) == 0 {
		return errors.New("name at least one asset to verify, e.g. keyhole-linux-amd64")
	}

	checksums, err := os.ReadFile(filepath.Join(dir, checksumsName))
	if err != nil {
		return fmt.Errorf("read %s: %w", checksumsName, err)
	}
	signature, err := os.ReadFile(filepath.Join(dir, signatureName))
	if err != nil {
		return fmt.Errorf("read %s: %w", signatureName, err)
	}

	for _, name := range names {
		binary, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			return fmt.Errorf("read %s: %w", name, err)
		}
		if err := release.Verify(binary, string(checksums), signature, publicKey, name); err != nil {
			return fmt.Errorf("verify %s: %w", name, err)
		}
		fmt.Printf("verified %s: signature over %s is valid for this key, and %s names these bytes\n",
			name, checksumsName, checksumsName)
	}
	return nil
}
