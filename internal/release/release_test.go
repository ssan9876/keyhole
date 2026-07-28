package release

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"

	"aead.dev/minisign"
)

// genMinisignKeypair generates a real minisign keypair for a test, returning
// the private key to sign with and the public key in the text form Verify
// expects. A hand-written fixture cannot prove the verifier accepts what the
// release workflow actually produces -- only a real keypair signing a real
// message can.
func genMinisignKeypair(t *testing.T) (priv minisign.PrivateKey, pubText string) {
	t.Helper()
	pub, priv, err := minisign.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("minisign.GenerateKey: %v", err)
	}
	text, err := pub.MarshalText()
	if err != nil {
		t.Fatalf("marshal public key: %v", err)
	}
	return priv, string(text)
}

// sumLine renders one line of `sha256sum`-format output for data under name.
func sumLine(name string, data []byte) string {
	sum := sha256.Sum256(data)
	return fmt.Sprintf("%s  %s\n", hex.EncodeToString(sum[:]), name)
}

func TestVerifyAcceptsAGenuineSignatureAndChecksum(t *testing.T) {
	priv, pubText := genMinisignKeypair(t)
	binary := []byte("pretend keyhole binary contents for linux/amd64")
	checksums := sumLine("keyhole-linux-amd64", binary) + sumLine("keyhole-darwin-arm64", []byte("a different binary"))
	signature := minisign.Sign(priv, []byte(checksums))

	if err := Verify(binary, checksums, signature, pubText, "keyhole-linux-amd64"); err != nil {
		t.Fatalf("Verify() = %v, want nil for a genuine signature and matching checksum", err)
	}
}

func TestVerifyRejectsATamperedBinary(t *testing.T) {
	priv, pubText := genMinisignKeypair(t)
	binary := []byte("pretend keyhole binary contents for linux/amd64")
	checksums := sumLine("keyhole-linux-amd64", binary)
	signature := minisign.Sign(priv, []byte(checksums))

	// Flip one byte of the binary. The signature over SHA256SUMS is still
	// valid -- it never covered the binary's bytes directly -- which is
	// exactly the attack the checksum step exists to catch.
	tampered := append([]byte(nil), binary...)
	tampered[0] ^= 0xFF

	err := Verify(tampered, checksums, signature, pubText, "keyhole-linux-amd64")
	if err == nil {
		t.Fatal("Verify() = nil, want an error: the binary no longer matches the signed checksum")
	}
}

func TestVerifyRejectsATamperedChecksumFile(t *testing.T) {
	priv, pubText := genMinisignKeypair(t)
	binary := []byte("pretend keyhole binary contents for linux/amd64")
	checksums := sumLine("keyhole-linux-amd64", binary)
	signature := minisign.Sign(priv, []byte(checksums))

	tampered := append([]byte(nil), binary...)
	tampered[0] ^= 0xFF
	// Rewrite SHA256SUMS to match the tampered binary. The checksum now
	// matches, but the signature -- computed over the original checksums
	// text -- does not match this rewritten text. This is the other half
	// of the attack: a tampered checksum list paired with a stale, still
	// "valid" signature over different bytes.
	rewrittenChecksums := sumLine("keyhole-linux-amd64", tampered)

	err := Verify(tampered, rewrittenChecksums, signature, pubText, "keyhole-linux-amd64")
	if err == nil {
		t.Fatal("Verify() = nil, want an error: the signature does not cover the rewritten checksum list")
	}
}

func TestVerifyRejectsASignatureFromADifferentKey(t *testing.T) {
	_, pubText := genMinisignKeypair(t)
	otherPriv, _ := genMinisignKeypair(t)
	binary := []byte("pretend keyhole binary contents for linux/amd64")
	checksums := sumLine("keyhole-linux-amd64", binary)
	// Signed by a key other than the one Verify is told to trust.
	signature := minisign.Sign(otherPriv, []byte(checksums))

	err := Verify(binary, checksums, signature, pubText, "keyhole-linux-amd64")
	if err == nil {
		t.Fatal("Verify() = nil, want an error for a signature made with a different private key")
	}
}

func TestVerifyRejectsAChecksumFileWithNoLineForThisFile(t *testing.T) {
	priv, pubText := genMinisignKeypair(t)
	binary := []byte("pretend keyhole binary contents for linux/amd64")
	// A genuinely signed SHA256SUMS -- but from a release that names only
	// other files, never this one. Falling through to "no line, nothing
	// to compare, fine" would accept any binary at all under this name.
	checksums := sumLine("keyhole-darwin-arm64", []byte("a different binary")) +
		sumLine("keyhole-windows-amd64", []byte("yet another binary"))
	signature := minisign.Sign(priv, []byte(checksums))

	err := Verify(binary, checksums, signature, pubText, "keyhole-linux-amd64")
	if err == nil {
		t.Fatal("Verify() = nil, want an error: the signed checksum list never mentions keyhole-linux-amd64")
	}
}

func TestChecksumForMatchesOnBasenameAndIgnoresUnrecognizedLines(t *testing.T) {
	binary := []byte("pretend keyhole binary contents")
	sum := sha256.Sum256(binary)
	want := hex.EncodeToString(sum[:])

	// Every junk line below names the *same* file the real line does, and
	// each is long enough to survive the length check. That is deliberate:
	// if any one of them were accepted, checksumFor would return its
	// garbage instead of the real digest further down, so each line proves
	// one specific guard is load-bearing rather than merely present.
	notHex := strings.Repeat("z", 64)           // 64 chars, right shape, not hex
	wrongSep := want + "\t keyhole-linux-amd64" // valid digest, "\t " instead of the two-space separator

	checksums := "not a checksum line at all\n" +
		"deadbeef  too-short-to-be-a-real-hex-digest\n" +
		notHex + "  keyhole-linux-amd64\n" +
		wrongSep + "\n" +
		want + "  /some/build/path/keyhole-linux-amd64\n"

	got, ok := checksumFor(checksums, "keyhole-linux-amd64")
	if !ok {
		t.Fatal("checksumFor() ok = false, want true: a valid line for this basename is present")
	}
	// Matching on the basename is what lets a SHA256SUMS generated in a
	// build directory ("/some/build/path/keyhole-linux-amd64") still match
	// the asset name we downloaded.
	if got != want {
		t.Errorf("checksumFor() = %q, want %q (the real digest, not a malformed earlier line)", got, want)
	}

	if _, ok := checksumFor(checksums, "keyhole-darwin-arm64"); ok {
		t.Error("checksumFor() ok = true for a filename with no matching line, want false")
	}
}

// TestChecksumForIgnoresALineWhoseDigestIsNotHex pins the isHexDigits guard
// on its own. Without it a 64-character non-hex line would be returned as a
// digest and shadow the genuine line for the same file -- turning a
// malformed SHA256SUMS into a checksum mismatch rather than a correct match.
func TestChecksumForIgnoresALineWhoseDigestIsNotHex(t *testing.T) {
	notHex := strings.Repeat("z", 64)
	if got, ok := checksumFor(notHex+"  keyhole-linux-amd64\n", "keyhole-linux-amd64"); ok {
		t.Errorf("checksumFor() = %q, ok = true for a non-hex digest, want ok = false", got)
	}
}

// TestChecksumForIgnoresALineWithTheWrongSeparator pins the separator guard.
// sha256sum writes exactly two spaces (text mode) or " *" (binary mode);
// anything else means the line was not produced by the tool whose format
// this parser is built around, so its digest is not trustworthy.
//
// The separator here is two characters ("\t ") on purpose, so the filename
// still begins at exactly offset 66 and the basename still matches. A
// one-character separator would shift the name by one and be rejected for
// having the wrong *name*, which would leave this guard untested while
// looking like it passed.
func TestChecksumForIgnoresALineWithTheWrongSeparator(t *testing.T) {
	digest := strings.Repeat("a", 64)
	line := digest + "\t keyhole-linux-amd64\n"
	if got, ok := checksumFor(line, "keyhole-linux-amd64"); ok {
		t.Errorf("checksumFor() = %q, ok = true for a %q separator, want ok = false", got, "\t ")
	}
}

// TestChecksumForAcceptsBinaryModeSeparator covers the other half of the
// separator rule: sha256sum -b writes " *", and a release workflow that used
// it must still verify rather than be rejected as malformed.
func TestChecksumForAcceptsBinaryModeSeparator(t *testing.T) {
	digest := strings.Repeat("a", 64)
	got, ok := checksumFor(digest+" *keyhole-linux-amd64\n", "keyhole-linux-amd64")
	if !ok {
		t.Fatal("checksumFor() ok = false for a binary-mode (\" *\") line, want true")
	}
	if got != digest {
		t.Errorf("checksumFor() = %q, want %q", got, digest)
	}
}
