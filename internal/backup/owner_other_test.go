//go:build !unix

package backup

import "testing"

// The same name as the test in owner_unix_test.go, deliberately: on this
// platform the assertion cannot be made, and saying so out loud is better
// than a package where `go test` reports one fewer test on Windows than on
// Linux and nothing explains the difference.
func TestRestorePreservesTheDatabasesOwner(t *testing.T) {
	t.Skip("file ownership is a POSIX uid/gid concept this platform does not have: " +
		"os.FileInfo.Sys() carries no owner to compare and os.Chown only returns EWINDOWS. " +
		"Restore's chownLike is a no-op here (owner_other.go). The real assertion runs on " +
		"every unix platform, including the ubuntu-latest runner that CI uses.")
}
