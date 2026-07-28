//go:build !unix

package backup

import "os"

// chownLike is a deliberate no-op on platforms with no POSIX file owner.
//
// Windows is the one that matters here: os.Chown exists but only ever
// returns EWINDOWS, and os.FileInfo.Sys() carries no uid or gid to copy
// forward. Returning that error would fail every restore on a developer
// machine over a detail the platform does not have. Keyhole is installed on
// Linux, which is where the owner is load-bearing and where owner_unix.go
// carries it across.
func chownLike(path string, info os.FileInfo) error { return nil }
