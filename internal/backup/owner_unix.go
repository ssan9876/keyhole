//go:build unix

package backup

import (
	"fmt"
	"os"
	"syscall"
)

// chownLike gives path the uid and gid recorded in info.
//
// This file is split by build tag rather than guarded with a runtime.GOOS
// check because the guard would not be enough to compile: syscall.Stat_t
// does not exist on Windows, so the type assertion below cannot appear in a
// file that platform builds. os.Chown is in the same position -- it exists
// there, but only to return EWINDOWS.
//
// A Sys() that is not a *syscall.Stat_t is treated as "this platform does
// not report an owner" rather than an error: there is nothing to copy, and
// failing the restore over it would turn a missing detail into a vault that
// stays down.
func chownLike(path string, info os.FileInfo) error {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return nil
	}
	if err := os.Chown(path, int(st.Uid), int(st.Gid)); err != nil {
		return fmt.Errorf("restore ownership %d:%d on %s: %w", st.Uid, st.Gid, path, err)
	}
	return nil
}
