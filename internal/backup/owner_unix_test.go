//go:build unix

package backup

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

type fileOwner struct{ uid, gid uint32 }

func ownerOf(t *testing.T, path string) fileOwner {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatalf("stat %s: Sys() is %T, not *syscall.Stat_t", path, info.Sys())
	}
	return fileOwner{uid: st.Uid, gid: st.Gid}
}

// giveTheDatabaseAnOwnerThisProcessWouldNotCreate is what makes the test
// below able to fail. Restore copies the snapshot into a newly created file,
// which the kernel gives this process's own uid and gid -- so a database
// that already had those cannot tell a Restore that carries ownership across
// from one that drops it on the floor.
func giveTheDatabaseAnOwnerThisProcessWouldNotCreate(t *testing.T, path string) {
	t.Helper()

	// The production shape exactly: root runs `keyhole restore` (or the
	// rollback inside `keyhole update`) over a database owned by the
	// unprivileged service user.
	if os.Geteuid() == 0 {
		const nobody = 65534
		if err := os.Chown(path, nobody, nobody); err != nil {
			t.Fatalf("chown %s to %d:%d: %v", path, nobody, nobody, err)
		}
		return
	}

	// Not root, which is how CI and most developer machines run this. The
	// uid cannot be moved, but the gid can be moved to any group this
	// process belongs to -- and a new file gets the process's *effective*
	// gid, so a database owned by a supplementary group is still an owner
	// the copy cannot reproduce on its own.
	groups, err := os.Getgroups()
	if err != nil {
		t.Fatalf("Getgroups: %v", err)
	}
	egid := os.Getegid()
	for _, gid := range groups {
		if gid == egid {
			continue
		}
		if err := os.Chown(path, -1, gid); err == nil {
			return
		}
	}

	t.Skipf("this process is not root (euid %d) and belongs to no group other than its own (gid %d), "+
		"so it cannot create a database whose owner differs from the one a fresh copy would get -- "+
		"nothing here could tell a Restore that preserves ownership from one that does not. "+
		"Run as root, or as a user in a second group.", os.Geteuid(), egid)
}

// The failure this guards is the whole recovery story: /usr/local/bin/keyhole
// is root-owned and both documented callers of Restore run as root, while the
// systemd unit runs as the keyhole user. A restored database owned by root is
// one the service cannot open -- so `systemctl start keyhole` fails,
// Restart=on-failure loops, the health wait times out, and the operator is
// told the rollback failed as well, with a hand-recovery instruction that
// cannot work.
func TestRestorePreservesTheDatabasesOwner(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "keyhole.db")
	liveDatabaseAt(t, dbPath)
	giveTheDatabaseAnOwnerThisProcessWouldNotCreate(t, dbPath)

	before := ownerOf(t, dbPath)

	if err := Restore(snapshotOfAFreshDatabase(t), dbPath); err != nil {
		t.Fatalf("Restore: %v", err)
	}

	if after := ownerOf(t, dbPath); after != before {
		t.Errorf("database owner after restore = %d:%d, want %d:%d: the restored file must belong to whoever owned the database it replaced, not to whoever ran the restore",
			after.uid, after.gid, before.uid, before.gid)
	}
}
