package secret

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestLoadOrCreateGenerates32Bytes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "server.secret")

	s, err := LoadOrCreate(path)
	if err != nil {
		t.Fatalf("LoadOrCreate: %v", err)
	}
	if len(s) != 32 {
		t.Errorf("secret length = %d, want 32", len(s))
	}
}

func TestLoadOrCreateIsStableAcrossCalls(t *testing.T) {
	path := filepath.Join(t.TempDir(), "server.secret")

	first, err := LoadOrCreate(path)
	if err != nil {
		t.Fatal(err)
	}
	second, err := LoadOrCreate(path)
	if err != nil {
		t.Fatal(err)
	}
	// A regenerated secret would invalidate every decoy salt the server has
	// ever issued, making prelogin responses inconsistent across restarts.
	if !bytes.Equal(first, second) {
		t.Error("the secret changed on the second load")
	}
}

func TestLoadOrCreateWritesRestrictivePermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix file modes are not meaningful on Windows")
	}
	path := filepath.Join(t.TempDir(), "server.secret")
	if _, err := LoadOrCreate(path); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if mode := info.Mode().Perm(); mode != 0o600 {
		t.Errorf("mode = %o, want 600", mode)
	}
}

func TestLoadOrCreateRejectsATruncatedSecret(t *testing.T) {
	path := filepath.Join(t.TempDir(), "server.secret")
	if err := os.WriteFile(path, []byte("short"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Silently regenerating would be worse than failing: it would change the
	// decoy salts with no operator visible signal.
	if _, err := LoadOrCreate(path); err == nil {
		t.Error("a truncated secret file was accepted")
	}
}

func TestAnUnreadableSecretIsAnErrorNotAFreshSecret(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "server.secret")

	if err := os.WriteFile(path, make([]byte, 32), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := os.Chmod(path, 0o000); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(path, 0o600) })

	// Windows ignores POSIX mode bits on files, so verify the chmod actually
	// took effect before asserting on it. A test that silently passes on the
	// development machine and only means something in CI is worse than one
	// that says which it is.
	if data, err := os.ReadFile(path); err == nil && len(data) == 32 {
		t.Skip("this filesystem does not enforce mode 0000; nothing to assert")
	}

	// Generating a fresh secret here would silently invalidate every prelogin
	// decoy salt the installation has ever produced — turning a permissions
	// problem into a change of identity nobody asked for.
	if _, err := LoadOrCreate(path); err == nil {
		t.Error("LoadOrCreate succeeded on an unreadable secret file")
	}
}
