package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDefaultHasUsableValues(t *testing.T) {
	c := Default()
	if c.Addr == "" {
		t.Error("Default().Addr must not be empty")
	}
	if c.DataDir == "" {
		t.Error("Default().DataDir must not be empty")
	}
	if c.LogLevel != "info" {
		t.Errorf("Default().LogLevel = %q, want %q", c.LogLevel, "info")
	}
}

func TestLoadMissingFileReturnsDefaults(t *testing.T) {
	c, err := Load(filepath.Join(t.TempDir(), "absent.yml"))
	if err != nil {
		t.Fatalf("Load on a missing file should fall back to defaults, got error: %v", err)
	}
	if c.Addr != Default().Addr {
		t.Errorf("Addr = %q, want the default %q", c.Addr, Default().Addr)
	}
}

func TestLoadOverridesOnlyWhatIsSet(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yml")
	body := "addr: 127.0.0.1:9999\nlog_level: debug\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	c, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if c.Addr != "127.0.0.1:9999" {
		t.Errorf("Addr = %q, want %q", c.Addr, "127.0.0.1:9999")
	}
	if c.LogLevel != "debug" {
		t.Errorf("LogLevel = %q, want %q", c.LogLevel, "debug")
	}
	// DataDir was absent from the file and must keep its default.
	if c.DataDir != Default().DataDir {
		t.Errorf("DataDir = %q, want the default %q", c.DataDir, Default().DataDir)
	}
}

func TestLoadRejectsUnparsableLine(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yml")
	if err := os.WriteFile(path, []byte("this line has no colon\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Error("Load should reject a line that is not key: value")
	}
}

func TestDBPathSitsUnderDataDir(t *testing.T) {
	c := Default()
	c.DataDir = filepath.Join("var", "lib", "keyhole")
	want := filepath.Join("var", "lib", "keyhole", "keyhole.db")
	if got := c.DBPath(); got != want {
		t.Errorf("DBPath() = %q, want %q", got, want)
	}
}

func TestLoadReadsTLSPaths(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yml")
	body := "tls_cert: /etc/keyhole/tls.crt\ntls_key: /etc/keyhole/tls.key\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	c, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if c.TLSCert != "/etc/keyhole/tls.crt" {
		t.Errorf("TLSCert = %q, want %q", c.TLSCert, "/etc/keyhole/tls.crt")
	}
	if c.TLSKey != "/etc/keyhole/tls.key" {
		t.Errorf("TLSKey = %q, want %q", c.TLSKey, "/etc/keyhole/tls.key")
	}
}

func TestTLSEnabledRequiresBothCertAndKey(t *testing.T) {
	cases := []struct {
		name string
		cert string
		key  string
		want bool
	}{
		{"neither set", "", "", false},
		{"cert only", "cert.pem", "", false},
		{"key only", "", "key.pem", false},
		{"both set", "cert.pem", "key.pem", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := Config{TLSCert: tc.cert, TLSKey: tc.key}
			if got := c.TLSEnabled(); got != tc.want {
				t.Errorf("TLSEnabled() with cert=%q key=%q = %v, want %v", tc.cert, tc.key, got, tc.want)
			}
		})
	}
}

func TestLoadRejectsACertWithoutAKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yml")
	body := "tls_cert: /etc/keyhole/tls.crt\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	_, err := Load(path)
	if err == nil {
		t.Fatal("Load with tls_cert set and tls_key absent should have errored")
	}
	if !strings.Contains(err.Error(), "tls_cert") || !strings.Contains(err.Error(), "tls_key") {
		t.Errorf("error %q should name both tls_cert and tls_key", err)
	}
}
