package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ssan9876/keyhole/internal/config"
)

// generateSelfSignedCert writes a throwaway self-signed certificate and key
// into dir, valid for 127.0.0.1, and returns their paths. Generated fresh
// per test with crypto/x509 rather than a committed fixture, so nothing here
// depends on a certificate that expires or needs regenerating by hand.
func generateSelfSignedCert(t *testing.T, dir string) (certPath, keyPath string) {
	t.Helper()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "keyhole-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IsCA:         true,
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:     []string{"localhost"},
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}

	certPath = filepath.Join(dir, "tls.crt")
	certOut, err := os.Create(certPath)
	if err != nil {
		t.Fatalf("create cert file: %v", err)
	}
	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: der}); err != nil {
		t.Fatalf("encode cert: %v", err)
	}
	if err := certOut.Close(); err != nil {
		t.Fatalf("close cert file: %v", err)
	}

	keyBytes, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	keyPath = filepath.Join(dir, "tls.key")
	keyOut, err := os.Create(keyPath)
	if err != nil {
		t.Fatalf("create key file: %v", err)
	}
	if err := pem.Encode(keyOut, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes}); err != nil {
		t.Fatalf("encode key: %v", err)
	}
	if err := keyOut.Close(); err != nil {
		t.Fatalf("close key file: %v", err)
	}

	return certPath, keyPath
}

// startTestServer starts serve() in the background on 127.0.0.1:0 with cfg,
// waits for it to report the address it actually bound, and registers a
// cleanup that cancels the server's shutdown context and waits for serve()
// to return -- so a failing subtest cannot leak a listener into the next
// test.
func startTestServer(t *testing.T, cfg config.Config) (addr string) {
	t.Helper()

	cfg.Addr = "127.0.0.1:0"

	ctx, cancel := context.WithCancel(context.Background())
	ready := make(chan string, 1)
	done := make(chan error, 1)

	go func() {
		done <- serve(cfg, ctx, ready)
	}()

	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("serve did not shut down cleanly: %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Error("serve did not stop within 5s of shutdown")
		}
	})

	select {
	case addr = <-ready:
		return addr
	case err := <-done:
		t.Fatalf("serve exited before it started listening: %v", err)
		return ""
	case <-time.After(5 * time.Second):
		t.Fatal("serve did not report a listening address within 5s")
		return ""
	}
}

// tempTLSConfig writes a config with a fresh data dir and the given TLS
// paths, addressed at 127.0.0.1:0 so the OS picks a free port.
func tempTLSConfig(t *testing.T, certPath, keyPath string) config.Config {
	t.Helper()

	c := config.Default()
	c.DataDir = filepath.Join(t.TempDir(), "data")
	c.TLSCert = certPath
	c.TLSKey = keyPath
	return c
}

func TestServeTerminatesTLSItself(t *testing.T) {
	certDir := t.TempDir()
	certPath, keyPath := generateSelfSignedCert(t, certDir)
	cfg := tempTLSConfig(t, certPath, keyPath)

	addr := startTestServer(t, cfg)

	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatalf("read generated cert: %v", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(certPEM) {
		t.Fatal("failed to load generated cert into a CertPool")
	}

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: pool},
		},
		Timeout: 5 * time.Second,
	}

	// A client that trusts the self-signed cert must see a healthy TLS
	// response: proof the server actually terminated TLS with the
	// configured cert/key pair rather than, say, silently falling back to
	// plaintext on the same port.
	resp, err := client.Get("https://" + addr + "/healthz")
	if err != nil {
		t.Fatalf("GET https://%s/healthz: %v", addr, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	// Same socket, plain HTTP. Go's TLS server recognizes a plaintext HTTP
	// request arriving on a TLS listener and answers with a 400 explaining
	// the mismatch rather than dropping the connection outright, so the
	// transport-level request can succeed even though the vault is
	// unreachable this way -- the assertion that matters is that it is
	// never the 200 a real /healthz response would be.
	plainClient := &http.Client{Timeout: 2 * time.Second}
	resp2, err := plainClient.Get("http://" + addr + "/healthz")
	if err == nil {
		defer resp2.Body.Close()
		if resp2.StatusCode == http.StatusOK {
			t.Errorf("plain HTTP request to a TLS-only listener returned %d, want anything but a healthy 200", resp2.StatusCode)
		}
	}
	// err != nil (a connection reset, most commonly) is also a valid way for
	// the plain request to fail and requires no further assertion.
}

func TestServeWarnsOnPlainHTTPOnNonLoopbackAddr(t *testing.T) {
	// Regression guard for isLoopbackAddr, exercised directly: a routable
	// address without TLS is a warning, not a refusal, because a reverse
	// proxy or tunnel in front of a loopback bind is also a valid way to
	// reach a non-loopback network -- see the doc comment on isLoopbackAddr's
	// call site in serve().
	if isLoopbackAddr("0.0.0.0:8477") {
		t.Error(`isLoopbackAddr("0.0.0.0:8477") = true, want false`)
	}
	if isLoopbackAddr(":8477") {
		t.Error(`isLoopbackAddr(":8477") = true, want false`)
	}
	if !isLoopbackAddr("127.0.0.1:8477") {
		t.Error(`isLoopbackAddr("127.0.0.1:8477") = false, want true`)
	}
	if !isLoopbackAddr("localhost:8477") {
		t.Error(`isLoopbackAddr("localhost:8477") = false, want true`)
	}
}
