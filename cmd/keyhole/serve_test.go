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
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
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

// captureStdout redirects os.Stdout for the duration of fn and returns
// everything written to it.
//
// serve() builds its own slog handler over os.Stdout at the moment it is
// called and takes no logger, so there is no seam to inject one through:
// swapping the file out from under it is the only way to read what it
// logged. fn must have finished with the server before it returns, or the
// close below races the server's own logging goroutine.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	previous := os.Stdout
	os.Stdout = w
	// Deferred rather than done inline after fn, so a t.Fatal inside fn
	// does not leave every later test in this package writing into a pipe
	// nobody reads.
	defer func() { os.Stdout = previous }()

	fn()

	// The write end has to be closed before the read, or ReadAll waits for
	// an EOF only this side can produce.
	if err := w.Close(); err != nil {
		t.Fatalf("close the write end of the capture pipe: %v", err)
	}
	defer r.Close()
	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("read the capture pipe: %v", err)
	}
	return string(out)
}

// serveUntilItIsListening runs serve(cfg) as far as its listener, then
// shuts it down and waits for it to return. Everything serve logs on the way
// up has been written by the time this returns.
//
// Deliberately not startTestServer: that helper overwrites cfg.Addr with
// 127.0.0.1:0, and the address under test here is the whole point.
func serveUntilItIsListening(t *testing.T, cfg config.Config) {
	t.Helper()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ready := make(chan string, 1)
	done := make(chan error, 1)

	go func() { done <- serve(cfg, ctx, ready) }()

	select {
	case <-ready:
	case err := <-done:
		t.Fatalf("serve exited before it started listening: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("serve did not report a listening address within 5s")
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("serve did not shut down cleanly: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("serve did not stop within 5s of shutdown")
	}
}

// plainHTTPWarning is the substring the two tests below agree on. Both
// assertions have to name the same line, or one of them stops meaning
// anything the moment the wording changes.
const plainHTTPWarning = "serving without TLS on a non-loopback address"

// This warning is the only thing between an operator who binds a routable
// address in the clear and a vault that loads, accepts a password, and
// cannot decrypt a single item: window.crypto.subtle does not exist outside
// a secure context.
//
// So it is asserted through serve() rather than through isLoopbackAddr.
// The test that used to carry this name never called serve and never looked
// at a log line, which meant deleting the warning outright left it green.
func TestServeWarnsWhenServingPlainHTTPOnANonLoopbackAddress(t *testing.T) {
	cfg := config.Default()
	cfg.DataDir = filepath.Join(t.TempDir(), "data")
	// The configuration the warning exists for. serve() emits it after the
	// listener binds, so the bind is real -- on a kernel-chosen port, for
	// the few milliseconds it takes to come up and go down again.
	cfg.Addr = "0.0.0.0:0"

	out := captureStdout(t, func() { serveUntilItIsListening(t, cfg) })

	if !strings.Contains(out, plainHTTPWarning) {
		t.Errorf("serve on %s without TLS logged no warning; it logged:\n%s", cfg.Addr, out)
	}
}

// The other half. A warning that fires on every start is one an operator
// learns to scroll past, and an assertion that only looks for the line
// would pass against exactly that.
func TestServeDoesNotWarnOnALoopbackAddress(t *testing.T) {
	cfg := config.Default()
	cfg.DataDir = filepath.Join(t.TempDir(), "data")
	cfg.Addr = "127.0.0.1:0"

	out := captureStdout(t, func() { serveUntilItIsListening(t, cfg) })

	if strings.Contains(out, plainHTTPWarning) {
		t.Errorf("serve warned about plain HTTP on %s, which nothing off this machine can reach; it logged:\n%s", cfg.Addr, out)
	}
}

func TestIsLoopbackAddr(t *testing.T) {
	// A routable address without TLS is a warning, not a refusal, because a
	// reverse proxy or tunnel in front of a loopback bind is also a valid
	// way to reach a non-loopback network -- see the doc comment on
	// isLoopbackAddr's call site in serve().
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
