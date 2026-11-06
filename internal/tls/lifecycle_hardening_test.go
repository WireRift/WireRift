package tls

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	cryptotls "crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCancelledIssuanceWaiterReturnsImmediately(t *testing.T) {
	m := &Manager{inflight: make(map[string]*issueCall)}
	leader := &issueCall{done: make(chan struct{})}
	m.inflight["app.example.com"] = leader
	defer close(leader.done)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	result := make(chan error, 1)
	go func() {
		_, err := m.issueCoalesced(ctx, "app.example.com")
		result <- err
	}()

	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("waiter error = %v, want context.Canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("cancelled handshake remained blocked behind shared certificate issuance")
	}
}

func TestAtomicWriteFailurePreservesDestination(t *testing.T) {
	path := filepath.Join(t.TempDir(), "live.crt")
	const original = "LAST-KNOWN-GOOD-CERTIFICATE"
	if err := os.WriteFile(path, []byte(original), 0o600); err != nil {
		t.Fatal(err)
	}
	wantErr := errors.New("injected disk failure")
	err := writeFileAtomic(path, func(f *os.File) error {
		_, _ = f.Write([]byte("TRUNCATED"))
		return wantErr
	})
	if !errors.Is(err, wantErr) {
		t.Fatalf("write error = %v, want injected error", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != original {
		t.Fatalf("failed atomic write replaced live certificate with %q", got)
	}
}

func TestCorruptACMEAccountKeyFailsClosed(t *testing.T) {
	dir := t.TempDir()
	mgr, err := NewACMEManager("ops@example.com", dir, true, nil)
	if err != nil {
		t.Fatal(err)
	}

	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p384DER, err := x509.MarshalECPrivateKey(p384)
	if err != nil {
		t.Fatal(err)
	}

	tests := map[string][]byte{
		"not PEM":        []byte("not a PEM private key\n"),
		"invalid DER":    pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: []byte("broken")}),
		"wrong PEM type": pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: p384DER}),
		"wrong curve":    pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: p384DER}),
	}
	for name, corrupt := range tests {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(dir, strings.ReplaceAll(name, " ", "-")+".key")
			if err := os.WriteFile(path, corrupt, 0600); err != nil {
				t.Fatal(err)
			}

			if _, err := mgr.loadOrCreateKey(path); err == nil {
				t.Fatal("existing corrupt account key was silently replaced")
			}
			got, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != string(corrupt) {
				t.Fatal("existing corrupt account key was overwritten")
			}
		})
	}
}

func TestAbbreviatedTokenHandlesShortACMEResponses(t *testing.T) {
	for token, want := range map[string]string{
		"":          "",
		"x":         "x",
		"12345678":  "12345678",
		"123456789": "12345678...",
	} {
		if got := abbreviatedToken(token); got != want {
			t.Errorf("abbreviatedToken(%q) = %q, want %q", token, got, want)
		}
	}
}

func TestSignedPostRejectsMalformedACMEURLWithoutPanic(t *testing.T) {
	nonce := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Replay-Nonce", "nonce")
	}))
	defer nonce.Close()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	m := &ACMEManager{
		account:    &acmeAccount{URL: "account", Key: key},
		directory:  acmeDirectory{NewNonce: nonce.URL},
		httpClient: nonce.Client(),
	}
	if _, err := m.signedPost(context.Background(), "http://[::1", []byte("{}")); err == nil {
		t.Fatal("malformed ACME URL was accepted")
	}
}

func TestRequiredACMEInitializationFailsClosed(t *testing.T) {
	oldTransport := http.DefaultTransport
	http.DefaultTransport = roundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("injected ACME outage")
	})
	defer func() { http.DefaultTransport = oldTransport }()

	_, err := NewManager(Config{
		Domain:      "tunnel.example.com",
		CertDir:     t.TempDir(),
		Email:       "ops@example.com",
		RequireACME: true,
	})
	if err == nil || !strings.Contains(err.Error(), "injected ACME outage") {
		t.Fatalf("NewManager error = %v, want fatal ACME initialization error", err)
	}
}

func TestRequiredACMEOutageUsesValidCachedIdentityAndCertificate(t *testing.T) {
	const domain = "tunnel.example.com"
	dir := t.TempDir()

	// Seed the same durable artifacts a successful prior ACME run leaves.
	seed, err := NewManager(Config{Domain: domain, CertDir: dir, AutoCert: true})
	if err != nil {
		t.Fatal(err)
	}
	seedCert, err := seed.GetCertificate(&cryptotls.ClientHelloInfo{ServerName: domain})
	if err != nil {
		t.Fatal(err)
	}
	account, err := NewACMEManager("ops@example.com", dir, true, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := account.loadOrCreateKey(filepath.Join(dir, "acme-account.key")); err != nil {
		t.Fatal(err)
	}

	oldTransport := http.DefaultTransport
	http.DefaultTransport = roundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("injected ACME outage")
	})
	defer func() { http.DefaultTransport = oldTransport }()

	m, err := NewManager(Config{
		Domain:      domain,
		CertDir:     dir,
		Email:       "ops@example.com",
		UseStaging:  true,
		RequireACME: true,
		AutoCert:    true,
	})
	if err != nil {
		t.Fatalf("cached degraded startup failed: %v", err)
	}
	if !m.IsACMEEnabled() || m.acmeReady.Load() {
		t.Fatalf("ACME state = enabled:%v ready:%v, want enabled degraded mode", m.IsACMEEnabled(), m.acmeReady.Load())
	}
	got, err := m.GetCertificate(&cryptotls.ClientHelloInfo{ServerName: domain})
	if err != nil {
		t.Fatalf("serve cached certificate: %v", err)
	}
	if string(got.Certificate[0]) != string(seedCert.Certificate[0]) {
		t.Fatal("degraded startup did not serve the cached certificate")
	}

	// Once the directory is reachable, the normal ACME state is restored
	// without restarting the server.
	mock := mockACMEServer(t)
	defer mock.Close()
	m.acme.httpClient = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.URL.String() == LetsEncryptStaging {
			req = req.Clone(req.Context())
			req.URL, _ = req.URL.Parse(mock.URL + "/directory")
		}
		return oldTransport.RoundTrip(req)
	})}
	if err := m.retryACMEInitialization(); err != nil {
		t.Fatalf("retry ACME initialization: %v", err)
	}
	if !m.acmeReady.Load() {
		t.Fatal("ACME did not leave degraded mode after connectivity recovered")
	}
}
