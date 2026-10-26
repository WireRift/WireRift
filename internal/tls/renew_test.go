package tls

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"sync/atomic"
	"testing"
	"time"
)

// expiringCert returns a self-signed certificate for host that expires in d.
func expiringCert(t *testing.T, host string, d time.Duration) *tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: host},
		DNSNames:     []string{host},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(d),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func newRenewalManager(t *testing.T) *Manager {
	t.Helper()
	mockSrv := mockACMEServerForCerts(t)
	t.Cleanup(mockSrv.Close)

	dir := t.TempDir()
	acme, err := NewACMEManager("test@example.com", dir, true, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := acme.httpClient.Get(mockSrv.URL + "/directory")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	_ = json.NewDecoder(resp.Body).Decode(&acme.directory)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	acme.account = &acmeAccount{Key: key}
	_ = acme.registerAccount()

	m, err := NewManager(Config{Domain: "test.local", CertDir: dir, AutoCert: true})
	if err != nil {
		t.Fatal(err)
	}
	m.acme = acme
	return m
}

// A certificate inside the renewal window is replaced by the background check,
// not by the first visitor who happens to arrive afterwards.
func TestRenewDueReplacesCertInsideRenewalWindow(t *testing.T) {
	m := newRenewalManager(t)

	const host = "renew.test.local"
	old := expiringCert(t, host, 3*24*time.Hour)
	m.storeCert(host, old)
	fresh := expiringCert(t, "fresh.test.local", 60*24*time.Hour)
	m.storeCert("fresh.test.local", fresh)

	m.renewDue(context.Background())

	got, ok := m.certs.Load(host)
	if !ok {
		t.Fatal("renewed certificate is not cached")
	}
	if c := got.(*tls.Certificate); c == old || !certUsable(c) {
		t.Errorf("certificate was not renewed (same=%v usable=%v)", c == old, certUsable(c))
	}
	if c, _ := m.certs.Load("fresh.test.local"); c.(*tls.Certificate) != fresh {
		t.Error("a certificate outside the renewal window must be left alone")
	}
}

// When renewal fails the still-valid certificate keeps being served.
func TestRenewDueKeepsServingOldCertWhenRenewalFails(t *testing.T) {
	m := newRenewalManager(t)
	m.acme.directory.NewOrder = "http://127.0.0.1:1/unreachable"

	const host = "keep.test.local"
	old := expiringCert(t, host, 3*24*time.Hour)
	m.storeCert(host, old)

	m.renewDue(context.Background())

	// The failed order must not leave a self-signed stand-in in place of the
	// old, still valid certificate.
	got, ok := m.certs.Load(host)
	if !ok || got.(*tls.Certificate) != old {
		t.Error("expected the old certificate to stay cached after a failed renewal")
	}
}

func TestCertificateNotAfter(t *testing.T) {
	fallback := time.Now().Add(time.Hour)
	if got := certificateNotAfter([]byte("not pem"), fallback); !got.Equal(fallback) {
		t.Errorf("unparsable input: got %v, want the fallback", got)
	}
}

// Several orders may run at once, but not unboundedly many, and waiting for a
// slot honours the caller's context.
func TestACMEOrderSlotsAreBoundedNotExclusive(t *testing.T) {
	m := &ACMEManager{}
	var releases []func()
	for i := 0; i < maxConcurrentOrders; i++ {
		release, err := m.acquireOrderSlot(context.Background())
		if err != nil {
			t.Fatalf("slot %d: %v", i, err)
		}
		releases = append(releases, release)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, err := m.acquireOrderSlot(ctx); err == nil {
		t.Fatal("got a slot beyond the limit")
	}
	releases[0]()
	release, err := m.acquireOrderSlot(context.Background())
	if err != nil {
		t.Fatalf("slot after release: %v", err)
	}
	release()
}

func newPostTestACME(t *testing.T, handler http.HandlerFunc) *ACMEManager {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	return &ACMEManager{
		directory:  acmeDirectory{NewNonce: srv.URL + "/nonce"},
		account:    &acmeAccount{Key: key},
		httpClient: srv.Client(),
		logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
		certDir:    t.TempDir(),
	}
}

// A badNonce rejection is retried with a fresh nonce instead of failing the order.
func TestSignedPostRetriesBadNonce(t *testing.T) {
	var posts atomic.Int32
	m := newPostTestACME(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/nonce" {
			w.Header().Set("Replay-Nonce", "n")
			return
		}
		if posts.Add(1) == 1 {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"type":"urn:ietf:params:acme:error:badNonce"}`))
			return
		}
		_, _ = w.Write([]byte("ok"))
	})
	resp, err := m.signedPost(context.Background(), m.directory.NewNonce+"/x", nil)
	if err != nil || string(resp.body) != "ok" || posts.Load() != 2 {
		t.Fatalf("resp=%v err=%v posts=%d, want ok after one retry", resp, err, posts.Load())
	}
}

func TestSignedPostGivesUpOnPersistentErrorsAndMissingNonce(t *testing.T) {
	m := newPostTestACME(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/nonce" {
			w.Header().Set("Replay-Nonce", "n")
			return
		}
		w.WriteHeader(http.StatusForbidden)
	})
	if _, err := m.signedPost(context.Background(), m.directory.NewNonce+"/x", nil); err == nil {
		t.Error("a 403 must not be retried into success")
	}

	m = newPostTestACME(t, func(w http.ResponseWriter, r *http.Request) {})
	if _, err := m.getNonce(context.Background()); err == nil {
		t.Error("an empty Replay-Nonce must be an error")
	}
}

func TestSaveCertBundleLeavesNoTempFiles(t *testing.T) {
	m := newPostTestACME(t, func(http.ResponseWriter, *http.Request) {})
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	b := &CertificateBundle{CertPEM: []byte("pem"), PrivateKey: key, Domains: []string{"a.test"}, IssuedAt: time.Now(), ExpiresAt: time.Now()}
	if err := m.saveCertBundle("a.test", b); err != nil {
		t.Fatal(err)
	}
	entries, _ := os.ReadDir(m.certDir)
	if len(entries) != 3 {
		t.Errorf("want exactly the .crt/.key/.json files, got %d entries", len(entries))
	}
}

func TestPruneRetriesDropsOnlyFinishedEntriesWithoutCertificate(t *testing.T) {
	m := &Manager{}
	past, future := time.Now().Add(-time.Minute), time.Now().Add(time.Hour)
	m.retryAfter.Store("gone.example", past)      // finished, nothing cached: drop
	m.retryAfter.Store("waiting.example", future) // still backing off: keep
	m.retryAfter.Store("served.example", past)    // finished but a fallback is cached: keep
	m.certs.Store("served.example", &tls.Certificate{})

	m.pruneRetries()

	for host, want := range map[string]bool{"gone.example": false, "waiting.example": true, "served.example": true} {
		if _, ok := m.retryAfter.Load(host); ok != want {
			t.Errorf("%s kept = %v, want %v", host, ok, want)
		}
	}
}
