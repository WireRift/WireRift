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
	"math/big"
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
