package tls

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	cryptotls "crypto/tls"
	"crypto/x509"
	"log/slog"
	"path/filepath"
	"testing"
	"time"
)

func TestEarliestCertificateExpiryUsesMemoryOnlyCache(t *testing.T) {
	m := &Manager{}
	if got := m.EarliestCertificateExpiry(); !got.IsZero() {
		t.Fatalf("empty cache expiry = %v", got)
	}
	later := time.Unix(2_100_000_000, 0)
	earlier := time.Unix(2_000_000_000, 0)
	m.storeCert("later.example", &cryptotls.Certificate{Leaf: &x509.Certificate{NotAfter: later}})
	m.storeCert("earlier.example", &cryptotls.Certificate{Leaf: &x509.Certificate{NotAfter: earlier}})
	if got := m.EarliestCertificateExpiry(); !got.Equal(earlier) {
		t.Fatalf("earliest expiry = %v, want %v", got, earlier)
	}
}

func TestCertificatePersistenceErrorsAreCounted(t *testing.T) {
	m := &Manager{config: Config{CertDir: filepath.Join(t.TempDir(), "missing")}}
	if err := m.saveCertificate("app.example", []byte("cert"), []byte("key")); err == nil {
		t.Fatal("saveCertificate succeeded in missing directory")
	}
	if got := m.PersistenceErrors(); got != 1 {
		t.Fatalf("manager persistence errors = %d, want 1", got)
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	acme := &ACMEManager{certDir: filepath.Join(t.TempDir(), "missing"), logger: slog.Default()}
	bundle := &CertificateBundle{CertPEM: []byte("cert"), PrivateKey: key}
	if err := acme.saveCertBundle("app.example", bundle); err == nil {
		t.Fatal("saveCertBundle succeeded in missing directory")
	}
	if got := acme.PersistenceErrors(); got != 1 {
		t.Fatalf("ACME persistence errors = %d, want 1", got)
	}
	m.acme = acme
	if got := m.PersistenceErrors(); got != 2 {
		t.Fatalf("aggregated persistence errors = %d, want 2", got)
	}
}
