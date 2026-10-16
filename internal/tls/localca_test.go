package tls

import (
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

type tlsClientHello = tls.ClientHelloInfo

func newTestCA(t *testing.T) *LocalCA {
	t.Helper()
	ca, err := LoadOrCreateLocalCA(filepath.Join(t.TempDir(), "ca"))
	if err != nil {
		t.Fatal(err)
	}
	return ca
}

func verifyFor(t *testing.T, ca *LocalCA, leaf *x509.Certificate, name string) error {
	t.Helper()
	_, err := leaf.Verify(x509.VerifyOptions{
		Roots:     ca.Pool(),
		DNSName:   name,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	return err
}

func TestLocalCACreatedOnceAndReloaded(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "ca")
	first, err := LoadOrCreateLocalCA(dir)
	if err != nil {
		t.Fatal(err)
	}
	second, err := LoadOrCreateLocalCA(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !first.Cert.Equal(second.Cert) {
		t.Error("CA was regenerated instead of reloaded (users would have to trust it again)")
	}

	if runtime.GOOS != "windows" {
		keyInfo, _ := os.Stat(first.KeyPath())
		if keyInfo.Mode().Perm() != 0o600 {
			t.Errorf("CA key mode = %v, want 0600", keyInfo.Mode().Perm())
		}
		dirInfo, _ := os.Stat(dir)
		if dirInfo.Mode().Perm() != 0o700 {
			t.Errorf("CA dir mode = %v, want 0700", dirInfo.Mode().Perm())
		}
	}
}

func TestLocalCAIsNameConstrained(t *testing.T) {
	ca := newTestCA(t)
	c := ca.Cert
	if !c.IsCA || !c.MaxPathLenZero || !c.PermittedDNSDomainsCritical {
		t.Fatalf("CA must be a path-length-0 CA with critical name constraints: %+v", c)
	}
	if len(c.PermittedDNSDomains) == 0 || len(c.PermittedIPRanges) == 0 {
		t.Fatal("CA lacks DNS/IP name constraints")
	}
}

func TestLocalLeafVerifiesInsideNamespace(t *testing.T) {
	ca := newTestCA(t)
	cert, err := ca.IssueLeaf([]string{"localhost", "*.localhost", "127.0.0.1", "::1", "api.test", "*.test"})
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"localhost", "myapp.localhost", "api.test", "x.test"} {
		if err := verifyFor(t, ca, cert.Leaf, name); err != nil {
			t.Errorf("verify %q: %v", name, err)
		}
	}
	// IP SANs must pass the CA's IP constraints too.
	if _, err := cert.Leaf.Verify(x509.VerifyOptions{Roots: ca.Pool(), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
		t.Errorf("leaf with loopback IP SANs does not verify: %v", err)
	}
	if err := cert.Leaf.VerifyHostname("127.0.0.1"); err != nil {
		t.Errorf("IP SAN: %v", err)
	}
}

func TestIssueLeafRejectsOutOfScopeNames(t *testing.T) {
	ca := newTestCA(t)
	for _, name := range []string{"example.com", "*.example.com", "evil.localhost.example.com", "10.0.0.1", "", "notlocalhost"} {
		if _, err := ca.IssueLeaf([]string{name}); !errors.Is(err, ErrNameNotPermitted) {
			t.Errorf("IssueLeaf(%q) err = %v, want ErrNameNotPermitted", name, err)
		}
	}
}

// The important property: even a stolen CA key cannot produce a certificate
// that a client accepts for a real site. Bypass IssueLeaf's own check and
// prove the X.509 name constraints are what stop it.
func TestStolenCAKeyCannotImpersonatePublicSites(t *testing.T) {
	ca := newTestCA(t)
	cert, err := ca.signLeaf([]string{"www.google.com", "bank.example.com"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"www.google.com", "bank.example.com"} {
		err := verifyFor(t, ca, cert.Leaf, name)
		if err == nil {
			t.Fatalf("certificate for %q verified against the local CA: name constraints are not enforced", name)
		}
		var invalid x509.CertificateInvalidError
		if !errors.As(err, &invalid) || invalid.Reason != x509.CANotAuthorizedForThisName {
			t.Errorf("verify %q: err = %v, want CANotAuthorizedForThisName", name, err)
		}
	}

	ipCert, err := ca.signLeaf([]string{"localhost"}, []net.IP{net.ParseIP("8.8.8.8")})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ipCert.Leaf.Verify(x509.VerifyOptions{Roots: ca.Pool(), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err == nil {
		t.Error("certificate with a public IP SAN verified against the local CA")
	}
}

func TestLoadLocalCARefusesBadState(t *testing.T) {
	// Missing -> ErrNotExist (so LoadOrCreate may create).
	if _, err := LoadLocalCA(t.TempDir()); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("missing CA err = %v, want ErrNotExist", err)
	}

	// Corrupt existing CA must NOT be silently replaced.
	ca := newTestCA(t)
	if err := os.WriteFile(ca.CertPath(), []byte("garbage"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOrCreateLocalCA(ca.Dir); err == nil || errors.Is(err, os.ErrNotExist) {
		t.Errorf("corrupt CA err = %v, want a hard error", err)
	}

	// Key that does not belong to the certificate.
	a, b := newTestCA(t), newTestCA(t)
	keyB, _ := os.ReadFile(b.KeyPath())
	if err := os.WriteFile(a.KeyPath(), keyB, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadLocalCA(a.Dir); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Errorf("mismatched key err = %v", err)
	}
}

func TestLeafProviderIssuesExactNamesAndCaches(t *testing.T) {
	ca := newTestCA(t)
	p, err := ca.NewLeafProvider("localhost")
	if err != nil {
		t.Fatal(err)
	}

	hello := func(name string) *tlsClientHello { return &tlsClientHello{ServerName: name} }
	a, err := p.GetCertificate(hello("myapp.localhost"))
	if err != nil {
		t.Fatal(err)
	}
	b, _ := p.GetCertificate(hello("MyApp.Localhost.")) // case/trailing dot normalised
	if a != b {
		t.Error("certificate not cached per host")
	}
	if len(a.Leaf.DNSNames) != 1 || a.Leaf.DNSNames[0] != "myapp.localhost" {
		t.Errorf("SANs = %v, want exactly the requested name (no wildcard)", a.Leaf.DNSNames)
	}
	if err := verifyFor(t, ca, a.Leaf, "myapp.localhost"); err != nil {
		t.Errorf("verify: %v", err)
	}

	// No SNI (connecting by IP): base domain plus loopback IPs.
	base, err := p.GetCertificate(hello(""))
	if err != nil {
		t.Fatal(err)
	}
	if base.Leaf.VerifyHostname("127.0.0.1") != nil || base.Leaf.VerifyHostname("localhost") != nil {
		t.Errorf("base certificate should cover localhost and 127.0.0.1: %v %v", base.Leaf.DNSNames, base.Leaf.IPAddresses)
	}

	// Different hosts get different certificates.
	c, _ := p.GetCertificate(hello("api.localhost"))
	if c == a {
		t.Error("distinct hosts shared a certificate")
	}
}

func TestLeafProviderRejectsForeignAndMalformedNames(t *testing.T) {
	ca := newTestCA(t)
	p, _ := ca.NewLeafProvider("myapp.test")
	for _, name := range []string{"example.com", "evil.test", "myapp.test.evil.com", "a..myapp.test", "bad_name.myapp.test", "*.myapp.test", "-x.myapp.test"} {
		if _, err := p.GetCertificate(&tlsClientHello{ServerName: name}); !errors.Is(err, ErrNameNotPermitted) {
			t.Errorf("GetCertificate(%q) err = %v, want ErrNameNotPermitted", name, err)
		}
	}
	if _, err := p.GetCertificate(&tlsClientHello{ServerName: "deep.sub.myapp.test"}); err != nil {
		t.Errorf("nested subdomain rejected: %v", err)
	}
	for _, base := range []string{"example.com", "", "127.0.0.1"} {
		if _, err := ca.NewLeafProvider(base); !errors.Is(err, ErrNameNotPermitted) {
			t.Errorf("NewLeafProvider(%q) err = %v", base, err)
		}
	}
}

func TestLeafProviderRenewsNearExpiryAndBoundsCache(t *testing.T) {
	ca := newTestCA(t)
	p, _ := ca.NewLeafProvider("localhost")
	a, _ := p.GetCertificate(&tlsClientHello{ServerName: "x.localhost"})

	p.mu.Lock()
	p.certs["x.localhost"].Leaf.NotAfter = time.Now().Add(24 * time.Hour)
	p.mu.Unlock()
	if b, _ := p.GetCertificate(&tlsClientHello{ServerName: "x.localhost"}); b == a {
		t.Error("near-expiry certificate was not renewed")
	}

	for i := 0; i < maxLeafCache+10; i++ {
		if _, err := p.GetCertificate(&tlsClientHello{ServerName: fmt.Sprintf("h%d.localhost", i)}); err != nil {
			t.Fatal(err)
		}
	}
	p.mu.Lock()
	n := len(p.certs)
	p.mu.Unlock()
	if n > maxLeafCache {
		t.Errorf("cache grew to %d entries (limit %d)", n, maxLeafCache)
	}
}

func TestLocalCAHelpers(t *testing.T) {
	dir, err := DefaultLocalCADir()
	if err != nil || !strings.HasSuffix(dir, filepath.Join("wirerift", "local-ca")) {
		t.Errorf("DefaultLocalCADir = %q, %v", dir, err)
	}
	ca := newTestCA(t)
	if fp := ca.Fingerprint(); len(fp) != 64 || fp != strings.ToUpper(fp) {
		t.Errorf("fingerprint = %q", fp)
	}
	if !LocalNamePermitted("a.localhost") || LocalNamePermitted("a.com") {
		t.Error("LocalNamePermitted wrong")
	}
	p, _ := ca.NewLeafProvider("localhost")
	cfg := p.TLSConfig()
	if cfg.MinVersion < tls.VersionTLS12 || cfg.GetCertificate == nil || len(cfg.NextProtos) == 0 {
		t.Errorf("TLSConfig = %+v", cfg)
	}
}

func TestLoadLocalCARefusesUnconstrainedAndExpired(t *testing.T) {
	// An unconstrained CA (e.g. one swapped in by mistake) is a system-wide
	// MITM key and must be refused.
	ca := newTestCA(t)
	tmpl := *ca.Cert
	tmpl.PermittedDNSDomains = nil
	tmpl.PermittedIPRanges = nil
	tmpl.PermittedDNSDomainsCritical = false
	tmpl.Raw, tmpl.RawTBSCertificate = nil, nil
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &ca.Key.PublicKey, ca.Key)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(ca.CertPath(), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadLocalCA(ca.Dir); err == nil || !strings.Contains(err.Error(), "name constraints") {
		t.Errorf("unconstrained CA err = %v", err)
	}

	expired := newTestCA(t)
	etmpl := *expired.Cert
	etmpl.NotBefore, etmpl.NotAfter = time.Now().Add(-48*time.Hour), time.Now().Add(-24*time.Hour)
	etmpl.Raw, etmpl.RawTBSCertificate = nil, nil
	der, err = x509.CreateCertificate(rand.Reader, &etmpl, &etmpl, &expired.Key.PublicKey, expired.Key)
	if err != nil {
		t.Fatal(err)
	}
	os.WriteFile(expired.CertPath(), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644)
	if _, err := LoadLocalCA(expired.Dir); err == nil || !strings.Contains(err.Error(), "expired") {
		t.Errorf("expired CA err = %v", err)
	}

	// Garbage PEM / key problems.
	bad := newTestCA(t)
	os.WriteFile(bad.KeyPath(), []byte("nope"), 0o600)
	if _, err := LoadLocalCA(bad.Dir); err == nil {
		t.Error("garbage key accepted")
	}
	os.Remove(bad.KeyPath())
	if _, err := LoadLocalCA(bad.Dir); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("missing key err = %v", err)
	}
}

func TestCreateLocalCAFailsInReadOnlyLocation(t *testing.T) {
	file := filepath.Join(t.TempDir(), "afile")
	os.WriteFile(file, nil, 0o600)
	if _, err := LoadOrCreateLocalCA(filepath.Join(file, "sub")); err == nil {
		t.Error("expected an error when the CA directory cannot be created")
	}
}

func TestIssueLeafRequiresNames(t *testing.T) {
	if _, err := newTestCA(t).IssueLeaf(nil); err == nil {
		t.Error("IssueLeaf(nil) accepted")
	}
}
