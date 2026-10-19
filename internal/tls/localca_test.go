package tls

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
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

// A half-broken CA (exactly one of the two files present) must never be
// silently replaced: users may already trust the surviving certificate, so
// LoadOrCreateLocalCA must return a hard error and leave that file untouched.
// Only a directory with neither file is a genuine first use that may create.
func TestLoadOrCreateRefusesHalfBrokenCA(t *testing.T) {
	// Key missing, certificate present.
	ca := newTestCA(t)
	originalCert, err := os.ReadFile(ca.CertPath())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(ca.KeyPath()); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOrCreateLocalCA(ca.Dir); err == nil || errors.Is(err, os.ErrNotExist) {
		t.Errorf("cert-present/key-missing err = %v, want a hard error (not ErrNotExist)", err)
	}
	afterCert, err := os.ReadFile(ca.CertPath())
	if err != nil {
		t.Fatal(err)
	}
	if string(afterCert) != string(originalCert) {
		t.Error("existing trusted CA certificate was silently replaced")
	}

	// Certificate missing, key present.
	ca2 := newTestCA(t)
	originalKey, err := os.ReadFile(ca2.KeyPath())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(ca2.CertPath()); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOrCreateLocalCA(ca2.Dir); err == nil || errors.Is(err, os.ErrNotExist) {
		t.Errorf("key-present/cert-missing err = %v, want a hard error (not ErrNotExist)", err)
	}
	afterKey, err := os.ReadFile(ca2.KeyPath())
	if err != nil {
		t.Fatal(err)
	}
	if string(afterKey) != string(originalKey) {
		t.Error("existing CA key was silently replaced")
	}

	// Control: neither file present -> genuine first use still creates.
	fresh, err := LoadOrCreateLocalCA(filepath.Join(t.TempDir(), "fresh"))
	if err != nil {
		t.Errorf("fresh-dir creation err = %v, want nil", err)
	} else if _, err := os.Stat(fresh.CertPath()); err != nil {
		t.Errorf("fresh cert missing: %v", err)
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

// leafWith signs an arbitrary leaf with the CA key, bypassing IssueLeaf, to
// prove the CA certificate itself (not our code) limits what is accepted.
func leafWith(t *testing.T, ca *LocalCA, mutate func(*x509.Certificate)) *x509.Certificate {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(42), Subject: pkix.Name{CommonName: "x"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	mutate(tmpl)
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.Cert, &key.PublicKey, ca.Key)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return c
}

func TestStolenCAKeyCannotMintOtherIdentities(t *testing.T) {
	ca := newTestCA(t)
	verify := func(c *x509.Certificate, usage x509.ExtKeyUsage) error {
		_, err := c.Verify(x509.VerifyOptions{Roots: ca.Pool(), KeyUsages: []x509.ExtKeyUsage{usage}})
		return err
	}

	// An e-mail identity at a real company is outside the permitted namespace.
	mail := leafWith(t, ca, func(c *x509.Certificate) {
		c.EmailAddresses = []string{"ceo@bank.com"}
		c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageEmailProtection}
	})
	if err := verify(mail, x509.ExtKeyUsageEmailProtection); err == nil {
		t.Error("an S/MIME certificate for ceo@bank.com verified against the local CA")
	}
	// A URI identity likewise.
	uri := leafWith(t, ca, func(c *x509.Certificate) {
		u, _ := url.Parse("https://bank.example.com/")
		c.URIs = []*url.URL{u}
	})
	if err := verify(uri, x509.ExtKeyUsageServerAuth); err == nil {
		t.Error("a certificate with a bank URI SAN verified against the local CA")
	}
	// Client auth and code signing are not what this CA is for, even for a local name.
	for name, usage := range map[string]x509.ExtKeyUsage{
		"clientAuth": x509.ExtKeyUsageClientAuth, "codeSigning": x509.ExtKeyUsageCodeSigning, "emailProtection": x509.ExtKeyUsageEmailProtection,
	} {
		c := leafWith(t, ca, func(c *x509.Certificate) {
			c.DNSNames = []string{"app.localhost"}
			c.ExtKeyUsage = []x509.ExtKeyUsage{usage}
		})
		if err := verify(c, usage); err == nil {
			t.Errorf("%s certificate verified against the local CA", name)
		}
	}
	// The one intended use still works.
	ok := leafWith(t, ca, func(c *x509.Certificate) { c.DNSNames = []string{"app.localhost"} })
	if err := verify(ok, x509.ExtKeyUsageServerAuth); err != nil {
		t.Errorf("server certificate for app.localhost: %v", err)
	}
	if w := ca.Legacy(); len(w) != 0 {
		t.Errorf("a freshly created CA reports legacy weaknesses: %v", w)
	}
}

// Writing a CA with the given template mutation into a fresh directory.
func writeCAFrom(t *testing.T, mutate func(*x509.Certificate)) string {
	t.Helper()
	ca := newTestCA(t)
	tmpl := *ca.Cert
	tmpl.Raw, tmpl.RawTBSCertificate = nil, nil
	mutate(&tmpl)
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &ca.Key.PublicKey, ca.Key)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(ca.CertPath(), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		t.Fatal(err)
	}
	return ca.Dir
}

func TestLoadLocalCARefusesTamperedConstraints(t *testing.T) {
	for name, mutate := range map[string]func(*x509.Certificate){
		"permits com": func(c *x509.Certificate) { c.PermittedDNSDomains = []string{"com"} },
		"permits extra": func(c *x509.Certificate) {
			c.PermittedDNSDomains = append([]string{"example.org"}, c.PermittedDNSDomains...)
		},
		"any IP": func(c *x509.Certificate) {
			_, n, _ := net.ParseCIDR("0.0.0.0/0")
			c.PermittedIPRanges = []*net.IPNet{n}
		},
		"no IP constraint": func(c *x509.Certificate) { c.PermittedIPRanges = nil },
		"not critical":     func(c *x509.Certificate) { c.PermittedDNSDomainsCritical = false },
		"deeper path":      func(c *x509.Certificate) { c.MaxPathLen, c.MaxPathLenZero = 3, false },
	} {
		dir := writeCAFrom(t, mutate)
		if _, err := LoadLocalCA(dir); err == nil {
			t.Errorf("%s: a CA with weakened constraints was accepted (it would be trusted system-wide)", name)
		}
	}
}

// CAs created by v1.8/v1.9 lack the EKU and e-mail/URI constraints: they keep
// working but are flagged so users can recreate them.
func TestLegacyCAIsAcceptedButFlagged(t *testing.T) {
	dir := writeCAFrom(t, func(c *x509.Certificate) {
		c.ExtKeyUsage = nil
		c.PermittedEmailAddresses = nil
		c.PermittedURIDomains = nil
	})
	ca, err := LoadLocalCA(dir)
	if err != nil {
		t.Fatalf("legacy CA refused: %v", err)
	}
	if w := ca.Legacy(); len(w) != 2 {
		t.Errorf("Legacy() = %v, want both weaknesses", w)
	}
}

// Two processes creating the CA at the same time must end up with one valid,
// matching key/certificate pair (they used to interleave into a broken pair).
func TestConcurrentCreationYieldsOneConsistentCA(t *testing.T) {
	for i := 0; i < 150; i++ {
		dir := filepath.Join(t.TempDir(), "ca")
		const workers = 4
		certs := make([]*LocalCA, workers)
		errs := make([]error, workers)
		var wg sync.WaitGroup
		for w := 0; w < workers; w++ {
			wg.Add(1)
			go func(w int) {
				defer wg.Done()
				certs[w], errs[w] = LoadOrCreateLocalCA(dir)
			}(w)
		}
		wg.Wait()
		for w := 0; w < workers; w++ {
			if errs[w] != nil {
				t.Fatalf("iteration %d worker %d: %v", i, w, errs[w])
			}
			if !certs[w].Cert.Equal(certs[0].Cert) {
				t.Fatalf("iteration %d: workers ended up with different CAs", i)
			}
		}
		if _, err := LoadLocalCA(dir); err != nil {
			t.Fatalf("iteration %d: the CA on disk is broken: %v", i, err)
		}
		if fileExists(filepath.Join(dir, createLockFile)) {
			t.Fatalf("iteration %d: the lock file was left behind", i)
		}
	}
}

func TestStaleCreateLockIsBroken(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "ca")
	os.MkdirAll(dir, 0o700)
	lock := filepath.Join(dir, createLockFile)
	os.WriteFile(lock, nil, 0o600)
	old := time.Now().Add(-2 * createLockStale)
	os.Chtimes(lock, old, old)
	if _, err := LoadOrCreateLocalCA(dir); err != nil {
		t.Fatalf("a lock left by a crashed process blocked creation: %v", err)
	}
}

func TestLeafProviderDoesNotChurnWhenCapturedByCAExpiry(t *testing.T) {
	ca := newTestCA(t)
	ca.Cert.NotAfter = time.Now().Add(10 * 24 * time.Hour).Truncate(time.Second) // CA about to expire: every leaf is capped to it (certificates have second precision)
	p, err := ca.NewLeafProvider("localhost")
	if err != nil {
		t.Fatal(err)
	}
	a, _ := p.GetCertificate(&tlsClientHello{ServerName: "a.localhost"})
	b, _ := p.GetCertificate(&tlsClientHello{ServerName: "a.localhost"})
	if a != b {
		t.Error("a leaf capped at the CA expiry is re-issued on every handshake")
	}
}

// Deterministic version of the race macOS CI found: while one process is
// between writing the key and writing the certificate, a second process must
// wait for it instead of reporting a "half-broken" CA.
func TestSecondProcessWaitsWhileTheFirstIsBetweenKeyAndCertificate(t *testing.T) {
	inWindow := make(chan struct{})
	release := make(chan struct{})
	betweenCAFilesHook = func() {
		close(inWindow)
		<-release
	}
	defer func() { betweenCAFilesHook = nil }()

	dir := filepath.Join(t.TempDir(), "ca")
	first := make(chan error, 1)
	go func() { _, err := LoadOrCreateLocalCA(dir); first <- err }()
	<-inWindow // the key exists, the certificate does not

	second := make(chan error, 1)
	var got *LocalCA
	go func() {
		var err error
		got, err = LoadOrCreateLocalCA(dir)
		second <- err
	}()

	select {
	case err := <-second:
		t.Fatalf("the second caller returned while the first was mid-creation: %v", err)
	case <-time.After(300 * time.Millisecond): // it is waiting, as it should
	}
	close(release)
	if err := <-first; err != nil {
		t.Fatal(err)
	}
	if err := <-second; err != nil {
		t.Fatalf("second caller: %v", err)
	}
	if got == nil || got.Cert == nil {
		t.Fatal("second caller got no CA")
	}
	if loaded, err := LoadLocalCA(dir); err != nil || !loaded.Cert.Equal(got.Cert) {
		t.Errorf("the CA on disk differs from the one returned: %v", err)
	}
}
