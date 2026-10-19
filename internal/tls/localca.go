package tls

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// LocalCAName is the subject common name (and trust-store label) of the
// development CA.
const LocalCAName = "WireRift Local Development CA"

// localCAPermittedDomains are the only DNS names the development CA may ever
// issue for (RFC 6761 names that never exist on the public internet). A name
// constraint without a leading dot matches the domain and all its subdomains.
//
// This is what makes it safe to install the CA in the system trust store: even
// if the CA private key leaks, a certificate for any other site (a bank, a
// mail provider, ...) fails verification in every client that enforces name
// constraints (Go, Chrome, Firefox, Safari, OpenSSL).
var localCAPermittedDomains = []string{"localhost", "test"}

// localCAPermittedIPs restricts IP SANs to loopback.
var localCAPermittedIPs = []string{"127.0.0.0/8", "::1/128"}

// ErrNameNotPermitted is returned when a leaf is requested for a name outside
// the development CA's permitted namespace.
var ErrNameNotPermitted = errors.New("name not permitted by the local CA (only .localhost and .test are allowed)")

const (
	localCAFile    = "rootCA.pem"
	localCAKeyFile = "rootCA-key.pem"

	localCAValidity   = 10 * 365 * 24 * time.Hour
	localLeafValidity = 365 * 24 * time.Hour
	localLeafRenewal  = 30 * 24 * time.Hour
)

// LocalCA is a persistent, name-constrained certificate authority for local
// development HTTPS.
type LocalCA struct {
	Cert *x509.Certificate
	Key  *ecdsa.PrivateKey

	// Dir is the directory holding the CA files.
	Dir string
}

// DefaultLocalCADir returns the per-user directory for the development CA.
func DefaultLocalCADir() (string, error) {
	base, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("locate user config dir: %w", err)
	}
	return filepath.Join(base, "wirerift", "local-ca"), nil
}

// CertPath returns the path of the CA certificate (PEM).
func (ca *LocalCA) CertPath() string { return filepath.Join(ca.Dir, localCAFile) }

// KeyPath returns the path of the CA private key (PEM).
func (ca *LocalCA) KeyPath() string { return filepath.Join(ca.Dir, localCAKeyFile) }

// PEM returns the CA certificate in PEM form.
func (ca *LocalCA) PEM() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Cert.Raw})
}

// Pool returns a certificate pool containing only this CA.
func (ca *LocalCA) Pool() *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AddCert(ca.Cert)
	return pool
}

// LoadOrCreateLocalCA loads the CA from dir, creating it on first use. An
// existing but unreadable/invalid CA is an error: a CA that users already
// trust must never be silently replaced.
func LoadOrCreateLocalCA(dir string) (*LocalCA, error) {
	if ca, err := loadExistingOrExplain(dir); ca != nil || !errors.Is(err, os.ErrNotExist) {
		return ca, err
	}
	return createLocalCALocked(dir)
}

// loadExistingOrExplain returns the CA when it loads. A missing CA yields an
// error wrapping os.ErrNotExist ("first use"); every other problem is a hard
// error that must never lead to the CA being recreated.
func loadExistingOrExplain(dir string) (*LocalCA, error) {
	ca, err := LoadLocalCA(dir)
	if err == nil {
		return ca, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	// ErrNotExist only means "first use" when neither CA file exists. A lone
	// certificate or key is a half-broken CA users may already trust;
	// recreating it silently is exactly what this function must never do.
	if fileExists(filepath.Join(dir, localCAFile)) || fileExists(filepath.Join(dir, localCAKeyFile)) {
		// Not wrapping ErrNotExist: callers must not read this state as
		// "nothing there yet, go ahead and create".
		return nil, fmt.Errorf("local CA is incomplete: %v; restore the missing file in %s, or delete both files to create and trust a new CA", err, dir)
	}
	return nil, err
}

const (
	createLockFile  = ".create.lock"
	createLockStale = 30 * time.Second
	createLockWait  = 10 * time.Second
)

// createLocalCALocked creates the CA while holding an exclusive lock file, so
// two processes starting at once (`ca trust` and `-dev`, say) cannot interleave
// their key and certificate writes into a mismatched pair.
func createLocalCALocked(dir string) (*LocalCA, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create local CA dir: %w", err)
	}
	lock := filepath.Join(dir, createLockFile)
	deadline := time.Now().Add(createLockWait)
	for {
		f, err := os.OpenFile(lock, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err == nil {
			f.Close()
			defer os.Remove(lock)
			break
		}
		if !errors.Is(err, os.ErrExist) {
			return nil, fmt.Errorf("lock local CA dir: %w", err)
		}
		// Someone else is creating it: use their result once it is complete.
		if ca, lerr := LoadLocalCA(dir); lerr == nil {
			return ca, nil
		}
		if st, serr := os.Stat(lock); serr == nil && time.Since(st.ModTime()) > createLockStale {
			_ = os.Remove(lock) // left behind by a crashed process
			continue
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("timed out waiting for another process to create the local CA in %s", dir)
		}
		time.Sleep(25 * time.Millisecond)
	}

	// Re-check under the lock: another process may have finished meanwhile.
	if ca, err := loadExistingOrExplain(dir); ca != nil || !errors.Is(err, os.ErrNotExist) {
		return ca, err
	}
	return createLocalCA(dir)
}

// fileExists reports whether path exists.
func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// LoadLocalCA loads an existing CA from dir. It returns an error wrapping
// os.ErrNotExist when no CA has been created yet.
func LoadLocalCA(dir string) (*LocalCA, error) {
	certPEM, err := os.ReadFile(filepath.Join(dir, localCAFile))
	if err != nil {
		return nil, fmt.Errorf("read local CA certificate: %w", err)
	}
	keyPEM, err := os.ReadFile(filepath.Join(dir, localCAKeyFile))
	if err != nil {
		return nil, fmt.Errorf("read local CA key: %w", err)
	}

	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil || certBlock.Type != "CERTIFICATE" {
		return nil, errors.New("local CA certificate is not valid PEM")
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse local CA certificate: %w", err)
	}
	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, errors.New("local CA key is not valid PEM")
	}
	key, err := x509.ParseECPrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse local CA key: %w", err)
	}
	if pub, ok := cert.PublicKey.(*ecdsa.PublicKey); !ok || !pub.Equal(&key.PublicKey) {
		return nil, errors.New("local CA key does not match its certificate")
	}
	if err := validateCAConstraints(cert); err != nil {
		return nil, err
	}
	if time.Now().After(cert.NotAfter) {
		return nil, errors.New("local CA certificate has expired; delete it, create a new one and trust it again")
	}
	return &LocalCA{Cert: cert, Key: key, Dir: dir}, nil
}

func createLocalCA(dir string) (*LocalCA, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create local CA dir: %w", err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate local CA key: %w", err)
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}

	ipRanges := make([]*net.IPNet, 0, len(localCAPermittedIPs))
	for _, cidr := range localCAPermittedIPs {
		_, n, _ := net.ParseCIDR(cidr)
		ipRanges = append(ipRanges, n)
	}

	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: LocalCAName, Organization: []string{"WireRift"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(localCAValidity),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,

		// Only TLS server certificates, and nothing for e-mail or URIs outside
		// the local namespace: a leaked key cannot mint S/MIME, client-auth or
		// code-signing identities for real people or sites either.
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},

		PermittedDNSDomainsCritical: true,
		PermittedDNSDomains:         localCAPermittedDomains,
		PermittedIPRanges:           ipRanges,
		PermittedEmailAddresses:     localCAPermittedDomains,
		PermittedURIDomains:         localCAPermittedDomains,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("create local CA certificate: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("parse new local CA certificate: %w", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("encode local CA key: %w", err)
	}

	ca := &LocalCA{Cert: cert, Key: key, Dir: dir}
	// Write the key first (0600) so a half-written CA is never trustable.
	if err := writeFileAtomicMode(ca.KeyPath(), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		return nil, fmt.Errorf("write local CA key: %w", err)
	}
	if err := writeFileAtomicMode(ca.CertPath(), ca.PEM(), 0o644); err != nil {
		return nil, fmt.Errorf("write local CA certificate: %w", err)
	}
	return ca, nil
}

func randomSerial() (*big.Int, error) {
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return nil, fmt.Errorf("generate serial: %w", err)
	}
	return serial.Add(serial, big.NewInt(1)), nil
}

func writeFileAtomicMode(path string, data []byte, mode os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name()) // no-op after a successful rename
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// namePermitted reports whether a SAN is inside the CA's permitted namespace.
func namePermitted(name string) bool {
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	name = strings.TrimPrefix(name, "*.")
	if name == "" {
		return false
	}
	if ip := net.ParseIP(name); ip != nil {
		for _, cidr := range localCAPermittedIPs {
			if _, n, _ := net.ParseCIDR(cidr); n.Contains(ip) {
				return true
			}
		}
		return false
	}
	for _, d := range localCAPermittedDomains {
		if name == d || strings.HasSuffix(name, "."+d) {
			return true
		}
	}
	return false
}

// IssueLeaf issues a server certificate for names (DNS names, "*.x" wildcards
// and loopback IPs). Names outside the permitted namespace are rejected.
func (ca *LocalCA) IssueLeaf(names []string) (*tls.Certificate, error) {
	if len(names) == 0 {
		return nil, errors.New("no names given")
	}
	var dns []string
	var ips []net.IP
	for _, n := range names {
		if !namePermitted(n) {
			return nil, fmt.Errorf("%w: %q", ErrNameNotPermitted, n)
		}
		if ip := net.ParseIP(n); ip != nil {
			ips = append(ips, ip)
		} else {
			dns = append(dns, strings.ToLower(strings.TrimSuffix(n, ".")))
		}
	}
	return ca.signLeaf(dns, ips)
}

// signLeaf signs without validating names (tests use it to prove the CA's
// constraints, not this function, are what stop out-of-scope certificates).
func (ca *LocalCA) signLeaf(dns []string, ips []net.IP) (*tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate leaf key: %w", err)
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	cn := "WireRift local"
	if len(dns) > 0 {
		cn = dns[0]
	}
	notAfter := time.Now().Add(localLeafValidity)
	if notAfter.After(ca.Cert.NotAfter) {
		notAfter = ca.Cert.NotAfter
	}
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: cn},
		DNSNames:     dns,
		IPAddresses:  ips,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca.Cert, &key.PublicKey, ca.Key)
	if err != nil {
		return nil, fmt.Errorf("sign leaf: %w", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("parse leaf: %w", err)
	}
	return &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, nil
}

// maxLeafCache bounds the per-host certificate cache.
const maxLeafCache = 512

// LeafProvider serves a certificate for the exact host a client asks for
// (SNI), under one base domain, and reissues it before it expires.
//
// It issues exact names on demand instead of one wildcard certificate:
// OpenSSL/curl (and browsers' wildcard rules) refuse "*.localhost" because the
// suffix is a single label, i.e. looks like a top-level domain.
//
// It is safe for concurrent use and suitable for tls.Config.GetCertificate.
type LeafProvider struct {
	ca   *LocalCA
	base string

	mu    sync.Mutex
	certs map[string]*tls.Certificate
}

// NewLeafProvider creates a provider for base and everything below it. The
// base must itself be inside the CA's permitted namespace.
func (ca *LocalCA) NewLeafProvider(base string) (*LeafProvider, error) {
	base = strings.ToLower(strings.TrimSuffix(base, "."))
	if base == "" || net.ParseIP(base) != nil || !namePermitted(base) {
		return nil, fmt.Errorf("%w: %q", ErrNameNotPermitted, base)
	}
	p := &LeafProvider{ca: ca, base: base, certs: make(map[string]*tls.Certificate)}
	if _, err := p.certFor(base); err != nil { // fail fast
		return nil, err
	}
	return p, nil
}

// validHostLabel reports whether s is a plain DNS name made of letters,
// digits, hyphens and dots (no empty labels).
func validHostName(s string) bool {
	if s == "" || len(s) > 253 {
		return false
	}
	for _, label := range strings.Split(s, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}

func (p *LeafProvider) certFor(host string) (*tls.Certificate, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if c, ok := p.certs[host]; ok {
		// A leaf capped at the CA's own expiry cannot be renewed into anything
		// longer, so only renew while a longer-lived one is possible.
		if time.Until(c.Leaf.NotAfter) > localLeafRenewal || !c.Leaf.NotAfter.Before(p.ca.Cert.NotAfter) {
			return c, nil
		}
	}
	names := []string{host}
	if host == p.base {
		names = append(names, "127.0.0.1", "::1") // reachable by IP as well
	}
	cert, err := p.ca.IssueLeaf(names)
	if err != nil {
		return nil, err
	}
	if len(p.certs) >= maxLeafCache {
		p.certs = make(map[string]*tls.Certificate)
	}
	p.certs[host] = cert
	return cert, nil
}

// GetCertificate implements tls.Config.GetCertificate. A missing SNI (a
// client connecting by IP) gets the base domain's certificate.
func (p *LeafProvider) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	host := p.base
	if hello != nil && hello.ServerName != "" {
		host = strings.ToLower(strings.TrimSuffix(hello.ServerName, "."))
	}
	if !validHostName(host) || (host != p.base && !strings.HasSuffix(host, "."+p.base)) {
		return nil, fmt.Errorf("%w: %q is not under %q", ErrNameNotPermitted, host, p.base)
	}
	return p.certFor(host)
}

// TLSConfig returns a server TLS configuration using the provider.
func (p *LeafProvider) TLSConfig() *tls.Config {
	return &tls.Config{
		MinVersion:     tls.VersionTLS12,
		GetCertificate: p.GetCertificate,
		NextProtos:     []string{"h2", "http/1.1"},
	}
}

// LocalNamePermitted reports whether name may be served with the local CA
// (a domain under .localhost or .test, or loopback IP).
func LocalNamePermitted(name string) bool { return namePermitted(name) }

// Fingerprint returns the SHA-256 fingerprint of the CA certificate.
func (ca *LocalCA) Fingerprint() string {
	sum := sha256.Sum256(ca.Cert.Raw)
	return strings.ToUpper(hex.EncodeToString(sum[:]))
}

// validateCAConstraints refuses a CA whose constraints are not the ones this
// version issues (a swapped-in or tampered CA would be trusted system-wide
// when installed).
func validateCAConstraints(cert *x509.Certificate) error {
	bad := func(what string) error {
		return fmt.Errorf("local CA certificate %s; delete it and let WireRift create a new one", what)
	}
	if !cert.IsCA || !cert.BasicConstraintsValid || !cert.MaxPathLenZero {
		return bad("is not a path-length-0 CA")
	}
	if !cert.PermittedDNSDomainsCritical || len(cert.PermittedDNSDomains) == 0 {
		return bad("lacks critical DNS name constraints")
	}
	for _, d := range cert.PermittedDNSDomains {
		if !containsString(localCAPermittedDomains, d) {
			return bad(fmt.Sprintf("permits the DNS name %q, which this CA must never issue for", d))
		}
	}
	if len(cert.PermittedIPRanges) == 0 {
		return bad("lacks IP name constraints")
	}
	for _, n := range cert.PermittedIPRanges {
		if !containsString(localCAPermittedIPs, n.String()) {
			return bad(fmt.Sprintf("permits the IP range %s, which this CA must never issue for", n))
		}
	}
	return nil
}

func containsString(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// Legacy lists weaknesses of a CA created by an older version: it still works
// (and is still name-constrained for DNS names and IPs) but could sign
// certificates for other uses. Recreating the CA fixes it.
func (ca *LocalCA) Legacy() []string {
	var w []string
	if len(ca.Cert.ExtKeyUsage) != 1 || ca.Cert.ExtKeyUsage[0] != x509.ExtKeyUsageServerAuth {
		w = append(w, "not restricted to TLS server authentication")
	}
	if len(ca.Cert.PermittedEmailAddresses) == 0 || len(ca.Cert.PermittedURIDomains) == 0 {
		w = append(w, "no e-mail/URI name constraints")
	}
	return w
}
