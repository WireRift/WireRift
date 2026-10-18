package tls

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Errors returned by TLS operations.
var (
	ErrCertificateNotFound = errors.New("certificate not found")
	ErrDomainNotConfigured = errors.New("domain not configured")
)

// Config holds TLS configuration.
type Config struct {
	// Domain is the base domain for tunnels.
	Domain string

	// CertDir is the directory for storing certificates.
	CertDir string

	// Email for ACME registration (Let's Encrypt).
	Email string

	// UseStaging uses Let's Encrypt staging server.
	UseStaging bool

	// AutoCert enables automatic certificate generation.
	AutoCert bool
}

// Manager manages TLS certificates.
type Manager struct {
	config Config

	// Certificate cache
	certs sync.Map // map[string]*tls.Certificate

	// Per-host coalescing of concurrent issuances: parallel handshakes for
	// the same uncached host (a browser opens ~6 connections at once) must
	// run one disk load / ACME order, not one per connection.
	issueMu  sync.Mutex
	inflight map[string]*issueCall

	// CA certificate for development
	caCert *x509.Certificate
	caKey  *ecdsa.PrivateKey
	caOnce sync.Once

	// ACME (Let's Encrypt)
	acme *ACMEManager

	// allowHost, when set, admits host names outside the base domain (custom
	// domains) so certificates are only requested for names the server vouches for.
	allowMu   sync.RWMutex
	allowHost func(host string) bool
}

// SetHostAllower sets the callback that decides whether a host outside the base
// domain may get a certificate. Without it, only the base domain and its
// subdomains are served.
func (m *Manager) SetHostAllower(allow func(host string) bool) {
	m.allowMu.Lock()
	m.allowHost = allow
	m.allowMu.Unlock()
}

func (m *Manager) hostAllowed(host string) bool {
	m.allowMu.RLock()
	allow := m.allowHost
	m.allowMu.RUnlock()
	return allow != nil && allow(host)
}

// issueCall tracks one in-flight certificate issuance for a host. Waiters
// receive the leader's result after done is closed.
type issueCall struct {
	done chan struct{}
	cert *tls.Certificate
	err  error
}

// NewManager creates a new TLS manager.
func NewManager(config Config) (*Manager, error) {
	if config.Domain == "" {
		config.Domain = "localhost"
	}
	if config.CertDir == "" {
		config.CertDir = "./certs"
	}

	m := &Manager{
		config: config,
	}

	// Ensure cert directory exists
	if err := os.MkdirAll(config.CertDir, 0700); err != nil {
		return nil, fmt.Errorf("create cert dir: %w", err)
	}

	// Initialize ACME if email is provided
	if config.Email != "" {
		acmeMgr, err := NewACMEManager(config.Email, config.CertDir, config.UseStaging, nil)
		if err != nil {
			return nil, fmt.Errorf("ACME init: %w", err)
		}
		if err := acmeMgr.Initialize(); err != nil {
			slog.Warn("ACME initialization failed, falling back to self-signed", "error", err)
		} else {
			m.acme = acmeMgr
			slog.Info("ACME enabled (Let's Encrypt)", "staging", config.UseStaging)
		}
	}

	return m, nil
}

// GetCertificate returns a certificate for the given host.
func (m *Manager) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	host, err := m.normalizeHost(hello.ServerName)
	if err != nil {
		return nil, err
	}

	// Check cache first (dropping entries that are expired or about to be)
	if cached, ok := m.certs.Load(host); ok {
		if c := cached.(*tls.Certificate); certUsable(c) {
			return c, nil
		}
		m.certs.Delete(host)
	}

	// Coalesce concurrent issuances for the same host: parallel handshakes
	// for one uncached host must run a single disk load / ACME order, not
	// one per connection.
	m.issueMu.Lock()
	if call, ok := m.inflight[host]; ok {
		m.issueMu.Unlock()
		<-call.done
		if call.err != nil {
			return nil, call.err
		}
		return call.cert, nil
	}
	call := &issueCall{done: make(chan struct{})}
	if m.inflight == nil {
		m.inflight = make(map[string]*issueCall)
	}
	m.inflight[host] = call
	m.issueMu.Unlock()

	cert, err := m.issueCertificate(hello.Context(), host)

	call.cert, call.err = cert, err
	close(call.done)

	m.issueMu.Lock()
	delete(m.inflight, host)
	m.issueMu.Unlock()

	return cert, err
}

// issueCertificate runs the full issuance path for a host: disk cache,
// then ACME, then the self-signed development fallback. The caller must
// have registered itself as the leader for this host.
func (m *Manager) issueCertificate(ctx context.Context, host string) (*tls.Certificate, error) {
	// Try to load from disk
	cert, err := m.loadCertificate(host)
	if err == nil && certUsable(cert) {
		m.certs.Store(host, cert)
		return cert, nil
	}

	// Try ACME (Let's Encrypt) first
	if m.acme != nil {
		bundle, err := m.acme.ObtainCertificate(ctx, []string{host})
		if err == nil {
			tlsCert, err := bundle.TLSCertificate()
			if err == nil {
				m.certs.Store(host, tlsCert)
				slog.Info("ACME certificate obtained", "host", host)
				return tlsCert, nil
			}
		}
		slog.Warn("ACME failed, falling back", "host", host, "error", err)
	}

	// Fallback: generate self-signed for development
	if m.config.AutoCert {
		cert, err = m.generateSelfSigned(host)
		if err != nil {
			return nil, fmt.Errorf("generate certificate: %w", err)
		}
		m.certs.Store(host, cert)
		return cert, nil
	}

	return nil, ErrCertificateNotFound
}

// certRenewWindow is how long before expiry a certificate stops being served
// from cache/disk so that it is re-issued.
const certRenewWindow = 14 * 24 * time.Hour

// certUsable reports whether c is not expired and not within the renewal window.
func certUsable(c *tls.Certificate) bool {
	leaf := c.Leaf
	if leaf == nil {
		if len(c.Certificate) == 0 {
			return false
		}
		var err error
		if leaf, err = x509.ParseCertificate(c.Certificate[0]); err != nil {
			return false
		}
	}
	return time.Now().Add(certRenewWindow).Before(leaf.NotAfter)
}

// normalizeHost validates and lowercases a client-supplied SNI name. The name
// is used to build file paths and trigger certificate issuance, so it must be
// a plain hostname under the configured base domain.
func (m *Manager) normalizeHost(name string) (string, error) {
	host := strings.ToLower(strings.TrimSuffix(name, "."))
	if host == "" {
		return "", ErrDomainNotConfigured
	}
	if len(host) > 253 {
		return "", ErrDomainNotConfigured
	}
	for _, label := range strings.Split(host, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", ErrDomainNotConfigured
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return "", ErrDomainNotConfigured
			}
		}
	}
	if base := strings.ToLower(m.config.Domain); base != "" && host != base && !strings.HasSuffix(host, "."+base) {
		if !m.hostAllowed(host) {
			return "", ErrDomainNotConfigured
		}
	}
	return host, nil
}

// loadCertificate loads a certificate from disk.
func (m *Manager) loadCertificate(host string) (*tls.Certificate, error) {
	certPath := filepath.Join(m.config.CertDir, host+".crt")
	keyPath := filepath.Join(m.config.CertDir, host+".key")

	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, err
	}

	return &cert, nil
}

// generateSelfSigned generates a self-signed certificate.
func (m *Manager) generateSelfSigned(host string) (*tls.Certificate, error) {
	m.caOnce.Do(func() {
		m.caCert, m.caKey = m.generateCA()
	})

	// Generate server key (P256 with crypto/rand never fails in practice)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	// Create certificate template
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))

	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: host,
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:  x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
		},
		DNSNames:    []string{host, "*." + m.config.Domain},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
	}

	// Sign with CA
	certDER, err := x509.CreateCertificate(rand.Reader, template, m.caCert, &key.PublicKey, m.caKey)
	if err != nil {
		return nil, fmt.Errorf("create certificate: %w", err)
	}

	// MarshalECPrivateKey cannot fail for a valid ECDSA key
	keyDER, _ := x509.MarshalECPrivateKey(key)

	cert := &tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  key,
		Leaf:        template,
	}

	// Persist only when ACME is not in play: a saved fallback would be loaded
	// ahead of ACME forever and keep serving an untrusted cert.
	if m.acme == nil {
		if err := m.saveCertificate(host, certDER, keyDER); err != nil {
			// Log but don't fail
			slog.Warn("failed to save certificate", "host", host, "error", err)
		}
	}

	return cert, nil
}

// generateCA generates a CA certificate for development.
func (m *Manager) generateCA() (*x509.Certificate, *ecdsa.PrivateKey) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))

	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   "WireRift Development CA",
			Organization: []string{"WireRift"},
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(10 * 365 * 24 * time.Hour),
		IsCA:      true,
		KeyUsage:  x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}

	certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(certDER)

	return cert, key
}

// saveCertificate saves a certificate to disk.
func (m *Manager) saveCertificate(host string, certDER, keyDER []byte) error {
	certPath := filepath.Join(m.config.CertDir, host+".crt")
	keyPath := filepath.Join(m.config.CertDir, host+".key")

	// Write certificate (0600 to protect against unauthorized reads)
	if err := writeFileAtomic(certPath, func(f *os.File) error {
		return pem.Encode(f, &pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	}); err != nil {
		return fmt.Errorf("write certificate: %w", err)
	}

	// Write key
	if err := writeFileAtomic(keyPath, func(f *os.File) error {
		return pem.Encode(f, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	}); err != nil {
		return fmt.Errorf("write private key: %w", err)
	}

	return nil
}

// writeFileAtomic opens a file for writing, calls the writer function,
// then checks the Close error to ensure data is flushed to disk.
func writeFileAtomic(path string, writer func(*os.File) error) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}

	writeErr := writer(f)
	closeErr := f.Close()

	if writeErr != nil {
		return writeErr
	}
	return closeErr
}

// TLSConfig returns a TLS configuration for the server.
func (m *Manager) TLSConfig() *tls.Config {
	return &tls.Config{
		GetCertificate: m.GetCertificate,
		MinVersion:     tls.VersionTLS12,
		CurvePreferences: []tls.CurveID{
			tls.X25519,
			tls.CurveP256,
		},
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		},
	}
}

// ACMEChallengeHandler returns the HTTP handler for ACME HTTP-01 challenges.
// Mount at /.well-known/acme-challenge/ on port 80.
func (m *Manager) ACMEChallengeHandler() http.HandlerFunc {
	if m.acme == nil {
		return func(w http.ResponseWriter, r *http.Request) {
			http.NotFound(w, r)
		}
	}
	return m.acme.ServeChallenge
}

// IsACMEEnabled returns true if Let's Encrypt is configured and active.
func (m *Manager) IsACMEEnabled() bool {
	return m.acme != nil
}
