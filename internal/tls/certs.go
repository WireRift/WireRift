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
	"log/slog"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Errors returned by TLS operations.
var (
	ErrCertificateNotFound = errors.New("certificate not found")
	ErrInvalidCertificate  = errors.New("invalid certificate")
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

	// CA certificate for development
	caCert    *x509.Certificate
	caKey     *ecdsa.PrivateKey
	caOnce    sync.Once
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

	return m, nil
}

// GetCertificate returns a certificate for the given host.
func (m *Manager) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	host := hello.ServerName
	if host == "" {
		return nil, ErrDomainNotConfigured
	}

	// Check cache first
	if cert, ok := m.certs.Load(host); ok {
		return cert.(*tls.Certificate), nil
	}

	// Try to load from disk
	cert, err := m.loadCertificate(host)
	if err == nil {
		m.certs.Store(host, cert)
		return cert, nil
	}

	// Generate self-signed for development
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

	// Save to disk
	if err := m.saveCertificate(host, certDER, keyDER); err != nil {
		// Log but don't fail
		slog.Warn("failed to save certificate", "host", host, "error", err)
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
	certFile, err := os.OpenFile(certPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer certFile.Close()
	if err := pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: certDER}); err != nil {
		return fmt.Errorf("encode certificate: %w", err)
	}

	// Write key
	keyFile, err := os.OpenFile(keyPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer keyFile.Close()
	if err := pem.Encode(keyFile, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}); err != nil {
		return fmt.Errorf("encode private key: %w", err)
	}
	return nil
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

// WildcardDomain returns the wildcard domain for the base domain.
func (m *Manager) WildcardDomain() string {
	return "*." + m.config.Domain
}
