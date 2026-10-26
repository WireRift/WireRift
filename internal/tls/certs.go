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
	"sync/atomic"
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

	// Certificate cache (bounded by maxCachedCerts)
	certs     sync.Map // map[string]*tls.Certificate
	certCount atomic.Int64

	// retryAfter holds, per host, the earliest time ACME may be tried again
	// after a failure. While it is in the future the host is served a
	// short-lived self-signed fallback (AutoCert) or refused, instead of
	// repeating a failing ACME order per handshake and instead of caching a
	// fallback for a year.
	retryAfter sync.Map // map[string]time.Time

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

	// allowHost, when set, decides which host names may get a certificate:
	// every name except the base domain itself must pass it (custom domains
	// and subdomains with a live tunnel), so nobody can trigger issuance for
	// arbitrary names. Unset: any subdomain of the base domain is served.
	allowMu   sync.RWMutex
	allowHost func(host string) bool
}

const (
	// maxCachedCerts bounds the in-memory certificate cache.
	maxCachedCerts = 4096
	// acmeRetryDelay is how long a failed ACME host waits before the next order.
	acmeRetryDelay = 5 * time.Minute
	// acmeOrderTimeout bounds one ACME order (shared by coalesced waiters).
	acmeOrderTimeout = 2 * time.Minute
)

// storeCert caches a certificate, keeping the cache bounded.
func (m *Manager) storeCert(host string, cert *tls.Certificate) {
	if _, existed := m.certs.Swap(host, cert); !existed && m.certCount.Add(1) > maxCachedCerts {
		// Over the limit: drop about half of the entries (arbitrary ones).
		var n int
		m.certs.Range(func(k, _ any) bool {
			if k != host {
				m.certs.Delete(k)
				m.certCount.Add(-1)
				n++
			}
			return n < maxCachedCerts/2
		})
	}
}

func (m *Manager) dropCert(host string) {
	if _, loaded := m.certs.LoadAndDelete(host); loaded {
		m.certCount.Add(-1)
	}
}

// SetHostAllower sets the callback that decides whether a host outside the base
// domain may get a certificate. Without it, only the base domain and its
// subdomains are served.
func (m *Manager) SetHostAllower(allow func(host string) bool) {
	m.allowMu.Lock()
	m.allowHost = allow
	m.allowMu.Unlock()
}

func (m *Manager) allowerSet() bool {
	m.allowMu.RLock()
	defer m.allowMu.RUnlock()
	return m.allowHost != nil
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

	// Check cache first (dropping entries that are expired or about to be, and
	// short-lived fallbacks whose retry time has come)
	if cached, ok := m.certs.Load(host); ok {
		c := cached.(*tls.Certificate)
		if certUsable(c) && !m.fallbackExpired(host) {
			return c, nil
		}
		m.dropCert(host)
	}

	return m.issueCoalesced(hello.Context(), host)
}

// issueCoalesced runs one issuance for host, shared by every concurrent caller.
// parent supplies values only (nil is fine): the order must not be cancelled
// when the first caller goes away.
func (m *Manager) issueCoalesced(parent context.Context, host string) (*tls.Certificate, error) {
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

	// Always release the waiters, even if issuing panics (they would block
	// forever otherwise and the host could never be issued again).
	call.err = errors.New("certificate issuance aborted")
	defer func() {
		close(call.done)
		m.issueMu.Lock()
		delete(m.inflight, host)
		m.issueMu.Unlock()
	}()

	// The order is shared by every coalesced waiter, so it must not die with
	// the first client's connection: detach from that client's cancellation.
	if parent == nil {
		parent = context.Background() // a hand-built ClientHelloInfo has no context
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(parent), acmeOrderTimeout)
	defer cancel()
	cert, err := m.issueCertificate(ctx, host)
	call.cert, call.err = cert, err
	return cert, err
}

// RenewalCheckInterval is how often StartRenewal looks for certificates that
// have entered the renewal window.
const RenewalCheckInterval = 12 * time.Hour

// StartRenewal renews certificates in the background until ctx ends, so a
// certificate is replaced before the first visitor after the renewal window
// opens has to wait for (or lose to) an ACME order. Only hosts that are still
// allowed are renewed; a failed renewal keeps serving the old certificate and
// is retried at the next tick.
func (m *Manager) StartRenewal(ctx context.Context, every time.Duration) {
	if m.acme == nil || every <= 0 {
		return
	}
	go func() {
		t := time.NewTicker(every)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				m.renewDue(ctx)
			}
		}
	}()
}

// renewDue renews every cached certificate that is inside the renewal window.
func (m *Manager) renewDue(ctx context.Context) {
	m.pruneRetries()
	due := map[string]*tls.Certificate{}
	m.certs.Range(func(k, v any) bool {
		if c := v.(*tls.Certificate); !certUsable(c) && certNotExpired(c) {
			due[k.(string)] = c
		}
		return true
	})
	for host, old := range due {
		if ctx.Err() != nil {
			return
		}
		if _, err := m.normalizeHost(host); err != nil {
			continue // no longer a host we serve
		}
		m.dropCert(host)
		cert, err := m.issueCoalesced(ctx, host)
		// A failed order leaves a retry time behind and may have produced a
		// self-signed stand-in; the old certificate is still valid and better.
		if _, backoff := m.retryAfter.Load(host); err != nil || backoff {
			if err != nil {
				slog.Warn("certificate renewal failed", "host", host, "error", err)
			}
			m.storeCert(host, old)
			continue
		}
		m.storeCert(host, cert)
	}
}

// pruneRetries forgets finished back-off windows of hosts that have no cached
// certificate (anymore), so the map does not keep an entry for every host that
// ever failed to get one. A host with a cached fallback keeps its entry:
// fallbackExpired needs it to notice the end of the window.
func (m *Manager) pruneRetries() {
	m.retryAfter.Range(func(k, v any) bool {
		if time.Now().After(v.(time.Time)) {
			if _, cached := m.certs.Load(k); !cached {
				m.retryAfter.Delete(k)
			}
		}
		return true
	})
}

// fallbackExpired reports (and clears) a finished retry window for a host that
// is currently served a temporary fallback certificate.
func (m *Manager) fallbackExpired(host string) bool {
	if until, ok := m.retryAfter.Load(host); ok && time.Now().After(until.(time.Time)) {
		m.retryAfter.Delete(host)
		return true
	}
	return false
}

// issueCertificate obtains a certificate for host: disk, then ACME, then (with
// AutoCert) a self-signed fallback.
func (m *Manager) issueCertificate(ctx context.Context, host string) (*tls.Certificate, error) {
	// Try to load from disk
	cert, err := m.loadCertificate(host)
	if err == nil && certUsable(cert) {
		m.storeCert(host, cert)
		return cert, nil
	}

	// Try ACME (Let's Encrypt) first, unless it failed recently.
	if m.acme != nil {
		if until, ok := m.retryAfter.Load(host); !ok || time.Now().After(until.(time.Time)) {
			bundle, err := m.acme.ObtainCertificate(ctx, []string{host})
			if err == nil {
				tlsCert, terr := bundle.TLSCertificate()
				if terr == nil {
					m.retryAfter.Delete(host)
					m.storeCert(host, tlsCert)
					slog.Info("ACME certificate obtained", "host", host)
					return tlsCert, nil
				}
				err = terr
			}
			slog.Warn("ACME failed, falling back", "host", host, "error", err)
			m.retryAfter.Store(host, time.Now().Add(acmeRetryDelay))
		}
	}

	// With ACME, a certificate inside the renewal window is still valid: when
	// renewal failed or is backing off, serve it rather than a self-signed
	// stand-in. (Without ACME the on-disk cert is itself self-signed and is
	// regenerated below.)
	if m.acme != nil && err == nil && certNotExpired(cert) {
		return cert, nil
	}

	// Fallback: generate self-signed for development. When ACME is enabled this
	// is only a stop-gap until the retry time (not a year-long sticky cert).
	if m.config.AutoCert {
		cert, err = m.generateSelfSigned(host)
		if err != nil {
			return nil, fmt.Errorf("generate certificate: %w", err)
		}
		m.storeCert(host, cert)
		return cert, nil
	}

	return nil, ErrCertificateNotFound
}

// certRenewWindow is how long before expiry a certificate stops being served
// from cache/disk so that it is re-issued.
const certRenewWindow = 14 * 24 * time.Hour

// certUsable reports whether c is not expired and not within the renewal window.
func certUsable(c *tls.Certificate) bool {
	return certValidFor(c, certRenewWindow)
}

// certNotExpired reports whether c has not expired yet, renewal window aside.
func certNotExpired(c *tls.Certificate) bool {
	return certValidFor(c, 0)
}

// certValidFor reports whether c is still valid d from now.
func certValidFor(c *tls.Certificate, d time.Duration) bool {
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
	return time.Now().Add(d).Before(leaf.NotAfter)
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
	base := strings.ToLower(m.config.Domain)
	if base != "" && host == base {
		return host, nil // the base domain itself is always served
	}
	underBase := base != "" && strings.HasSuffix(host, "."+base)
	if !underBase || m.allowerSet() {
		// Outside the base domain (custom domains) a vouching callback is
		// required; under it, one is enforced whenever the server set it.
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
