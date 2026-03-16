// Package tls provides ACME (Let's Encrypt) certificate management.
// Implements RFC 8555 with HTTP-01 challenge using only Go stdlib.
package tls

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	cryptotls "crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// ACME directory URLs
const (
	LetsEncryptProduction = "https://acme-v02.api.letsencrypt.org/directory"
	LetsEncryptStaging    = "https://acme-staging-v02.api.letsencrypt.org/directory"
)

// ACME errors
var (
	ErrACMEChallengeFailed = errors.New("ACME challenge failed")
	ErrACMEOrderFailed     = errors.New("ACME order failed")
	ErrACMERateLimited     = errors.New("ACME rate limited")
)

// acmeDirectory holds ACME server endpoint URLs.
type acmeDirectory struct {
	NewNonce   string `json:"newNonce"`
	NewAccount string `json:"newAccount"`
	NewOrder   string `json:"newOrder"`
}

// acmeAccount represents a registered ACME account.
type acmeAccount struct {
	URL string
	Key *ecdsa.PrivateKey
}

// acmeOrder represents a certificate order.
type acmeOrder struct {
	Status         string   `json:"status"`
	Authorizations []string `json:"authorizations"`
	Finalize       string   `json:"finalize"`
	Certificate    string   `json:"certificate"`
}

// acmeAuthorization represents a domain authorization.
type acmeAuthorization struct {
	Status     string          `json:"status"`
	Identifier acmeIdentifier  `json:"identifier"`
	Challenges []acmeChallenge `json:"challenges"`
}

type acmeIdentifier struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

type acmeChallenge struct {
	Type  string `json:"type"`
	URL   string `json:"url"`
	Token string `json:"token"`
	Status string `json:"status"`
}

// ACMEManager handles automatic certificate issuance via Let's Encrypt.
type ACMEManager struct {
	email     string
	certDir   string
	directory acmeDirectory
	account   *acmeAccount
	staging   bool
	logger    *slog.Logger

	// HTTP-01 challenge responses: token -> keyAuth
	challenges sync.Map

	// Pending certificates being issued
	mu sync.Mutex

	httpClient *http.Client
}

// NewACMEManager creates a new ACME certificate manager.
func NewACMEManager(email, certDir string, staging bool, logger *slog.Logger) (*ACMEManager, error) {
	if email == "" {
		return nil, fmt.Errorf("email is required for Let's Encrypt registration")
	}
	if certDir == "" {
		certDir = "./certs"
	}
	if logger == nil {
		logger = slog.Default()
	}

	if err := os.MkdirAll(certDir, 0700); err != nil {
		return nil, fmt.Errorf("create cert dir: %w", err)
	}

	m := &ACMEManager{
		email:      email,
		certDir:    certDir,
		staging:    staging,
		logger:     logger,
		httpClient: &http.Client{Timeout: 30 * time.Second},
	}

	return m, nil
}

// Initialize fetches the ACME directory and registers/loads an account.
func (m *ACMEManager) Initialize() error {
	// 1. Fetch directory
	dirURL := LetsEncryptProduction
	if m.staging {
		dirURL = LetsEncryptStaging
	}
	m.logger.Info("fetching ACME directory", "url", dirURL)

	resp, err := m.httpClient.Get(dirURL)
	if err != nil {
		return fmt.Errorf("fetch directory: %w", err)
	}
	defer resp.Body.Close()

	if err := json.NewDecoder(resp.Body).Decode(&m.directory); err != nil {
		return fmt.Errorf("decode directory: %w", err)
	}

	// 2. Load or create account key
	keyPath := filepath.Join(m.certDir, "acme-account.key")
	key, err := m.loadOrCreateKey(keyPath)
	if err != nil {
		return fmt.Errorf("account key: %w", err)
	}

	m.account = &acmeAccount{Key: key}

	// 3. Register account
	if err := m.registerAccount(); err != nil {
		return fmt.Errorf("register account: %w", err)
	}

	m.logger.Info("ACME initialized", "account", m.account.URL, "staging", m.staging)
	return nil
}

// ObtainCertificate requests a certificate for the given domains.
func (m *ACMEManager) ObtainCertificate(ctx context.Context, domains []string) (*CertificateBundle, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.logger.Info("requesting certificate", "domains", domains)

	// 1. Create order
	orderPayload := map[string]interface{}{
		"identifiers": func() []map[string]string {
			ids := make([]map[string]string, len(domains))
			for i, d := range domains {
				ids[i] = map[string]string{"type": "dns", "value": d}
			}
			return ids
		}(),
	}

	orderBody, _ := json.Marshal(orderPayload)
	resp, err := m.signedPost(ctx, m.directory.NewOrder, orderBody)
	if err != nil {
		return nil, fmt.Errorf("create order: %w", err)
	}

	var order acmeOrder
	if err := json.Unmarshal(resp.body, &order); err != nil {
		return nil, fmt.Errorf("decode order: %w", err)
	}
	orderURL := resp.location

	// 2. Process authorizations
	for _, authzURL := range order.Authorizations {
		if err := m.processAuthorization(ctx, authzURL); err != nil {
			return nil, fmt.Errorf("authorization: %w", err)
		}
	}

	// 3. Wait for order to be ready
	for i := 0; i < 30; i++ {
		orderResp, err := m.signedPost(ctx, orderURL, nil)
		if err != nil {
			return nil, err
		}
		if err := json.Unmarshal(orderResp.body, &order); err != nil {
			return nil, fmt.Errorf("decode order: %w", err)
		}

		if order.Status == "ready" {
			break
		}
		if order.Status == "invalid" {
			return nil, fmt.Errorf("%w: order status invalid", ErrACMEOrderFailed)
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}

	if order.Status != "ready" {
		return nil, fmt.Errorf("%w: order not ready after timeout", ErrACMEOrderFailed)
	}

	// 4. Generate CSR and finalize
	certKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: domains[0]},
		DNSNames: domains,
	}, certKey)
	if err != nil {
		return nil, fmt.Errorf("create CSR: %w", err)
	}

	finalizePayload, _ := json.Marshal(map[string]string{
		"csr": base64URLEncode(csr),
	})

	resp, err = m.signedPost(ctx, order.Finalize, finalizePayload)
	if err != nil {
		return nil, fmt.Errorf("finalize: %w", err)
	}
	if err := json.Unmarshal(resp.body, &order); err != nil {
		return nil, fmt.Errorf("decode finalize response: %w", err)
	}

	// 5. Wait for certificate
	for i := 0; i < 30; i++ {
		if order.Certificate != "" {
			break
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(2 * time.Second):
		}
		orderResp, err := m.signedPost(ctx, orderURL, nil)
		if err != nil {
			continue
		}
		if err := json.Unmarshal(orderResp.body, &order); err != nil {
			continue
		}
	}

	if order.Certificate == "" {
		return nil, fmt.Errorf("%w: certificate URL not available", ErrACMEOrderFailed)
	}

	// 6. Download certificate
	certResp, err := m.signedPost(ctx, order.Certificate, nil)
	if err != nil {
		return nil, fmt.Errorf("download certificate: %w", err)
	}

	bundle := &CertificateBundle{
		CertPEM:    certResp.body,
		PrivateKey: certKey,
		Domains:    domains,
		IssuedAt:   time.Now(),
		ExpiresAt:  time.Now().Add(90 * 24 * time.Hour), // Let's Encrypt standard
	}

	// 7. Save to disk
	if err := m.saveCertBundle(domains[0], bundle); err != nil {
		m.logger.Warn("failed to save certificate", "error", err)
	}

	m.logger.Info("certificate obtained", "domains", domains)
	return bundle, nil
}

// CertificateBundle holds a certificate and its private key.
type CertificateBundle struct {
	CertPEM    []byte
	PrivateKey *ecdsa.PrivateKey
	Domains    []string
	IssuedAt   time.Time
	ExpiresAt  time.Time
}

// TLSCertificate converts the bundle to a crypto/tls.Certificate.
func (b *CertificateBundle) TLSCertificate() (*cryptotls.Certificate, error) {
	keyDER, _ := x509.MarshalECPrivateKey(b.PrivateKey)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	cert, err := cryptotls.X509KeyPair(b.CertPEM, keyPEM)
	if err != nil {
		return nil, err
	}
	return &cert, nil
}

// NeedsRenewal returns true if the certificate expires within 30 days.
func (b *CertificateBundle) NeedsRenewal() bool {
	return time.Until(b.ExpiresAt) < 30*24*time.Hour
}

// processAuthorization handles a single domain authorization.
func (m *ACMEManager) processAuthorization(ctx context.Context, authzURL string) error {
	resp, err := m.signedPost(ctx, authzURL, nil)
	if err != nil {
		return err
	}

	var authz acmeAuthorization
	if err := json.Unmarshal(resp.body, &authz); err != nil {
		return err
	}

	if authz.Status == "valid" {
		return nil // Already authorized
	}

	// Find HTTP-01 challenge
	var challenge *acmeChallenge
	for i := range authz.Challenges {
		if authz.Challenges[i].Type == "http-01" {
			challenge = &authz.Challenges[i]
			break
		}
	}
	if challenge == nil {
		return fmt.Errorf("no http-01 challenge for %s", authz.Identifier.Value)
	}

	// Compute key authorization: token + "." + thumbprint
	thumbprint := m.jwkThumbprint()
	keyAuth := challenge.Token + "." + thumbprint

	// Store for HTTP handler
	m.challenges.Store(challenge.Token, keyAuth)
	defer m.challenges.Delete(challenge.Token)

	m.logger.Info("responding to challenge",
		"domain", authz.Identifier.Value,
		"token", challenge.Token[:8]+"...",
	)

	// Tell ACME server we're ready
	_, err = m.signedPost(ctx, challenge.URL, []byte("{}"))
	if err != nil {
		return fmt.Errorf("respond to challenge: %w", err)
	}

	// Poll until valid or invalid
	for i := 0; i < 30; i++ {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(2 * time.Second):
		}

		pollResp, err := m.signedPost(ctx, authzURL, nil)
		if err != nil {
			continue
		}

		var pollAuthz acmeAuthorization
		if err := json.Unmarshal(pollResp.body, &pollAuthz); err != nil {
			continue
		}

		if pollAuthz.Status == "valid" {
			m.logger.Info("challenge validated", "domain", authz.Identifier.Value)
			return nil
		}
		if pollAuthz.Status == "invalid" {
			return fmt.Errorf("%w: challenge invalid for %s", ErrACMEChallengeFailed, authz.Identifier.Value)
		}
	}

	return fmt.Errorf("%w: challenge timeout for %s", ErrACMEChallengeFailed, authz.Identifier.Value)
}

// ServeChallenge handles HTTP-01 challenge requests.
// Mount at: /.well-known/acme-challenge/
func (m *ACMEManager) ServeChallenge(w http.ResponseWriter, r *http.Request) {
	token := strings.TrimPrefix(r.URL.Path, "/.well-known/acme-challenge/")
	if token == "" {
		http.NotFound(w, r)
		return
	}

	keyAuth, ok := m.challenges.Load(token)
	if !ok {
		http.NotFound(w, r)
		return
	}

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Write([]byte(keyAuth.(string)))
}

// ─── ACME Signed Requests (JWS) ─────────────────────────

type acmeResponse struct {
	body     []byte
	location string
}

func (m *ACMEManager) signedPost(ctx context.Context, url string, payload []byte) (*acmeResponse, error) {
	// Get nonce
	nonce, err := m.getNonce(ctx)
	if err != nil {
		return nil, err
	}

	// Build protected header
	header := map[string]interface{}{
		"alg":   "ES256",
		"nonce": nonce,
		"url":   url,
	}

	if m.account.URL != "" {
		header["kid"] = m.account.URL
	} else {
		header["jwk"] = m.jwk()
	}

	headerJSON, _ := json.Marshal(header)
	headerB64 := base64URLEncode(headerJSON)

	// Payload
	payloadB64 := ""
	if payload != nil {
		payloadB64 = base64URLEncode(payload)
	}

	// Sign
	sigInput := headerB64 + "." + payloadB64
	hash := sha256.Sum256([]byte(sigInput))
	r, s, err := ecdsa.Sign(rand.Reader, m.account.Key, hash[:])
	if err != nil {
		return nil, fmt.Errorf("sign: %w", err)
	}

	// ECDSA signature: r || s, each padded to 32 bytes for P-256
	rBytes := r.Bytes()
	sBytes := s.Bytes()
	sig := make([]byte, 64)
	copy(sig[32-len(rBytes):32], rBytes)
	copy(sig[64-len(sBytes):64], sBytes)

	// Build JWS
	jws := map[string]string{
		"protected": headerB64,
		"payload":   payloadB64,
		"signature": base64URLEncode(sig),
	}
	jwsJSON, _ := json.Marshal(jws)

	// POST
	req, _ := http.NewRequestWithContext(ctx, "POST", url, strings.NewReader(string(jwsJSON)))
	req.Header.Set("Content-Type", "application/jose+json")

	resp, err := m.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 4*1024*1024))
	if err != nil {
		return nil, fmt.Errorf("read response body: %w", err)
	}

	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("ACME error %d: %s", resp.StatusCode, string(body))
	}

	return &acmeResponse{
		body:     body,
		location: resp.Header.Get("Location"),
	}, nil
}

func (m *ACMEManager) getNonce(ctx context.Context) (string, error) {
	req, err := http.NewRequestWithContext(ctx, "HEAD", m.directory.NewNonce, nil)
	if err != nil {
		return "", err
	}
	resp, err := m.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	resp.Body.Close()
	return resp.Header.Get("Replay-Nonce"), nil
}

func (m *ACMEManager) registerAccount() error {
	ctx := context.Background()
	payload := map[string]interface{}{
		"termsOfServiceAgreed": true,
		"contact":             []string{"mailto:" + m.email},
	}
	body, _ := json.Marshal(payload)

	resp, err := m.signedPost(ctx, m.directory.NewAccount, body)
	if err != nil {
		return err
	}

	m.account.URL = resp.location
	return nil
}

// ─── JWK / Thumbprint ──────────────────────────────────

func (m *ACMEManager) jwk() map[string]string {
	pub := m.account.Key.PublicKey
	return map[string]string{
		"kty": "EC",
		"crv": "P-256",
		"x":   base64URLEncode(pub.X.Bytes()),
		"y":   base64URLEncode(pub.Y.Bytes()),
	}
}

func (m *ACMEManager) jwkThumbprint() string {
	pub := m.account.Key.PublicKey
	// Canonical JWK for thumbprint (RFC 7638): ordered keys
	canonical := fmt.Sprintf(`{"crv":"P-256","kty":"EC","x":"%s","y":"%s"}`,
		base64URLEncode(padTo32(pub.X.Bytes())),
		base64URLEncode(padTo32(pub.Y.Bytes())),
	)
	hash := sha256.Sum256([]byte(canonical))
	return base64URLEncode(hash[:])
}

// ─── Key Management ─────────────────────────────────────

func (m *ACMEManager) loadOrCreateKey(path string) (*ecdsa.PrivateKey, error) {
	// Try to load existing
	data, err := os.ReadFile(path)
	if err == nil {
		block, _ := pem.Decode(data)
		if block != nil {
			key, err := x509.ParseECPrivateKey(block.Bytes)
			if err == nil {
				return key, nil
			}
		}
	}

	// Generate new
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	// Save
	keyDER, _ := x509.MarshalECPrivateKey(key)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(path, keyPEM, 0600); err != nil {
		return nil, fmt.Errorf("save account key: %w", err)
	}

	return key, nil
}

// ─── Certificate Storage ────────────────────────────────

func (m *ACMEManager) saveCertBundle(domain string, bundle *CertificateBundle) error {
	certPath := filepath.Join(m.certDir, domain+".crt")
	keyPath := filepath.Join(m.certDir, domain+".key")

	// Save cert chain
	if err := os.WriteFile(certPath, bundle.CertPEM, 0600); err != nil {
		return err
	}

	// Save private key
	keyDER, _ := x509.MarshalECPrivateKey(bundle.PrivateKey)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(keyPath, keyPEM, 0600); err != nil {
		return err
	}

	// Save metadata
	meta := map[string]interface{}{
		"domains":    bundle.Domains,
		"issued_at":  bundle.IssuedAt.Format(time.RFC3339),
		"expires_at": bundle.ExpiresAt.Format(time.RFC3339),
	}
	metaJSON, _ := json.MarshalIndent(meta, "", "  ")
	if err := os.WriteFile(filepath.Join(m.certDir, domain+".json"), metaJSON, 0600); err != nil {
		m.logger.Warn("failed to save certificate metadata", "domain", domain, "error", err)
	}

	return nil
}

// LoadCertBundle loads a certificate bundle from disk.
func (m *ACMEManager) LoadCertBundle(domain string) (*CertificateBundle, error) {
	certPath := filepath.Join(m.certDir, domain+".crt")
	keyPath := filepath.Join(m.certDir, domain+".key")
	metaPath := filepath.Join(m.certDir, domain+".json")

	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, err
	}

	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(keyPEM)
	if block == nil {
		return nil, fmt.Errorf("invalid key PEM")
	}
	key, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	bundle := &CertificateBundle{
		CertPEM:    certPEM,
		PrivateKey: key,
		Domains:    []string{domain},
	}

	// Load metadata if available
	metaData, err := os.ReadFile(metaPath)
	if err == nil {
		var meta map[string]interface{}
		if json.Unmarshal(metaData, &meta) == nil {
			if exp, ok := meta["expires_at"].(string); ok {
				bundle.ExpiresAt, _ = time.Parse(time.RFC3339, exp)
			}
			if iss, ok := meta["issued_at"].(string); ok {
				bundle.IssuedAt, _ = time.Parse(time.RFC3339, iss)
			}
		}
	}

	return bundle, nil
}

// ─── Helpers ────────────────────────────────────────────

func base64URLEncode(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}

func padTo32(b []byte) []byte {
	if len(b) >= 32 {
		return b
	}
	padded := make([]byte, 32)
	copy(padded[32-len(b):], b)
	return padded
}

// ─── Auto-Renewal ───────────────────────────────────────

// StartAutoRenewal starts a background goroutine that checks certificate
// expiry and renews when needed (30 days before expiry).
func (m *ACMEManager) StartAutoRenewal(domains []string, getCert func(string) *CertificateBundle, setCert func(string, *CertificateBundle), done <-chan struct{}) {
	go func() {
		defer func() {
			if r := recover(); r != nil {
				m.logger.Error("panic in auto-renewal", "error", r)
			}
		}()

		ticker := time.NewTicker(12 * time.Hour)
		defer ticker.Stop()

		ctx, cancel := context.WithCancel(context.Background())
		go func() {
			<-done
			cancel()
		}()

		for {
			select {
			case <-done:
				return
			case <-ticker.C:
				m.checkAndRenew(ctx, domains, getCert, setCert, done)
			}
		}
	}()
}

// checkAndRenew iterates through domains and renews certificates that are expiring soon.
func (m *ACMEManager) checkAndRenew(ctx context.Context, domains []string, getCert func(string) *CertificateBundle, setCert func(string, *CertificateBundle), done <-chan struct{}) {
	for _, domain := range domains {
		// Check if we should stop before starting expensive renewal
		select {
		case <-done:
			return
		default:
		}

		bundle := getCert(domain)
		if bundle == nil || bundle.NeedsRenewal() {
			m.logger.Info("renewing certificate", "domain", domain)
			newBundle, err := m.ObtainCertificate(ctx, []string{domain})
			if err != nil {
				m.logger.Error("renewal failed", "domain", domain, "error", err)
				continue
			}
			setCert(domain, newBundle)
			m.logger.Info("certificate renewed", "domain", domain, "expires", newBundle.ExpiresAt)
		}
	}
}

// EstimateExpiry parses the first certificate in PEM and returns NotAfter.
func EstimateExpiry(certPEM []byte) (time.Time, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return time.Time{}, fmt.Errorf("no PEM block found")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return time.Time{}, err
	}
	return cert.NotAfter, nil
}

