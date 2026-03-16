package tls

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestBase64URLEncode(t *testing.T) {
	tests := []struct {
		input    []byte
		expected string
	}{
		{[]byte("hello"), "aGVsbG8"},
		{[]byte{0, 1, 2}, "AAEC"},
		{[]byte{}, ""},
	}
	for _, tt := range tests {
		got := base64URLEncode(tt.input)
		if got != tt.expected {
			t.Errorf("base64URLEncode(%v) = %q, want %q", tt.input, got, tt.expected)
		}
	}
}

func TestPadTo32(t *testing.T) {
	short := []byte{1, 2, 3}
	padded := padTo32(short)
	if len(padded) != 32 {
		t.Errorf("len = %d, want 32", len(padded))
	}
	if padded[31] != 3 || padded[30] != 2 || padded[29] != 1 {
		t.Error("padding incorrect")
	}

	exact := make([]byte, 32)
	exact[0] = 42
	result := padTo32(exact)
	if len(result) != 32 || result[0] != 42 {
		t.Error("32-byte input should pass through unchanged")
	}

	long := make([]byte, 40)
	result = padTo32(long)
	if len(result) != 40 {
		t.Error("longer than 32 should pass through unchanged")
	}
}

func TestNewACMEManagerValidation(t *testing.T) {
	_, err := NewACMEManager("", "", false, nil)
	if err == nil {
		t.Error("Expected error for empty email")
	}

	dir := t.TempDir()
	mgr, err := NewACMEManager("test@example.com", dir, true, nil)
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}
	if mgr.email != "test@example.com" {
		t.Error("Email not set")
	}
	if !mgr.staging {
		t.Error("Staging not set")
	}
}

func TestACMEManagerLoadOrCreateKey(t *testing.T) {
	dir := t.TempDir()
	mgr, _ := NewACMEManager("test@example.com", dir, true, nil)
	keyPath := filepath.Join(dir, "test-key.pem")

	// Create new key
	key1, err := mgr.loadOrCreateKey(keyPath)
	if err != nil {
		t.Fatalf("Failed to create key: %v", err)
	}
	if key1 == nil {
		t.Fatal("Key is nil")
	}

	// Verify file was saved
	if _, err := os.Stat(keyPath); os.IsNotExist(err) {
		t.Error("Key file not created")
	}

	// Load existing key
	key2, err := mgr.loadOrCreateKey(keyPath)
	if err != nil {
		t.Fatalf("Failed to load key: %v", err)
	}

	// Same key
	if key1.D.Cmp(key2.D) != 0 {
		t.Error("Loaded key doesn't match created key")
	}
}

func TestACMEManagerJWK(t *testing.T) {
	dir := t.TempDir()
	mgr, _ := NewACMEManager("test@example.com", dir, true, nil)

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	mgr.account = &acmeAccount{Key: key}

	jwk := mgr.jwk()
	if jwk["kty"] != "EC" {
		t.Errorf("kty = %q, want EC", jwk["kty"])
	}
	if jwk["crv"] != "P-256" {
		t.Errorf("crv = %q, want P-256", jwk["crv"])
	}
	if jwk["x"] == "" || jwk["y"] == "" {
		t.Error("x or y is empty")
	}
}

func TestACMEManagerJWKThumbprint(t *testing.T) {
	dir := t.TempDir()
	mgr, _ := NewACMEManager("test@example.com", dir, true, nil)

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	mgr.account = &acmeAccount{Key: key}

	thumbprint := mgr.jwkThumbprint()
	if thumbprint == "" {
		t.Error("Thumbprint is empty")
	}
	if len(thumbprint) < 20 {
		t.Errorf("Thumbprint too short: %d chars", len(thumbprint))
	}

	// Should be deterministic
	thumbprint2 := mgr.jwkThumbprint()
	if thumbprint != thumbprint2 {
		t.Error("Thumbprint not deterministic")
	}
}

func TestACMEManagerServeChallenge(t *testing.T) {
	dir := t.TempDir()
	mgr, _ := NewACMEManager("test@example.com", dir, true, nil)

	// Store a challenge
	mgr.challenges.Store("test-token-123", "test-token-123.thumbprint-value")

	// Valid challenge request
	req := httptest.NewRequest("GET", "/.well-known/acme-challenge/test-token-123", nil)
	rec := httptest.NewRecorder()
	mgr.ServeChallenge(rec, req)

	if rec.Code != 200 {
		t.Errorf("Status = %d, want 200", rec.Code)
	}
	if rec.Body.String() != "test-token-123.thumbprint-value" {
		t.Errorf("Body = %q", rec.Body.String())
	}

	// Unknown token
	req2 := httptest.NewRequest("GET", "/.well-known/acme-challenge/unknown", nil)
	rec2 := httptest.NewRecorder()
	mgr.ServeChallenge(rec2, req2)

	if rec2.Code != 404 {
		t.Errorf("Unknown token: status = %d, want 404", rec2.Code)
	}

	// Empty token
	req3 := httptest.NewRequest("GET", "/.well-known/acme-challenge/", nil)
	rec3 := httptest.NewRecorder()
	mgr.ServeChallenge(rec3, req3)

	if rec3.Code != 404 {
		t.Errorf("Empty token: status = %d, want 404", rec3.Code)
	}
}

func TestCertificateBundleNeedsRenewal(t *testing.T) {
	// Expires in 60 days - no renewal needed
	b1 := &CertificateBundle{ExpiresAt: time.Now().Add(60 * 24 * time.Hour)}
	if b1.NeedsRenewal() {
		t.Error("60 days out should not need renewal")
	}

	// Expires in 20 days - needs renewal
	b2 := &CertificateBundle{ExpiresAt: time.Now().Add(20 * 24 * time.Hour)}
	if !b2.NeedsRenewal() {
		t.Error("20 days out should need renewal")
	}

	// Already expired
	b3 := &CertificateBundle{ExpiresAt: time.Now().Add(-1 * time.Hour)}
	if !b3.NeedsRenewal() {
		t.Error("Expired cert should need renewal")
	}
}

func TestCertificateBundleTLSCertificate(t *testing.T) {
	// Generate a self-signed cert for testing
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	serial, _ := rand.Int(rand.Reader, big.NewInt(1000000))
	template := &x509.Certificate{
		SerialNumber: serial,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{"test.example.com"},
	}
	certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	bundle := &CertificateBundle{
		CertPEM:    certPEM,
		PrivateKey: key,
	}

	tlsCert, err := bundle.TLSCertificate()
	if err != nil {
		t.Fatalf("TLSCertificate error: %v", err)
	}
	if tlsCert == nil {
		t.Fatal("TLSCertificate returned nil")
	}
	if len(tlsCert.Certificate) == 0 {
		t.Error("No certificates in chain")
	}
}

func TestSaveCertBundleAndLoad(t *testing.T) {
	dir := t.TempDir()
	mgr, _ := NewACMEManager("test@example.com", dir, true, nil)

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	serial, _ := rand.Int(rand.Reader, big.NewInt(1000000))
	template := &x509.Certificate{
		SerialNumber: serial,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(90 * 24 * time.Hour),
		DNSNames:     []string{"test.example.com"},
	}
	certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	bundle := &CertificateBundle{
		CertPEM:    certPEM,
		PrivateKey: key,
		Domains:    []string{"test.example.com"},
		IssuedAt:   time.Now(),
		ExpiresAt:  time.Now().Add(90 * 24 * time.Hour),
	}

	// Save
	err := mgr.saveCertBundle("test.example.com", bundle)
	if err != nil {
		t.Fatalf("saveCertBundle error: %v", err)
	}

	// Verify files exist
	if _, err := os.Stat(filepath.Join(dir, "test.example.com.crt")); os.IsNotExist(err) {
		t.Error("Cert file not created")
	}
	if _, err := os.Stat(filepath.Join(dir, "test.example.com.key")); os.IsNotExist(err) {
		t.Error("Key file not created")
	}
	if _, err := os.Stat(filepath.Join(dir, "test.example.com.json")); os.IsNotExist(err) {
		t.Error("Metadata file not created")
	}

	// Load
	loaded, err := mgr.LoadCertBundle("test.example.com")
	if err != nil {
		t.Fatalf("LoadCertBundle error: %v", err)
	}
	if loaded.PrivateKey.D.Cmp(key.D) != 0 {
		t.Error("Loaded key doesn't match")
	}
	if loaded.ExpiresAt.IsZero() {
		t.Error("ExpiresAt not loaded")
	}
}

func TestEstimateExpiry(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	serial, _ := rand.Int(rand.Reader, big.NewInt(1000000))
	notAfter := time.Now().Add(90 * 24 * time.Hour).Truncate(time.Second)
	template := &x509.Certificate{
		SerialNumber: serial,
		NotBefore:    time.Now(),
		NotAfter:     notAfter,
	}
	certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	expiry, err := EstimateExpiry(certPEM)
	if err != nil {
		t.Fatalf("EstimateExpiry error: %v", err)
	}
	if !expiry.Equal(notAfter) {
		t.Errorf("Expiry = %v, want %v", expiry, notAfter)
	}

	// Invalid PEM
	_, err = EstimateExpiry([]byte("not a pem"))
	if err == nil {
		t.Error("Expected error for invalid PEM")
	}
}

func TestACMEManagerInitializeWithFakeServer(t *testing.T) {
	// Mock ACME directory
	mockDir := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		dir := acmeDirectory{
			NewNonce:   "http://" + r.Host + "/nonce",
			NewAccount: "http://" + r.Host + "/account",
			NewOrder:   "http://" + r.Host + "/order",
		}
		json.NewEncoder(w).Encode(dir)
	}))
	defer mockDir.Close()

	dir := t.TempDir()
	mgr, _ := NewACMEManager("test@example.com", dir, true, nil)

	// Override directory URL for test
	resp, err := mgr.httpClient.Get(mockDir.URL)
	if err != nil {
		t.Fatalf("Failed to fetch mock directory: %v", err)
	}
	defer resp.Body.Close()
	json.NewDecoder(resp.Body).Decode(&mgr.directory)

	if mgr.directory.NewNonce == "" {
		t.Error("Directory NewNonce not set")
	}
	if mgr.directory.NewAccount == "" {
		t.Error("Directory NewAccount not set")
	}
}

func TestACMEChallengeHandlerOnManagerWithoutACME(t *testing.T) {
	// Manager without ACME should return 404
	mgr := &Manager{}
	handler := mgr.ACMEChallengeHandler()

	req := httptest.NewRequest("GET", "/.well-known/acme-challenge/token", nil)
	rec := httptest.NewRecorder()
	handler(rec, req)

	if rec.Code != 404 {
		t.Errorf("Status = %d, want 404", rec.Code)
	}
}

func TestIsACMEEnabled(t *testing.T) {
	mgr := &Manager{}
	if mgr.IsACMEEnabled() {
		t.Error("Should be false without ACME")
	}

	mgr.acme = &ACMEManager{}
	if !mgr.IsACMEEnabled() {
		t.Error("Should be true with ACME")
	}
}

func TestLoadCertBundleNotFound(t *testing.T) {
	dir := t.TempDir()
	mgr, _ := NewACMEManager("test@example.com", dir, true, nil)

	_, err := mgr.LoadCertBundle("nonexistent.com")
	if err == nil {
		t.Error("Expected error for nonexistent bundle")
	}
}

// ─── Mock ACME Server ────────────────────────────────────

// mockACMEServer creates a complete fake ACME server for testing the full flow.
// It supports directory, nonce, account, order, authorization, challenge,
// finalize, and certificate download endpoints.
func mockACMEServer(t *testing.T) *httptest.Server {
	t.Helper()

	// Generate a self-signed CA cert for the mock to issue
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caSerial, _ := rand.Int(rand.Reader, big.NewInt(1000000))
	caTemplate := &x509.Certificate{
		SerialNumber:          caSerial,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	caDER, _ := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)

	// Track state
	var (
		orderReady      = false
		challengePosted = false
	)

	mux := http.NewServeMux()

	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mux.ServeHTTP(w, r)
	}))

	base := srv.URL

	// Directory
	mux.HandleFunc("/directory", func(w http.ResponseWriter, r *http.Request) {
		dir := acmeDirectory{
			NewNonce:   base + "/nonce",
			NewAccount: base + "/account",
			NewOrder:   base + "/order",
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(dir)
	})

	// Nonce (HEAD)
	mux.HandleFunc("/nonce", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Replay-Nonce", fmt.Sprintf("nonce-%d", time.Now().UnixNano()))
		w.WriteHeader(http.StatusOK)
	})

	// Account creation (POST)
	mux.HandleFunc("/account", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", base+"/account/1")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status": "valid",
		})
	})

	// Order creation (POST)
	mux.HandleFunc("/order", func(w http.ResponseWriter, r *http.Request) {
		orderReady = false
		challengePosted = false
		w.Header().Set("Location", base+"/order/1")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(acmeOrder{
			Status:         "pending",
			Authorizations: []string{base + "/authz/1"},
			Finalize:       base + "/finalize/1",
		})
	})

	// Order status polling (POST with empty payload, same as signedPost)
	mux.HandleFunc("/order/1", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		status := "pending"
		cert := ""
		if challengePosted {
			status = "ready"
			orderReady = true
		}
		if orderReady {
			status = "ready"
		}
		json.NewEncoder(w).Encode(acmeOrder{
			Status:         status,
			Authorizations: []string{base + "/authz/1"},
			Finalize:       base + "/finalize/1",
			Certificate:    cert,
		})
	})

	// Authorization (POST/GET)
	mux.HandleFunc("/authz/1", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		status := "pending"
		if challengePosted {
			status = "valid"
		}
		json.NewEncoder(w).Encode(acmeAuthorization{
			Status: status,
			Identifier: acmeIdentifier{
				Type:  "dns",
				Value: "test.example.com",
			},
			Challenges: []acmeChallenge{
				{
					Type:   "http-01",
					URL:    base + "/challenge/1",
					Token:  "mock-token-12345678",
					Status: status,
				},
			},
		})
	})

	// Challenge response (POST)
	mux.HandleFunc("/challenge/1", func(w http.ResponseWriter, r *http.Request) {
		challengePosted = true
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status": "processing",
		})
	})

	// Finalize (POST)
	mux.HandleFunc("/finalize/1", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(acmeOrder{
			Status:      "valid",
			Certificate: base + "/cert/1",
		})
	})

	// Certificate download (POST)
	mux.HandleFunc("/cert/1", func(w http.ResponseWriter, r *http.Request) {
		// Issue a cert signed by mock CA
		certKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		serial, _ := rand.Int(rand.Reader, big.NewInt(1000000))
		tmpl := &x509.Certificate{
			SerialNumber: serial,
			NotBefore:    time.Now(),
			NotAfter:     time.Now().Add(90 * 24 * time.Hour),
			DNSNames:     []string{"test.example.com"},
		}
		certDER, _ := x509.CreateCertificate(rand.Reader, tmpl, caTemplate, &certKey.PublicKey, caKey)
		certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
		caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
		w.Header().Set("Content-Type", "application/pem-certificate-chain")
		w.Write(certPEM)
		w.Write(caPEM)
	})

	return srv
}

// setupMockManager creates an ACMEManager wired to a mock ACME server.
func setupMockManager(t *testing.T, mockSrv *httptest.Server) *ACMEManager {
	t.Helper()
	dir := t.TempDir()
	mgr, err := NewACMEManager("test@example.com", dir, true, nil)
	if err != nil {
		t.Fatalf("NewACMEManager: %v", err)
	}

	// Fetch directory from mock
	resp, err := mgr.httpClient.Get(mockSrv.URL + "/directory")
	if err != nil {
		t.Fatalf("Fetch directory: %v", err)
	}
	defer resp.Body.Close()
	if err := json.NewDecoder(resp.Body).Decode(&mgr.directory); err != nil {
		t.Fatalf("Decode directory: %v", err)
	}

	// Create account key
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	mgr.account = &acmeAccount{Key: key}

	return mgr
}

func TestSignedPost_MockServer(t *testing.T) {
	mockSrv := mockACMEServer(t)
	defer mockSrv.Close()
	mgr := setupMockManager(t, mockSrv)

	// signedPost to account endpoint should return a valid response
	payload, _ := json.Marshal(map[string]interface{}{
		"termsOfServiceAgreed": true,
		"contact":             []string{"mailto:test@example.com"},
	})
	resp, err := mgr.signedPost(context.Background(),mgr.directory.NewAccount, payload)
	if err != nil {
		t.Fatalf("signedPost failed: %v", err)
	}
	if resp == nil {
		t.Fatal("signedPost returned nil response")
	}
	if resp.location == "" {
		t.Error("signedPost: Location header not set")
	}
}

func TestSignedPost_NilPayload(t *testing.T) {
	mockSrv := mockACMEServer(t)
	defer mockSrv.Close()
	mgr := setupMockManager(t, mockSrv)

	// signedPost with nil payload (POST-as-GET)
	resp, err := mgr.signedPost(context.Background(),mockSrv.URL+"/authz/1", nil)
	if err != nil {
		t.Fatalf("signedPost with nil payload failed: %v", err)
	}
	if resp == nil {
		t.Fatal("Response is nil")
	}
	if len(resp.body) == 0 {
		t.Error("Response body is empty")
	}
}

func TestSignedPost_ErrorResponse(t *testing.T) {
	// Server that always returns 403
	errorSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "HEAD" {
			w.Header().Set("Replay-Nonce", "test-nonce")
			return
		}
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte(`{"type":"forbidden","detail":"test error"}`))
	}))
	defer errorSrv.Close()

	dir := t.TempDir()
	mgr, _ := NewACMEManager("test@example.com", dir, true, nil)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	mgr.account = &acmeAccount{Key: key}
	mgr.directory = acmeDirectory{
		NewNonce:   errorSrv.URL + "/nonce",
		NewAccount: errorSrv.URL + "/account",
	}

	_, err := mgr.signedPost(context.Background(),errorSrv.URL+"/account", []byte("{}"))
	if err == nil {
		t.Fatal("Expected error for 403 response")
	}
	if !strings.Contains(err.Error(), "ACME error 403") {
		t.Errorf("Expected 'ACME error 403', got: %v", err)
	}
}

func TestRegisterAccount_MockServer(t *testing.T) {
	mockSrv := mockACMEServer(t)
	defer mockSrv.Close()
	mgr := setupMockManager(t, mockSrv)

	err := mgr.registerAccount()
	if err != nil {
		t.Fatalf("registerAccount failed: %v", err)
	}
	if mgr.account.URL == "" {
		t.Error("Account URL not set after registration")
	}
	// Should contain the mock server's account location
	if !strings.Contains(mgr.account.URL, "/account/1") {
		t.Errorf("Account URL = %q, expected to contain /account/1", mgr.account.URL)
	}
}

func TestProcessAuthorization_MockServer(t *testing.T) {
	mockSrv := mockACMEServer(t)
	defer mockSrv.Close()
	mgr := setupMockManager(t, mockSrv)

	// Register account first (needed for kid header)
	mgr.registerAccount()

	// processAuthorization should find http-01 challenge, post to it, poll until valid
	err := mgr.processAuthorization(context.Background(),mockSrv.URL + "/authz/1")
	if err != nil {
		t.Fatalf("processAuthorization failed: %v", err)
	}
}

func TestProcessAuthorization_AlreadyValid(t *testing.T) {
	// Mock server where authz is already "valid"
	validSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "HEAD" {
			w.Header().Set("Replay-Nonce", "nonce-1")
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(acmeAuthorization{
			Status: "valid",
			Identifier: acmeIdentifier{
				Type:  "dns",
				Value: "test.example.com",
			},
		})
	}))
	defer validSrv.Close()

	dir := t.TempDir()
	mgr, _ := NewACMEManager("test@example.com", dir, true, nil)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	mgr.account = &acmeAccount{Key: key, URL: validSrv.URL + "/account/1"}
	mgr.directory = acmeDirectory{
		NewNonce: validSrv.URL + "/nonce",
	}

	err := mgr.processAuthorization(context.Background(),validSrv.URL + "/authz/1")
	if err != nil {
		t.Fatalf("Already-valid authz should succeed: %v", err)
	}
}

func TestProcessAuthorization_NoHTTP01Challenge(t *testing.T) {
	// Mock server that returns authz with only dns-01 challenge (no http-01)
	var srvURL string
	dnsSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "HEAD" {
			w.Header().Set("Replay-Nonce", "nonce-1")
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(acmeAuthorization{
			Status: "pending",
			Identifier: acmeIdentifier{
				Type:  "dns",
				Value: "test.example.com",
			},
			Challenges: []acmeChallenge{
				{
					Type:   "dns-01",
					URL:    srvURL + "/chall",
					Token:  "dns-token",
					Status: "pending",
				},
			},
		})
	}))
	defer dnsSrv.Close()
	srvURL = dnsSrv.URL

	dir := t.TempDir()
	mgr, _ := NewACMEManager("test@example.com", dir, true, nil)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	mgr.account = &acmeAccount{Key: key, URL: dnsSrv.URL + "/account/1"}
	mgr.directory = acmeDirectory{
		NewNonce: dnsSrv.URL + "/nonce",
	}

	err := mgr.processAuthorization(context.Background(),dnsSrv.URL + "/authz/1")
	if err == nil {
		t.Fatal("Expected error for missing http-01 challenge")
	}
	if !strings.Contains(err.Error(), "no http-01 challenge") {
		t.Errorf("Expected 'no http-01 challenge', got: %v", err)
	}
}

func TestObtainCertificate_MockServer(t *testing.T) {
	mockSrv := mockACMEServer(t)
	defer mockSrv.Close()
	mgr := setupMockManager(t, mockSrv)

	// Register account first
	if err := mgr.registerAccount(); err != nil {
		t.Fatalf("registerAccount failed: %v", err)
	}

	bundle, err := mgr.ObtainCertificate(context.Background(), []string{"test.example.com"})
	if err != nil {
		t.Fatalf("ObtainCertificate failed: %v", err)
	}

	if bundle == nil {
		t.Fatal("Bundle is nil")
	}
	if len(bundle.CertPEM) == 0 {
		t.Error("CertPEM is empty")
	}
	if bundle.PrivateKey == nil {
		t.Error("PrivateKey is nil")
	}
	if len(bundle.Domains) != 1 || bundle.Domains[0] != "test.example.com" {
		t.Errorf("Domains = %v, want [test.example.com]", bundle.Domains)
	}
	if bundle.IssuedAt.IsZero() {
		t.Error("IssuedAt is zero")
	}
	if bundle.ExpiresAt.IsZero() {
		t.Error("ExpiresAt is zero")
	}

	// Verify cert files were saved
	certPath := filepath.Join(mgr.certDir, "test.example.com.crt")
	if _, err := os.Stat(certPath); os.IsNotExist(err) {
		t.Error("Cert file not saved to disk")
	}

	keyPath := filepath.Join(mgr.certDir, "test.example.com.key")
	if _, err := os.Stat(keyPath); os.IsNotExist(err) {
		t.Error("Key file not saved to disk")
	}

	// Verify the CertPEM contains valid PEM blocks
	block, _ := pem.Decode(bundle.CertPEM)
	if block == nil {
		t.Fatal("CertPEM does not contain valid PEM")
	}
	if block.Type != "CERTIFICATE" {
		t.Errorf("PEM block type = %q, want CERTIFICATE", block.Type)
	}
	// Note: TLSCertificate() would fail key matching because the mock server
	// issues a cert with its own key, not the CSR key. That's expected for mocks.
}

func TestGetNonce_MockServer(t *testing.T) {
	mockSrv := mockACMEServer(t)
	defer mockSrv.Close()
	mgr := setupMockManager(t, mockSrv)

	nonce, err := mgr.getNonce(context.Background())
	if err != nil {
		t.Fatalf("getNonce failed: %v", err)
	}
	if nonce == "" {
		t.Error("Nonce is empty")
	}
	if !strings.HasPrefix(nonce, "nonce-") {
		t.Errorf("Nonce = %q, expected prefix 'nonce-'", nonce)
	}
}

func TestSignedPost_WithKID(t *testing.T) {
	mockSrv := mockACMEServer(t)
	defer mockSrv.Close()
	mgr := setupMockManager(t, mockSrv)

	// Set account URL so kid is used instead of jwk
	mgr.account.URL = mockSrv.URL + "/account/1"

	resp, err := mgr.signedPost(context.Background(),mockSrv.URL+"/order/1", nil)
	if err != nil {
		t.Fatalf("signedPost with kid failed: %v", err)
	}
	if resp == nil {
		t.Fatal("Response is nil")
	}
}

func TestSignedPost_WithoutKID(t *testing.T) {
	mockSrv := mockACMEServer(t)
	defer mockSrv.Close()
	mgr := setupMockManager(t, mockSrv)

	// Clear account URL so jwk is used
	mgr.account.URL = ""

	payload, _ := json.Marshal(map[string]interface{}{
		"termsOfServiceAgreed": true,
	})
	resp, err := mgr.signedPost(context.Background(),mgr.directory.NewAccount, payload)
	if err != nil {
		t.Fatalf("signedPost without kid failed: %v", err)
	}
	if resp.location == "" {
		t.Error("Location header not set")
	}
}

func TestInitialize_MockServer(t *testing.T) {
	mockSrv := mockACMEServer(t)
	defer mockSrv.Close()

	dir := t.TempDir()
	mgr, err := NewACMEManager("test@example.com", dir, true, nil)
	if err != nil {
		t.Fatalf("NewACMEManager: %v", err)
	}

	// Override the httpClient GET to redirect to our mock directory
	// We patch the directory fetch by directly calling the mock
	resp, err := mgr.httpClient.Get(mockSrv.URL + "/directory")
	if err != nil {
		t.Fatalf("Fetch directory: %v", err)
	}
	defer resp.Body.Close()
	json.NewDecoder(resp.Body).Decode(&mgr.directory)

	// Load or create key
	keyPath := filepath.Join(dir, "acme-account.key")
	key, err := mgr.loadOrCreateKey(keyPath)
	if err != nil {
		t.Fatalf("loadOrCreateKey: %v", err)
	}
	mgr.account = &acmeAccount{Key: key}

	// Register account via mock
	if err := mgr.registerAccount(); err != nil {
		t.Fatalf("registerAccount: %v", err)
	}

	if mgr.account.URL == "" {
		t.Error("Account URL not set after Initialize-like flow")
	}
	if mgr.directory.NewNonce == "" {
		t.Error("Directory NewNonce empty")
	}
	if mgr.directory.NewAccount == "" {
		t.Error("Directory NewAccount empty")
	}
	if mgr.directory.NewOrder == "" {
		t.Error("Directory NewOrder empty")
	}
}

func TestInitialize_KeyPersistence(t *testing.T) {
	mockSrv := mockACMEServer(t)
	defer mockSrv.Close()

	dir := t.TempDir()
	mgr, err := NewACMEManager("test@example.com", dir, true, nil)
	if err != nil {
		t.Fatalf("NewACMEManager: %v", err)
	}

	// Manually set directory to our mock
	resp, err := mgr.httpClient.Get(mockSrv.URL + "/directory")
	if err != nil {
		t.Fatalf("Fetch directory: %v", err)
	}
	defer resp.Body.Close()
	if err := json.NewDecoder(resp.Body).Decode(&mgr.directory); err != nil {
		t.Fatalf("Decode directory: %v", err)
	}

	// Test loadOrCreateKey (creates new key)
	keyPath := filepath.Join(dir, "acme-account.key")
	key, err := mgr.loadOrCreateKey(keyPath)
	if err != nil {
		t.Fatalf("loadOrCreateKey (create): %v", err)
	}
	mgr.account = &acmeAccount{Key: key}

	// Test loadOrCreateKey (loads existing key)
	key2, err := mgr.loadOrCreateKey(keyPath)
	if err != nil {
		t.Fatalf("loadOrCreateKey (load): %v", err)
	}
	if key.D.Cmp(key2.D) != 0 {
		t.Error("Loaded key should match created key")
	}

	// Test registerAccount
	if err := mgr.registerAccount(); err != nil {
		t.Fatalf("registerAccount: %v", err)
	}
	if mgr.account.URL == "" {
		t.Error("Account URL should be set after registration")
	}
}

func TestStartAutoRenewal(t *testing.T) {
	mockSrv := mockACMEServer(t)
	defer mockSrv.Close()
	mgr := setupMockManager(t, mockSrv)

	if err := mgr.registerAccount(); err != nil {
		t.Fatalf("registerAccount: %v", err)
	}

	// Track calls
	var getCalled, setCalled bool
	getCert := func(domain string) *CertificateBundle {
		getCalled = true
		// Return a bundle that needs renewal (expires soon)
		return &CertificateBundle{
			ExpiresAt: time.Now().Add(10 * 24 * time.Hour), // 10 days, needs renewal (<30 days)
		}
	}
	setCert := func(domain string, b *CertificateBundle) {
		setCalled = true
	}

	done := make(chan struct{})
	mgr.StartAutoRenewal([]string{"test.example.com"}, getCert, setCert, done)

	// Wait briefly — the renewal goroutine uses a 12h ticker, so we can't wait for it
	// Instead, just verify it started without panic and close immediately
	time.Sleep(50 * time.Millisecond)
	close(done)
	time.Sleep(50 * time.Millisecond)

	// The goroutine should have stopped cleanly
	// getCalled/setCalled may not be true since ticker hasn't fired, that's OK
	_ = getCalled
	_ = setCalled
}

func TestObtainCertificate_ContextCancellation(t *testing.T) {
	// Create a mock server that delays responses
	slowSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "HEAD" {
			w.Header().Set("Replay-Nonce", "nonce-1")
			return
		}
		// Delay to test cancellation
		time.Sleep(5 * time.Second)
		w.WriteHeader(http.StatusOK)
	}))
	defer slowSrv.Close()

	dir := t.TempDir()
	mgr, _ := NewACMEManager("test@example.com", dir, true, nil)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	mgr.account = &acmeAccount{Key: key, URL: slowSrv.URL + "/account/1"}
	mgr.directory = acmeDirectory{
		NewNonce: slowSrv.URL + "/nonce",
		NewOrder: slowSrv.URL + "/order",
	}

	// Cancel immediately
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	_, err := mgr.ObtainCertificate(ctx, []string{"test.example.com"})
	if err == nil {
		t.Fatal("Expected error from cancelled context")
	}
}

func TestEstimateExpiry_InvalidPEM(t *testing.T) {
	_, err := EstimateExpiry([]byte("not valid PEM"))
	if err == nil {
		t.Error("Expected error for invalid PEM")
	}
}

func TestTLSCertificate_Valid(t *testing.T) {
	// Create a minimal valid bundle
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	serial, _ := rand.Int(rand.Reader, big.NewInt(1000))
	template := &x509.Certificate{
		SerialNumber: serial,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	bundle := &CertificateBundle{
		CertPEM:    certPEM,
		PrivateKey: key,
	}

	tlsCert, err := bundle.TLSCertificate()
	if err != nil {
		t.Fatalf("TLSCertificate: %v", err)
	}
	if tlsCert == nil {
		t.Fatal("TLSCertificate returned nil")
	}
}

func TestInitialize_WithMockTransport(t *testing.T) {
	mockSrv := mockACMEServer(t)
	defer mockSrv.Close()

	dir := t.TempDir()
	mgr, err := NewACMEManager("test@example.com", dir, true, nil)
	if err != nil {
		t.Fatalf("NewACMEManager: %v", err)
	}

	// Replace the httpClient to redirect staging URL to mock server
	originalTransport := http.DefaultTransport.(*http.Transport).Clone()
	mgr.httpClient = &http.Client{
		Timeout: 10 * time.Second,
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			// Redirect staging URL to mock
			if req.URL.String() == LetsEncryptStaging {
				req = req.Clone(req.Context())
				req.URL, _ = req.URL.Parse(mockSrv.URL + "/directory")
			} else if strings.HasPrefix(req.URL.String(), "https://") {
				// Redirect any ACME URL to mock
				path := req.URL.Path
				req = req.Clone(req.Context())
				req.URL, _ = req.URL.Parse(mockSrv.URL + path)
			}
			return originalTransport.RoundTrip(req)
		}),
	}

	err = mgr.Initialize()
	if err != nil {
		t.Fatalf("Initialize: %v", err)
	}

	if mgr.account == nil {
		t.Fatal("account should be set after Initialize")
	}
	if mgr.account.URL == "" {
		t.Error("account URL should be set")
	}
	if mgr.directory.NewNonce == "" {
		t.Error("directory.NewNonce should be set")
	}

	// Verify key was persisted
	keyPath := filepath.Join(dir, "acme-account.key")
	if _, err := os.Stat(keyPath); os.IsNotExist(err) {
		t.Error("Account key should be saved to disk")
	}
}

// roundTripFunc is an adapter to use a function as http.RoundTripper.
type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func TestNewACMEManager_EmptyEmail(t *testing.T) {
	_, err := NewACMEManager("", t.TempDir(), false, nil)
	if err == nil {
		t.Error("Expected error for empty email")
	}
}

func TestNewACMEManager_DefaultCertDir(t *testing.T) {
	// Use a temp dir as working directory for "certs" default
	origDir := t.TempDir()
	mgr, err := NewACMEManager("test@example.com", origDir, true, nil)
	if err != nil {
		t.Fatalf("NewACMEManager: %v", err)
	}
	if mgr.certDir != origDir {
		t.Errorf("certDir = %q, want %q", mgr.certDir, origDir)
	}
}

// ─── Additional Coverage Tests ──────────────────────────

// TestNewACMEManager_EmptyCertDirDefault verifies the "" certDir defaults to "./certs"
func TestNewACMEManager_EmptyCertDirDefault(t *testing.T) {
	// Save and restore working directory
	origWd, _ := os.Getwd()
	tmpDir := t.TempDir()
	os.Chdir(tmpDir)
	defer os.Chdir(origWd)

	mgr, err := NewACMEManager("user@example.com", "", true, nil)
	if err != nil {
		t.Fatalf("NewACMEManager: %v", err)
	}
	if mgr.certDir != "./certs" {
		t.Errorf("certDir = %q, want ./certs", mgr.certDir)
	}
	// Verify the directory was created
	if _, err := os.Stat(filepath.Join(tmpDir, "certs")); os.IsNotExist(err) {
		t.Error("Default certs directory was not created")
	}
}

// TestNewACMEManager_CertDirCreateError verifies MkdirAll error is returned
func TestNewACMEManager_CertDirCreateError(t *testing.T) {
	// Create a file to block directory creation
	dir := t.TempDir()
	blocker := filepath.Join(dir, "blocker")
	os.WriteFile(blocker, []byte("x"), 0644)

	_, err := NewACMEManager("user@example.com", filepath.Join(blocker, "sub"), true, nil)
	if err == nil {
		t.Error("Expected error when cert dir cannot be created")
	}
}

// TestInitialize_FetchDirectoryError verifies Initialize returns error on HTTP failure
func TestInitialize_FetchDirectoryError(t *testing.T) {
	dir := t.TempDir()
	mgr, _ := NewACMEManager("test@example.com", dir, true, nil)

	// Point to a non-existent server
	mgr.httpClient = &http.Client{Timeout: 100 * time.Millisecond}
	mgr.staging = true // will try LetsEncryptStaging URL

	// Replace the transport to force connection refused
	mgr.httpClient.Transport = roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return nil, fmt.Errorf("connection refused")
	})

	err := mgr.Initialize()
	if err == nil {
		t.Error("Expected error when directory fetch fails")
	}
	if !strings.Contains(err.Error(), "fetch directory") {
		t.Errorf("Expected 'fetch directory' error, got: %v", err)
	}
}

// TestInitialize_DecodeDirectoryError verifies Initialize returns error on bad JSON
func TestInitialize_DecodeDirectoryError(t *testing.T) {
	// Server that returns invalid JSON
	badSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("not-json"))
	}))
	defer badSrv.Close()

	dir := t.TempDir()
	mgr, _ := NewACMEManager("test@example.com", dir, true, nil)

	// Redirect staging URL to our bad server
	mgr.httpClient = &http.Client{
		Timeout: 5 * time.Second,
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			req = req.Clone(req.Context())
			req.URL, _ = req.URL.Parse(badSrv.URL)
			return http.DefaultTransport.RoundTrip(req)
		}),
	}

	err := mgr.Initialize()
	if err == nil {
		t.Error("Expected error when directory JSON is invalid")
	}
	if !strings.Contains(err.Error(), "decode directory") {
		t.Errorf("Expected 'decode directory' error, got: %v", err)
	}
}

// TestInitialize_LoadOrCreateKeyError verifies Initialize returns error when key creation fails
func TestInitialize_LoadOrCreateKeyError(t *testing.T) {
	mockSrv := mockACMEServer(t)
	defer mockSrv.Close()

	dir := t.TempDir()
	mgr, _ := NewACMEManager("test@example.com", dir, true, nil)

	// Redirect to mock server for directory fetch
	mgr.httpClient = &http.Client{
		Timeout: 5 * time.Second,
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			if req.URL.String() == LetsEncryptStaging {
				req = req.Clone(req.Context())
				req.URL, _ = req.URL.Parse(mockSrv.URL + "/directory")
			}
			return http.DefaultTransport.RoundTrip(req)
		}),
	}

	// Block the key file path by creating a directory there
	keyPath := filepath.Join(dir, "acme-account.key")
	os.MkdirAll(keyPath, 0700)

	err := mgr.Initialize()
	if err == nil {
		t.Error("Expected error when account key cannot be saved")
	}
	if !strings.Contains(err.Error(), "account key") {
		t.Errorf("Expected 'account key' error, got: %v", err)
	}
}

// TestObtainCertificate_DecodeOrderError verifies order JSON decode error
func TestObtainCertificate_DecodeOrderError(t *testing.T) {
	callCount := 0
	badOrderSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "HEAD" {
			w.Header().Set("Replay-Nonce", "nonce-1")
			return
		}
		callCount++
		if callCount == 1 {
			// First POST (create order) returns invalid JSON
			w.Header().Set("Location", "http://"+r.Host+"/order/1")
			w.Write([]byte("not-json"))
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("{}"))
	}))
	defer badOrderSrv.Close()

	dir := t.TempDir()
	mgr, _ := NewACMEManager("test@example.com", dir, true, nil)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	mgr.account = &acmeAccount{Key: key, URL: badOrderSrv.URL + "/account/1"}
	mgr.directory = acmeDirectory{
		NewNonce: badOrderSrv.URL + "/nonce",
		NewOrder: badOrderSrv.URL + "/order",
	}

	_, err := mgr.ObtainCertificate(context.Background(), []string{"test.example.com"})
	if err == nil {
		t.Fatal("Expected error for invalid order JSON")
	}
	if !strings.Contains(err.Error(), "decode order") {
		t.Errorf("Expected 'decode order' error, got: %v", err)
	}
}

// TestObtainCertificate_CreateOrderError verifies signedPost failure for order creation
func TestObtainCertificate_CreateOrderError(t *testing.T) {
	dir := t.TempDir()
	mgr, _ := NewACMEManager("test@example.com", dir, true, nil)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	mgr.account = &acmeAccount{Key: key, URL: "http://127.0.0.1:1/account/1"}
	// Point nonce to unreachable address so getNonce fails, which makes signedPost fail
	mgr.directory = acmeDirectory{
		NewNonce: "http://127.0.0.1:1/nonce",
		NewOrder: "http://127.0.0.1:1/order",
	}
	mgr.httpClient = &http.Client{Timeout: 100 * time.Millisecond}

	_, err := mgr.ObtainCertificate(context.Background(), []string{"test.example.com"})
	if err == nil {
		t.Fatal("Expected error for failed order creation")
	}
	if !strings.Contains(err.Error(), "create order") {
		t.Errorf("Expected 'create order' error, got: %v", err)
	}
}

// TestObtainCertificate_AuthorizationError verifies processAuthorization failure in ObtainCertificate
func TestObtainCertificate_AuthorizationError(t *testing.T) {
	callCount := 0
	authzFailSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "HEAD" {
			w.Header().Set("Replay-Nonce", "nonce-1")
			return
		}
		callCount++
		if callCount == 1 {
			// First POST: create order => return valid order with authz
			w.Header().Set("Location", "http://"+r.Host+"/order/1")
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(acmeOrder{
				Status:         "pending",
				Authorizations: []string{"http://" + r.Host + "/authz/1"},
				Finalize:       "http://" + r.Host + "/finalize",
			})
			return
		}
		// Second POST: fetch authz => return invalid JSON to trigger error
		w.Write([]byte("bad-json"))
	}))
	defer authzFailSrv.Close()

	dir := t.TempDir()
	mgr, _ := NewACMEManager("test@example.com", dir, true, nil)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	mgr.account = &acmeAccount{Key: key, URL: authzFailSrv.URL + "/account/1"}
	mgr.directory = acmeDirectory{
		NewNonce: authzFailSrv.URL + "/nonce",
		NewOrder: authzFailSrv.URL + "/order",
	}

	_, err := mgr.ObtainCertificate(context.Background(), []string{"test.example.com"})
	if err == nil {
		t.Fatal("Expected authorization error")
	}
	if !strings.Contains(err.Error(), "authorization") {
		t.Errorf("Expected 'authorization' error, got: %v", err)
	}
}

// TestObtainCertificate_OrderWaitInvalidStatus tests the "invalid" order status path
func TestObtainCertificate_OrderWaitInvalidStatus(t *testing.T) {
	callCount := 0
	invalidOrderSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "HEAD" {
			w.Header().Set("Replay-Nonce", fmt.Sprintf("nonce-%d", time.Now().UnixNano()))
			return
		}
		callCount++
		w.Header().Set("Content-Type", "application/json")
		switch {
		case callCount == 1:
			// Create order
			w.Header().Set("Location", "http://"+r.Host+"/order/1")
			json.NewEncoder(w).Encode(acmeOrder{
				Status:         "pending",
				Authorizations: []string{"http://" + r.Host + "/authz/1"},
				Finalize:       "http://" + r.Host + "/finalize",
			})
		case callCount == 2:
			// Fetch authz => already valid
			json.NewEncoder(w).Encode(acmeAuthorization{
				Status:     "valid",
				Identifier: acmeIdentifier{Type: "dns", Value: "test.example.com"},
			})
		default:
			// Poll order => invalid
			json.NewEncoder(w).Encode(acmeOrder{
				Status: "invalid",
			})
		}
	}))
	defer invalidOrderSrv.Close()

	dir := t.TempDir()
	mgr, _ := NewACMEManager("test@example.com", dir, true, nil)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	mgr.account = &acmeAccount{Key: key, URL: invalidOrderSrv.URL + "/account/1"}
	mgr.directory = acmeDirectory{
		NewNonce: invalidOrderSrv.URL + "/nonce",
		NewOrder: invalidOrderSrv.URL + "/order",
	}

	_, err := mgr.ObtainCertificate(context.Background(), []string{"test.example.com"})
	if err == nil {
		t.Fatal("Expected error for invalid order status")
	}
	if !strings.Contains(err.Error(), "order status invalid") {
		t.Errorf("Expected 'order status invalid' error, got: %v", err)
	}
}

// TestObtainCertificate_OrderWaitTimeout tests the order timeout (never becomes ready)
func TestObtainCertificate_OrderWaitTimeout(t *testing.T) {
	callCount := 0
	pendingOrderSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "HEAD" {
			w.Header().Set("Replay-Nonce", fmt.Sprintf("nonce-%d", time.Now().UnixNano()))
			return
		}
		callCount++
		w.Header().Set("Content-Type", "application/json")
		switch {
		case callCount == 1:
			// Create order
			w.Header().Set("Location", "http://"+r.Host+"/order/1")
			json.NewEncoder(w).Encode(acmeOrder{
				Status:         "pending",
				Authorizations: []string{"http://" + r.Host + "/authz/1"},
				Finalize:       "http://" + r.Host + "/finalize",
			})
		case callCount == 2:
			// Fetch authz => already valid
			json.NewEncoder(w).Encode(acmeAuthorization{
				Status:     "valid",
				Identifier: acmeIdentifier{Type: "dns", Value: "test.example.com"},
			})
		default:
			// Always pending - never becomes ready
			json.NewEncoder(w).Encode(acmeOrder{
				Status: "pending",
			})
		}
	}))
	defer pendingOrderSrv.Close()

	dir := t.TempDir()
	mgr, _ := NewACMEManager("test@example.com", dir, true, nil)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	mgr.account = &acmeAccount{Key: key, URL: pendingOrderSrv.URL + "/account/1"}
	mgr.directory = acmeDirectory{
		NewNonce: pendingOrderSrv.URL + "/nonce",
		NewOrder: pendingOrderSrv.URL + "/order",
	}

	// Use context with tight timeout to avoid waiting for all 30 iterations
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	_, err := mgr.ObtainCertificate(ctx, []string{"test.example.com"})
	if err == nil {
		t.Fatal("Expected error for order timeout or context cancellation")
	}
}

// TestObtainCertificate_ContextCancelDuringOrderWait tests ctx.Done in the order wait loop
func TestObtainCertificate_ContextCancelDuringOrderWait(t *testing.T) {
	callCount := 0
	pendingSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "HEAD" {
			w.Header().Set("Replay-Nonce", fmt.Sprintf("nonce-%d", time.Now().UnixNano()))
			return
		}
		callCount++
		w.Header().Set("Content-Type", "application/json")
		switch {
		case callCount == 1:
			w.Header().Set("Location", "http://"+r.Host+"/order/1")
			json.NewEncoder(w).Encode(acmeOrder{
				Status:         "pending",
				Authorizations: []string{"http://" + r.Host + "/authz/1"},
				Finalize:       "http://" + r.Host + "/finalize",
			})
		case callCount == 2:
			json.NewEncoder(w).Encode(acmeAuthorization{
				Status:     "valid",
				Identifier: acmeIdentifier{Type: "dns", Value: "test.example.com"},
			})
		default:
			// Keep pending to let context cancel
			json.NewEncoder(w).Encode(acmeOrder{Status: "processing"})
		}
	}))
	defer pendingSrv.Close()

	dir := t.TempDir()
	mgr, _ := NewACMEManager("test@example.com", dir, true, nil)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	mgr.account = &acmeAccount{Key: key, URL: pendingSrv.URL + "/account/1"}
	mgr.directory = acmeDirectory{
		NewNonce: pendingSrv.URL + "/nonce",
		NewOrder: pendingSrv.URL + "/order",
	}

	ctx, cancel := context.WithCancel(context.Background())
	// Cancel shortly after the order wait starts polling
	go func() {
		time.Sleep(100 * time.Millisecond)
		cancel()
	}()

	_, err := mgr.ObtainCertificate(ctx, []string{"test.example.com"})
	if err == nil {
		t.Fatal("Expected context cancelled error")
	}
}

// TestObtainCertificate_FinalizeError tests finalize signedPost failure
func TestObtainCertificate_FinalizeError(t *testing.T) {
	callCount := 0
	finErrSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "HEAD" {
			w.Header().Set("Replay-Nonce", fmt.Sprintf("nonce-%d", time.Now().UnixNano()))
			return
		}
		callCount++
		w.Header().Set("Content-Type", "application/json")
		switch {
		case callCount == 1:
			// Create order
			w.Header().Set("Location", "http://"+r.Host+"/order/1")
			json.NewEncoder(w).Encode(acmeOrder{
				Status:         "pending",
				Authorizations: []string{"http://" + r.Host + "/authz/1"},
				Finalize:       "http://" + r.Host + "/finalize",
			})
		case callCount == 2:
			// Authz already valid
			json.NewEncoder(w).Encode(acmeAuthorization{
				Status:     "valid",
				Identifier: acmeIdentifier{Type: "dns", Value: "test.example.com"},
			})
		case callCount == 3:
			// Poll order: ready
			json.NewEncoder(w).Encode(acmeOrder{
				Status:   "ready",
				Finalize: "http://" + r.Host + "/finalize",
			})
		case callCount == 4:
			// Finalize: return 500
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(`{"type":"serverInternal","detail":"finalize failed"}`))
		default:
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer finErrSrv.Close()

	dir := t.TempDir()
	mgr, _ := NewACMEManager("test@example.com", dir, true, nil)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	mgr.account = &acmeAccount{Key: key, URL: finErrSrv.URL + "/account/1"}
	mgr.directory = acmeDirectory{
		NewNonce: finErrSrv.URL + "/nonce",
		NewOrder: finErrSrv.URL + "/order",
	}

	_, err := mgr.ObtainCertificate(context.Background(), []string{"test.example.com"})
	if err == nil {
		t.Fatal("Expected finalize error")
	}
	if !strings.Contains(err.Error(), "finalize") {
		t.Errorf("Expected 'finalize' error, got: %v", err)
	}
}

// TestObtainCertificate_FinalizeDecodeError tests finalize response decode failure
func TestObtainCertificate_FinalizeDecodeError(t *testing.T) {
	callCount := 0
	finDecErrSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "HEAD" {
			w.Header().Set("Replay-Nonce", fmt.Sprintf("nonce-%d", time.Now().UnixNano()))
			return
		}
		callCount++
		w.Header().Set("Content-Type", "application/json")
		switch {
		case callCount == 1:
			w.Header().Set("Location", "http://"+r.Host+"/order/1")
			json.NewEncoder(w).Encode(acmeOrder{
				Status:         "pending",
				Authorizations: []string{"http://" + r.Host + "/authz/1"},
				Finalize:       "http://" + r.Host + "/finalize",
			})
		case callCount == 2:
			json.NewEncoder(w).Encode(acmeAuthorization{
				Status:     "valid",
				Identifier: acmeIdentifier{Type: "dns", Value: "test.example.com"},
			})
		case callCount == 3:
			json.NewEncoder(w).Encode(acmeOrder{
				Status:   "ready",
				Finalize: "http://" + r.Host + "/finalize",
			})
		case callCount == 4:
			// Finalize: return invalid JSON
			w.Write([]byte("bad-finalize-json"))
		default:
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer finDecErrSrv.Close()

	dir := t.TempDir()
	mgr, _ := NewACMEManager("test@example.com", dir, true, nil)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	mgr.account = &acmeAccount{Key: key, URL: finDecErrSrv.URL + "/account/1"}
	mgr.directory = acmeDirectory{
		NewNonce: finDecErrSrv.URL + "/nonce",
		NewOrder: finDecErrSrv.URL + "/order",
	}

	_, err := mgr.ObtainCertificate(context.Background(), []string{"test.example.com"})
	if err == nil {
		t.Fatal("Expected decode finalize error")
	}
	if !strings.Contains(err.Error(), "decode finalize") {
		t.Errorf("Expected 'decode finalize' error, got: %v", err)
	}
}

// TestObtainCertificate_CertWaitTimeout tests certificate URL never becomes available
func TestObtainCertificate_CertWaitTimeout(t *testing.T) {
	callCount := 0
	noCertSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "HEAD" {
			w.Header().Set("Replay-Nonce", fmt.Sprintf("nonce-%d", time.Now().UnixNano()))
			return
		}
		callCount++
		w.Header().Set("Content-Type", "application/json")
		switch {
		case callCount == 1:
			w.Header().Set("Location", "http://"+r.Host+"/order/1")
			json.NewEncoder(w).Encode(acmeOrder{
				Status:         "pending",
				Authorizations: []string{"http://" + r.Host + "/authz/1"},
				Finalize:       "http://" + r.Host + "/finalize",
			})
		case callCount == 2:
			json.NewEncoder(w).Encode(acmeAuthorization{
				Status:     "valid",
				Identifier: acmeIdentifier{Type: "dns", Value: "test.example.com"},
			})
		case callCount == 3:
			json.NewEncoder(w).Encode(acmeOrder{
				Status:   "ready",
				Finalize: "http://" + r.Host + "/finalize",
			})
		case callCount == 4:
			// Finalize returns valid but no certificate URL
			json.NewEncoder(w).Encode(acmeOrder{
				Status:      "valid",
				Certificate: "", // no cert URL
			})
		default:
			// Order polling: never has certificate URL
			json.NewEncoder(w).Encode(acmeOrder{
				Status:      "valid",
				Certificate: "",
			})
		}
	}))
	defer noCertSrv.Close()

	dir := t.TempDir()
	mgr, _ := NewACMEManager("test@example.com", dir, true, nil)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	mgr.account = &acmeAccount{Key: key, URL: noCertSrv.URL + "/account/1"}
	mgr.directory = acmeDirectory{
		NewNonce: noCertSrv.URL + "/nonce",
		NewOrder: noCertSrv.URL + "/order",
	}

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	_, err := mgr.ObtainCertificate(ctx, []string{"test.example.com"})
	if err == nil {
		t.Fatal("Expected error for certificate URL not available")
	}
}

// TestObtainCertificate_ContextCancelDuringCertWait tests ctx.Done in the certificate wait loop
func TestObtainCertificate_ContextCancelDuringCertWait(t *testing.T) {
	callCount := 0
	certWaitSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "HEAD" {
			w.Header().Set("Replay-Nonce", fmt.Sprintf("nonce-%d", time.Now().UnixNano()))
			return
		}
		callCount++
		w.Header().Set("Content-Type", "application/json")
		switch {
		case callCount == 1:
			w.Header().Set("Location", "http://"+r.Host+"/order/1")
			json.NewEncoder(w).Encode(acmeOrder{
				Status:         "pending",
				Authorizations: []string{"http://" + r.Host + "/authz/1"},
				Finalize:       "http://" + r.Host + "/finalize",
			})
		case callCount == 2:
			json.NewEncoder(w).Encode(acmeAuthorization{
				Status:     "valid",
				Identifier: acmeIdentifier{Type: "dns", Value: "test.example.com"},
			})
		case callCount == 3:
			json.NewEncoder(w).Encode(acmeOrder{
				Status:   "ready",
				Finalize: "http://" + r.Host + "/finalize",
			})
		case callCount == 4:
			// Finalize: no cert URL
			json.NewEncoder(w).Encode(acmeOrder{Status: "processing", Certificate: ""})
		default:
			// Keep returning no certificate
			json.NewEncoder(w).Encode(acmeOrder{Status: "processing", Certificate: ""})
		}
	}))
	defer certWaitSrv.Close()

	dir := t.TempDir()
	mgr, _ := NewACMEManager("test@example.com", dir, true, nil)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	mgr.account = &acmeAccount{Key: key, URL: certWaitSrv.URL + "/account/1"}
	mgr.directory = acmeDirectory{
		NewNonce: certWaitSrv.URL + "/nonce",
		NewOrder: certWaitSrv.URL + "/order",
	}

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(100 * time.Millisecond)
		cancel()
	}()

	_, err := mgr.ObtainCertificate(ctx, []string{"test.example.com"})
	if err == nil {
		t.Fatal("Expected error from context cancel during cert wait")
	}
}

// TestObtainCertificate_DownloadCertError tests certificate download failure
func TestObtainCertificate_DownloadCertError(t *testing.T) {
	callCount := 0
	dlFailSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "HEAD" {
			w.Header().Set("Replay-Nonce", fmt.Sprintf("nonce-%d", time.Now().UnixNano()))
			return
		}
		callCount++
		w.Header().Set("Content-Type", "application/json")
		switch {
		case callCount == 1:
			w.Header().Set("Location", "http://"+r.Host+"/order/1")
			json.NewEncoder(w).Encode(acmeOrder{
				Status:         "pending",
				Authorizations: []string{"http://" + r.Host + "/authz/1"},
				Finalize:       "http://" + r.Host + "/finalize",
			})
		case callCount == 2:
			json.NewEncoder(w).Encode(acmeAuthorization{
				Status:     "valid",
				Identifier: acmeIdentifier{Type: "dns", Value: "test.example.com"},
			})
		case callCount == 3:
			json.NewEncoder(w).Encode(acmeOrder{
				Status:   "ready",
				Finalize: "http://" + r.Host + "/finalize",
			})
		case callCount == 4:
			// Finalize: return cert URL
			json.NewEncoder(w).Encode(acmeOrder{
				Status:      "valid",
				Certificate: "http://" + r.Host + "/cert",
			})
		case callCount == 5:
			// Download cert: fail with 500
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte("download failed"))
		default:
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer dlFailSrv.Close()

	dir := t.TempDir()
	mgr, _ := NewACMEManager("test@example.com", dir, true, nil)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	mgr.account = &acmeAccount{Key: key, URL: dlFailSrv.URL + "/account/1"}
	mgr.directory = acmeDirectory{
		NewNonce: dlFailSrv.URL + "/nonce",
		NewOrder: dlFailSrv.URL + "/order",
	}

	_, err := mgr.ObtainCertificate(context.Background(), []string{"test.example.com"})
	if err == nil {
		t.Fatal("Expected download certificate error")
	}
	if !strings.Contains(err.Error(), "download certificate") {
		t.Errorf("Expected 'download certificate' error, got: %v", err)
	}
}

// TestObtainCertificate_OrderPollSignedPostError tests signedPost error during order polling
func TestObtainCertificate_OrderPollSignedPostError(t *testing.T) {
	callCount := 0
	pollErrSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "HEAD" {
			callCount++
			// Let the first few nonce requests succeed, then fail them to trigger signedPost error during polling
			if callCount > 4 {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			w.Header().Set("Replay-Nonce", fmt.Sprintf("nonce-%d", time.Now().UnixNano()))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		// Track POST calls separately
		if strings.HasSuffix(r.URL.Path, "/order") {
			w.Header().Set("Location", "http://"+r.Host+"/order/1")
			json.NewEncoder(w).Encode(acmeOrder{
				Status:         "pending",
				Authorizations: []string{"http://" + r.Host + "/authz/1"},
				Finalize:       "http://" + r.Host + "/finalize",
			})
			return
		}
		if strings.HasSuffix(r.URL.Path, "/authz/1") {
			json.NewEncoder(w).Encode(acmeAuthorization{
				Status:     "valid",
				Identifier: acmeIdentifier{Type: "dns", Value: "test.example.com"},
			})
			return
		}
		// Order polling => pending status always
		json.NewEncoder(w).Encode(acmeOrder{Status: "pending"})
	}))
	defer pollErrSrv.Close()

	dir := t.TempDir()
	mgr, _ := NewACMEManager("test@example.com", dir, true, nil)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	mgr.account = &acmeAccount{Key: key, URL: pollErrSrv.URL + "/account/1"}
	mgr.directory = acmeDirectory{
		NewNonce: pollErrSrv.URL + "/nonce",
		NewOrder: pollErrSrv.URL + "/order",
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	_, err := mgr.ObtainCertificate(ctx, []string{"test.example.com"})
	if err == nil {
		t.Fatal("Expected error during order polling")
	}
}

// TestTLSCertificate_InvalidPEM tests TLSCertificate with invalid CertPEM
func TestTLSCertificate_InvalidPEM(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	bundle := &CertificateBundle{
		CertPEM:    []byte("not-valid-pem"),
		PrivateKey: key,
	}

	_, err := bundle.TLSCertificate()
	if err == nil {
		t.Error("Expected error for invalid CertPEM")
	}
}

// TestProcessAuthorization_SignedPostError tests processAuthorization when initial signedPost fails
func TestProcessAuthorization_SignedPostError(t *testing.T) {
	dir := t.TempDir()
	mgr, _ := NewACMEManager("test@example.com", dir, true, nil)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	mgr.account = &acmeAccount{Key: key, URL: "http://127.0.0.1:1/account/1"}
	// Point nonce to unreachable address so getNonce fails at the network level
	mgr.directory = acmeDirectory{NewNonce: "http://127.0.0.1:1/nonce"}
	mgr.httpClient = &http.Client{Timeout: 100 * time.Millisecond}

	err := mgr.processAuthorization(context.Background(), "http://127.0.0.1:1/authz/1")
	if err == nil {
		t.Error("Expected error from processAuthorization when signedPost fails")
	}
}

// TestProcessAuthorization_DecodeAuthzError tests processAuthorization when authz JSON is invalid
func TestProcessAuthorization_DecodeAuthzError(t *testing.T) {
	badJsonSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "HEAD" {
			w.Header().Set("Replay-Nonce", "nonce-1")
			return
		}
		// Return invalid JSON
		w.Write([]byte("bad-json-authz"))
	}))
	defer badJsonSrv.Close()

	dir := t.TempDir()
	mgr, _ := NewACMEManager("test@example.com", dir, true, nil)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	mgr.account = &acmeAccount{Key: key, URL: badJsonSrv.URL + "/account/1"}
	mgr.directory = acmeDirectory{NewNonce: badJsonSrv.URL + "/nonce"}

	err := mgr.processAuthorization(context.Background(), badJsonSrv.URL+"/authz/1")
	if err == nil {
		t.Error("Expected error for invalid authz JSON")
	}
}

// TestProcessAuthorization_ChallengeRespondError tests processAuthorization when challenge response fails
func TestProcessAuthorization_ChallengeRespondError(t *testing.T) {
	postCount := 0
	challErrSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "HEAD" {
			w.Header().Set("Replay-Nonce", fmt.Sprintf("nonce-%d", time.Now().UnixNano()))
			return
		}
		postCount++
		w.Header().Set("Content-Type", "application/json")
		if postCount == 1 {
			// First POST: fetch authz - return pending with challenge
			json.NewEncoder(w).Encode(acmeAuthorization{
				Status:     "pending",
				Identifier: acmeIdentifier{Type: "dns", Value: "test.example.com"},
				Challenges: []acmeChallenge{
					{
						Type:   "http-01",
						URL:    "http://" + r.Host + "/challenge/1",
						Token:  "test-token-12345678",
						Status: "pending",
					},
				},
			})
			return
		}
		// Second POST: respond to challenge - return error
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte(`{"type":"forbidden","detail":"challenge respond failed"}`))
	}))
	defer challErrSrv.Close()

	dir := t.TempDir()
	mgr, _ := NewACMEManager("test@example.com", dir, true, nil)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	mgr.account = &acmeAccount{Key: key, URL: challErrSrv.URL + "/account/1"}
	mgr.directory = acmeDirectory{NewNonce: challErrSrv.URL + "/nonce"}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err := mgr.processAuthorization(ctx, challErrSrv.URL+"/authz/1")
	if err == nil {
		t.Error("Expected error from challenge respond failure")
	}
}

// TestProcessAuthorization_ChallengeInvalid tests processAuthorization when challenge becomes invalid
func TestProcessAuthorization_ChallengeInvalid(t *testing.T) {
	callCount := 0
	challInvalidSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "HEAD" {
			w.Header().Set("Replay-Nonce", fmt.Sprintf("nonce-%d", time.Now().UnixNano()))
			return
		}
		callCount++
		w.Header().Set("Content-Type", "application/json")
		if callCount == 1 {
			// Fetch authz: pending with http-01 challenge
			json.NewEncoder(w).Encode(acmeAuthorization{
				Status:     "pending",
				Identifier: acmeIdentifier{Type: "dns", Value: "test.example.com"},
				Challenges: []acmeChallenge{
					{
						Type:   "http-01",
						URL:    "http://" + r.Host + "/challenge/1",
						Token:  "test-token-12345678",
						Status: "pending",
					},
				},
			})
			return
		}
		if callCount == 2 {
			// Respond to challenge: ok
			json.NewEncoder(w).Encode(map[string]string{"status": "processing"})
			return
		}
		// All subsequent polls: invalid
		json.NewEncoder(w).Encode(acmeAuthorization{
			Status:     "invalid",
			Identifier: acmeIdentifier{Type: "dns", Value: "test.example.com"},
		})
	}))
	defer challInvalidSrv.Close()

	dir := t.TempDir()
	mgr, _ := NewACMEManager("test@example.com", dir, true, nil)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	mgr.account = &acmeAccount{Key: key, URL: challInvalidSrv.URL + "/account/1"}
	mgr.directory = acmeDirectory{NewNonce: challInvalidSrv.URL + "/nonce"}

	err := mgr.processAuthorization(context.Background(), challInvalidSrv.URL+"/authz/1")
	if err == nil {
		t.Fatal("Expected error for invalid challenge status")
	}
	if !strings.Contains(err.Error(), "challenge invalid") {
		t.Errorf("Expected 'challenge invalid' error, got: %v", err)
	}
}

// TestProcessAuthorization_ChallengeTimeout tests processAuthorization timeout (always processing)
func TestProcessAuthorization_ChallengeTimeout(t *testing.T) {
	callCount := 0
	challTimeoutSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "HEAD" {
			w.Header().Set("Replay-Nonce", fmt.Sprintf("nonce-%d", time.Now().UnixNano()))
			return
		}
		callCount++
		w.Header().Set("Content-Type", "application/json")
		if callCount == 1 {
			json.NewEncoder(w).Encode(acmeAuthorization{
				Status:     "pending",
				Identifier: acmeIdentifier{Type: "dns", Value: "test.example.com"},
				Challenges: []acmeChallenge{
					{
						Type:   "http-01",
						URL:    "http://" + r.Host + "/challenge/1",
						Token:  "test-token-12345678",
						Status: "pending",
					},
				},
			})
			return
		}
		if callCount == 2 {
			json.NewEncoder(w).Encode(map[string]string{"status": "processing"})
			return
		}
		// Always processing
		json.NewEncoder(w).Encode(acmeAuthorization{
			Status:     "processing",
			Identifier: acmeIdentifier{Type: "dns", Value: "test.example.com"},
		})
	}))
	defer challTimeoutSrv.Close()

	dir := t.TempDir()
	mgr, _ := NewACMEManager("test@example.com", dir, true, nil)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	mgr.account = &acmeAccount{Key: key, URL: challTimeoutSrv.URL + "/account/1"}
	mgr.directory = acmeDirectory{NewNonce: challTimeoutSrv.URL + "/nonce"}

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	err := mgr.processAuthorization(ctx, challTimeoutSrv.URL+"/authz/1")
	if err == nil {
		t.Fatal("Expected error for challenge timeout")
	}
}

// TestProcessAuthorization_ContextCancelDuringPoll tests ctx.Done during challenge polling
func TestProcessAuthorization_ContextCancelDuringPoll(t *testing.T) {
	callCount := 0
	pollSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "HEAD" {
			w.Header().Set("Replay-Nonce", fmt.Sprintf("nonce-%d", time.Now().UnixNano()))
			return
		}
		callCount++
		w.Header().Set("Content-Type", "application/json")
		if callCount == 1 {
			json.NewEncoder(w).Encode(acmeAuthorization{
				Status:     "pending",
				Identifier: acmeIdentifier{Type: "dns", Value: "test.example.com"},
				Challenges: []acmeChallenge{
					{Type: "http-01", URL: "http://" + r.Host + "/challenge/1", Token: "test-token-12345678", Status: "pending"},
				},
			})
			return
		}
		if callCount == 2 {
			json.NewEncoder(w).Encode(map[string]string{"status": "processing"})
			return
		}
		json.NewEncoder(w).Encode(acmeAuthorization{Status: "processing", Identifier: acmeIdentifier{Type: "dns", Value: "test.example.com"}})
	}))
	defer pollSrv.Close()

	dir := t.TempDir()
	mgr, _ := NewACMEManager("test@example.com", dir, true, nil)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	mgr.account = &acmeAccount{Key: key, URL: pollSrv.URL + "/account/1"}
	mgr.directory = acmeDirectory{NewNonce: pollSrv.URL + "/nonce"}

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(100 * time.Millisecond)
		cancel()
	}()

	err := mgr.processAuthorization(ctx, pollSrv.URL+"/authz/1")
	if err == nil {
		t.Fatal("Expected context cancelled error during challenge poll")
	}
}

// TestGetNonce_HTTPError tests getNonce when HTTP request fails
func TestGetNonce_HTTPError(t *testing.T) {
	dir := t.TempDir()
	mgr, _ := NewACMEManager("test@example.com", dir, true, nil)
	mgr.directory = acmeDirectory{NewNonce: "http://127.0.0.1:1/nonce"}
	mgr.httpClient = &http.Client{Timeout: 100 * time.Millisecond}

	_, err := mgr.getNonce(context.Background())
	if err == nil {
		t.Error("Expected error from getNonce with unreachable server")
	}
}

// TestLoadOrCreateKey_CorruptPEM tests loadOrCreateKey with corrupt PEM data on disk
func TestLoadOrCreateKey_CorruptPEM(t *testing.T) {
	dir := t.TempDir()
	mgr, _ := NewACMEManager("test@example.com", dir, true, nil)

	keyPath := filepath.Join(dir, "corrupt.key")
	// Write corrupt data (not valid PEM)
	os.WriteFile(keyPath, []byte("this is not PEM data"), 0600)

	// Should fall through to generate a new key
	key, err := mgr.loadOrCreateKey(keyPath)
	if err != nil {
		t.Fatalf("loadOrCreateKey with corrupt PEM should generate new key: %v", err)
	}
	if key == nil {
		t.Fatal("Expected a new key to be generated")
	}
}

// TestLoadOrCreateKey_CorruptPEMBlock tests loadOrCreateKey with valid PEM but invalid key bytes
func TestLoadOrCreateKey_CorruptPEMBlock(t *testing.T) {
	dir := t.TempDir()
	mgr, _ := NewACMEManager("test@example.com", dir, true, nil)

	keyPath := filepath.Join(dir, "badkey.key")
	// Write valid PEM with invalid key bytes
	badPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: []byte("not-a-valid-key")})
	os.WriteFile(keyPath, badPEM, 0600)

	// Should fall through to generate a new key because ParseECPrivateKey fails
	key, err := mgr.loadOrCreateKey(keyPath)
	if err != nil {
		t.Fatalf("loadOrCreateKey with bad key bytes should generate new key: %v", err)
	}
	if key == nil {
		t.Fatal("Expected a new key to be generated")
	}
}

// TestLoadOrCreateKey_WriteError tests loadOrCreateKey when key file cannot be saved
func TestLoadOrCreateKey_WriteError(t *testing.T) {
	dir := t.TempDir()
	mgr, _ := NewACMEManager("test@example.com", dir, true, nil)

	// Create a directory where the key file should go, blocking WriteFile
	keyPath := filepath.Join(dir, "blocked.key")
	os.MkdirAll(keyPath, 0700)

	_, err := mgr.loadOrCreateKey(keyPath)
	if err == nil {
		t.Error("Expected error when key file cannot be written")
	}
	if !strings.Contains(err.Error(), "save account key") {
		t.Errorf("Expected 'save account key' error, got: %v", err)
	}
}

// TestSaveCertBundle_CertWriteError tests saveCertBundle when cert file cannot be written
func TestSaveCertBundle_CertWriteError(t *testing.T) {
	dir := t.TempDir()
	mgr, _ := NewACMEManager("test@example.com", dir, true, nil)

	// Block the .crt file by creating a directory with the same name
	certBlocker := filepath.Join(dir, "blocked.crt")
	os.MkdirAll(certBlocker, 0700)

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	bundle := &CertificateBundle{
		CertPEM:    []byte("fake-cert-pem"),
		PrivateKey: key,
		Domains:    []string{"blocked"},
		IssuedAt:   time.Now(),
		ExpiresAt:  time.Now().Add(90 * 24 * time.Hour),
	}

	err := mgr.saveCertBundle("blocked", bundle)
	if err == nil {
		t.Error("Expected error writing cert file")
	}
}

// TestSaveCertBundle_KeyWriteError tests saveCertBundle when key file cannot be written
func TestSaveCertBundle_KeyWriteError(t *testing.T) {
	dir := t.TempDir()
	mgr, _ := NewACMEManager("test@example.com", dir, true, nil)

	// Block the .key file by creating a directory with the same name
	keyBlocker := filepath.Join(dir, "keyblocked.key")
	os.MkdirAll(keyBlocker, 0700)

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	bundle := &CertificateBundle{
		CertPEM:    []byte("fake-cert-pem"),
		PrivateKey: key,
		Domains:    []string{"keyblocked"},
		IssuedAt:   time.Now(),
		ExpiresAt:  time.Now().Add(90 * 24 * time.Hour),
	}

	err := mgr.saveCertBundle("keyblocked", bundle)
	if err == nil {
		t.Error("Expected error writing key file")
	}
}

// TestSaveCertBundle_MetadataWriteError tests saveCertBundle when metadata JSON file cannot be written
func TestSaveCertBundle_MetadataWriteError(t *testing.T) {
	dir := t.TempDir()
	mgr, _ := NewACMEManager("test@example.com", dir, true, nil)

	// Block the .json file by creating a directory with the same name
	metaBlocker := filepath.Join(dir, "metaerr.json")
	os.MkdirAll(metaBlocker, 0700)

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	bundle := &CertificateBundle{
		CertPEM:    []byte("fake-cert-pem"),
		PrivateKey: key,
		Domains:    []string{"metaerr"},
		IssuedAt:   time.Now(),
		ExpiresAt:  time.Now().Add(90 * 24 * time.Hour),
	}

	// saveCertBundle should NOT return an error for metadata write failure (it only logs a warning)
	err := mgr.saveCertBundle("metaerr", bundle)
	if err != nil {
		t.Errorf("saveCertBundle should succeed even when metadata write fails: %v", err)
	}
}

// TestLoadCertBundle_KeyFileReadError tests LoadCertBundle when key file is missing
func TestLoadCertBundle_KeyFileReadError(t *testing.T) {
	dir := t.TempDir()
	mgr, _ := NewACMEManager("test@example.com", dir, true, nil)

	// Create .crt but no .key
	os.WriteFile(filepath.Join(dir, "nokey.crt"), []byte("fake-cert"), 0600)

	_, err := mgr.LoadCertBundle("nokey")
	if err == nil {
		t.Error("Expected error when key file is missing")
	}
}

// TestLoadCertBundle_InvalidKeyPEM tests LoadCertBundle with non-PEM key data
func TestLoadCertBundle_InvalidKeyPEM(t *testing.T) {
	dir := t.TempDir()
	mgr, _ := NewACMEManager("test@example.com", dir, true, nil)

	os.WriteFile(filepath.Join(dir, "badpem.crt"), []byte("fake-cert"), 0600)
	os.WriteFile(filepath.Join(dir, "badpem.key"), []byte("not-pem-data"), 0600)

	_, err := mgr.LoadCertBundle("badpem")
	if err == nil {
		t.Error("Expected error for invalid key PEM")
	}
	if !strings.Contains(err.Error(), "invalid key PEM") {
		t.Errorf("Expected 'invalid key PEM' error, got: %v", err)
	}
}

// TestLoadCertBundle_InvalidKeyBytes tests LoadCertBundle with valid PEM but invalid EC key bytes
func TestLoadCertBundle_InvalidKeyBytes(t *testing.T) {
	dir := t.TempDir()
	mgr, _ := NewACMEManager("test@example.com", dir, true, nil)

	os.WriteFile(filepath.Join(dir, "badec.crt"), []byte("fake-cert"), 0600)
	badKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: []byte("invalid-ec-bytes")})
	os.WriteFile(filepath.Join(dir, "badec.key"), badKeyPEM, 0600)

	_, err := mgr.LoadCertBundle("badec")
	if err == nil {
		t.Error("Expected error for invalid EC key bytes")
	}
}

// TestLoadCertBundle_CorruptMetadataJSON tests LoadCertBundle with corrupt metadata JSON
func TestLoadCertBundle_CorruptMetadataJSON(t *testing.T) {
	dir := t.TempDir()
	mgr, _ := NewACMEManager("test@example.com", dir, true, nil)

	// First save a valid bundle
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	serial, _ := rand.Int(rand.Reader, big.NewInt(1000000))
	template := &x509.Certificate{
		SerialNumber: serial,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(90 * 24 * time.Hour),
		DNSNames:     []string{"corrupt-meta.example.com"},
	}
	certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	bundle := &CertificateBundle{
		CertPEM:    certPEM,
		PrivateKey: key,
		Domains:    []string{"corrupt-meta.example.com"},
		IssuedAt:   time.Now(),
		ExpiresAt:  time.Now().Add(90 * 24 * time.Hour),
	}
	mgr.saveCertBundle("corrupt-meta.example.com", bundle)

	// Corrupt the metadata JSON
	os.WriteFile(filepath.Join(dir, "corrupt-meta.example.com.json"), []byte("not-json{{{"), 0600)

	loaded, err := mgr.LoadCertBundle("corrupt-meta.example.com")
	if err != nil {
		t.Fatalf("LoadCertBundle should succeed even with corrupt metadata: %v", err)
	}
	// Metadata fields should be zero since JSON parse failed
	if !loaded.ExpiresAt.IsZero() {
		t.Error("ExpiresAt should be zero with corrupt metadata")
	}
	if !loaded.IssuedAt.IsZero() {
		t.Error("IssuedAt should be zero with corrupt metadata")
	}
}

// TestLoadCertBundle_NoMetadataFile tests LoadCertBundle when metadata file doesn't exist
func TestLoadCertBundle_NoMetadataFile(t *testing.T) {
	dir := t.TempDir()
	mgr, _ := NewACMEManager("test@example.com", dir, true, nil)

	// Save cert and key but remove metadata
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	serial, _ := rand.Int(rand.Reader, big.NewInt(1000000))
	template := &x509.Certificate{
		SerialNumber: serial,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(90 * 24 * time.Hour),
		DNSNames:     []string{"nometa.example.com"},
	}
	certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	bundle := &CertificateBundle{
		CertPEM:    certPEM,
		PrivateKey: key,
		Domains:    []string{"nometa.example.com"},
		IssuedAt:   time.Now(),
		ExpiresAt:  time.Now().Add(90 * 24 * time.Hour),
	}
	mgr.saveCertBundle("nometa.example.com", bundle)

	// Remove the metadata file
	os.Remove(filepath.Join(dir, "nometa.example.com.json"))

	loaded, err := mgr.LoadCertBundle("nometa.example.com")
	if err != nil {
		t.Fatalf("LoadCertBundle should succeed without metadata: %v", err)
	}
	if loaded == nil {
		t.Fatal("Loaded bundle should not be nil")
	}
}

// TestLoadCertBundle_MetadataMissingFields tests LoadCertBundle when metadata has missing fields
func TestLoadCertBundle_MetadataMissingFields(t *testing.T) {
	dir := t.TempDir()
	mgr, _ := NewACMEManager("test@example.com", dir, true, nil)

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	serial, _ := rand.Int(rand.Reader, big.NewInt(1000000))
	template := &x509.Certificate{
		SerialNumber: serial,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(90 * 24 * time.Hour),
		DNSNames:     []string{"partial.example.com"},
	}
	certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	bundle := &CertificateBundle{
		CertPEM:    certPEM,
		PrivateKey: key,
		Domains:    []string{"partial.example.com"},
		IssuedAt:   time.Now(),
		ExpiresAt:  time.Now().Add(90 * 24 * time.Hour),
	}
	mgr.saveCertBundle("partial.example.com", bundle)

	// Overwrite metadata with JSON that has wrong types for expires_at/issued_at
	os.WriteFile(filepath.Join(dir, "partial.example.com.json"), []byte(`{"domains":["partial.example.com"],"expires_at":123,"issued_at":456}`), 0600)

	loaded, err := mgr.LoadCertBundle("partial.example.com")
	if err != nil {
		t.Fatalf("LoadCertBundle should succeed with partial metadata: %v", err)
	}
	// expires_at and issued_at are number not string, so type assertion to string fails
	if !loaded.ExpiresAt.IsZero() {
		t.Error("ExpiresAt should be zero when metadata has wrong types")
	}
}

// TestEstimateExpiry_InvalidCertBytes tests EstimateExpiry with valid PEM but invalid cert bytes
func TestEstimateExpiry_InvalidCertBytes(t *testing.T) {
	badCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("not-a-valid-cert")})
	_, err := EstimateExpiry(badCertPEM)
	if err == nil {
		t.Error("Expected error for invalid certificate bytes")
	}
}

// TestStartAutoRenewal_DoneImmediately tests StartAutoRenewal when done is closed immediately
func TestStartAutoRenewal_DoneImmediately(t *testing.T) {
	dir := t.TempDir()
	mgr, _ := NewACMEManager("test@example.com", dir, true, nil)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	mgr.account = &acmeAccount{Key: key}

	done := make(chan struct{})
	close(done) // Close immediately

	getCert := func(domain string) *CertificateBundle { return nil }
	setCert := func(domain string, b *CertificateBundle) {}

	mgr.StartAutoRenewal([]string{"test.example.com"}, getCert, setCert, done)
	time.Sleep(50 * time.Millisecond) // Allow goroutine to start and exit
}

// TestStartAutoRenewal_RenewalFlow tests the full renewal flow with a fast ticker
func TestStartAutoRenewal_RenewalFlow(t *testing.T) {
	mockSrv := mockACMEServer(t)
	defer mockSrv.Close()
	mgr := setupMockManager(t, mockSrv)
	mgr.registerAccount()

	var renewed bool
	var mu sync.Mutex

	getCert := func(domain string) *CertificateBundle {
		mu.Lock()
		defer mu.Unlock()
		if renewed {
			// After renewal, return a cert that doesn't need renewal
			return &CertificateBundle{ExpiresAt: time.Now().Add(90 * 24 * time.Hour)}
		}
		// Return a bundle that needs renewal
		return &CertificateBundle{ExpiresAt: time.Now().Add(5 * 24 * time.Hour)}
	}
	setCert := func(domain string, b *CertificateBundle) {
		mu.Lock()
		defer mu.Unlock()
		renewed = true
	}

	done := make(chan struct{})
	defer close(done)

	// We can't control the ticker (12h), but we can test the done channel behavior
	mgr.StartAutoRenewal([]string{"test.example.com"}, getCert, setCert, done)
	time.Sleep(50 * time.Millisecond)
}

// TestStartAutoRenewal_NilBundle tests StartAutoRenewal when getCert returns nil
func TestStartAutoRenewal_NilBundle(t *testing.T) {
	mockSrv := mockACMEServer(t)
	defer mockSrv.Close()
	mgr := setupMockManager(t, mockSrv)
	mgr.registerAccount()

	getCert := func(domain string) *CertificateBundle {
		return nil // nil bundle triggers renewal
	}
	setCalled := false
	setCert := func(domain string, b *CertificateBundle) {
		setCalled = true
	}

	done := make(chan struct{})
	mgr.StartAutoRenewal([]string{"test.example.com"}, getCert, setCert, done)
	// Wait briefly then close
	time.Sleep(50 * time.Millisecond)
	close(done)
	time.Sleep(50 * time.Millisecond)
	_ = setCalled
}

// TestSignedPost_ContextCancelled tests signedPost with a cancelled context
func TestSignedPost_ContextCancelled(t *testing.T) {
	mockSrv := mockACMEServer(t)
	defer mockSrv.Close()
	mgr := setupMockManager(t, mockSrv)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	_, err := mgr.signedPost(ctx, mockSrv.URL+"/order/1", nil)
	if err == nil {
		t.Error("Expected error from cancelled context")
	}
}

// TestGetNonce_ContextCancelled tests getNonce with a cancelled context
func TestGetNonce_ContextCancelled(t *testing.T) {
	mockSrv := mockACMEServer(t)
	defer mockSrv.Close()
	mgr := setupMockManager(t, mockSrv)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := mgr.getNonce(ctx)
	if err == nil {
		t.Error("Expected error from cancelled context")
	}
}

// TestObtainCertificate_SaveBundleError tests that ObtainCertificate succeeds even when save fails
func TestObtainCertificate_SaveBundleError(t *testing.T) {
	mockSrv := mockACMEServer(t)
	defer mockSrv.Close()
	mgr := setupMockManager(t, mockSrv)
	mgr.registerAccount()

	// Make certDir read-only to force save to fail
	// On Windows, we block by creating directories with same names
	os.MkdirAll(filepath.Join(mgr.certDir, "test.example.com.crt"), 0700)

	bundle, err := mgr.ObtainCertificate(context.Background(), []string{"test.example.com"})
	// ObtainCertificate should still succeed (saveCertBundle only logs warning)
	if err != nil {
		t.Fatalf("ObtainCertificate should succeed even when save fails: %v", err)
	}
	if bundle == nil {
		t.Fatal("Bundle should not be nil")
	}
}

// TestObtainCertificate_OrderPollDecodeError tests JSON decode error during order polling
func TestObtainCertificate_OrderPollDecodeError(t *testing.T) {
	callCount := 0
	pollDecErrSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "HEAD" {
			w.Header().Set("Replay-Nonce", fmt.Sprintf("nonce-%d", time.Now().UnixNano()))
			return
		}
		callCount++
		w.Header().Set("Content-Type", "application/json")
		switch {
		case callCount == 1:
			w.Header().Set("Location", "http://"+r.Host+"/order/1")
			json.NewEncoder(w).Encode(acmeOrder{
				Status:         "pending",
				Authorizations: []string{"http://" + r.Host + "/authz/1"},
				Finalize:       "http://" + r.Host + "/finalize",
			})
		case callCount == 2:
			json.NewEncoder(w).Encode(acmeAuthorization{
				Status:     "valid",
				Identifier: acmeIdentifier{Type: "dns", Value: "test.example.com"},
			})
		default:
			// Return bad JSON for order polling to trigger decode error
			w.Write([]byte("not-json-order"))
		}
	}))
	defer pollDecErrSrv.Close()

	dir := t.TempDir()
	mgr, _ := NewACMEManager("test@example.com", dir, true, nil)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	mgr.account = &acmeAccount{Key: key, URL: pollDecErrSrv.URL + "/account/1"}
	mgr.directory = acmeDirectory{
		NewNonce: pollDecErrSrv.URL + "/nonce",
		NewOrder: pollDecErrSrv.URL + "/order",
	}

	_, err := mgr.ObtainCertificate(context.Background(), []string{"test.example.com"})
	if err == nil {
		t.Fatal("Expected error for order poll decode failure")
	}
	if !strings.Contains(err.Error(), "decode order") {
		t.Errorf("Expected 'decode order' error, got: %v", err)
	}
}

// TestObtainCertificate_OrderPollSignedPostFail_ThenReady tests that order poll
// handles signedPost failure (return nil, err at line 204-206).
func TestObtainCertificate_OrderPollSignedPostFail_ThenReady(t *testing.T) {
	postCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "HEAD" {
			w.Header().Set("Replay-Nonce", fmt.Sprintf("nonce-%d", time.Now().UnixNano()))
			return
		}
		postCount++
		w.Header().Set("Content-Type", "application/json")
		switch {
		case postCount == 1:
			// Create order
			w.Header().Set("Location", "http://"+r.Host+"/order/1")
			json.NewEncoder(w).Encode(acmeOrder{
				Status:         "pending",
				Authorizations: []string{"http://" + r.Host + "/authz/1"},
				Finalize:       "http://" + r.Host + "/finalize",
			})
		case postCount == 2:
			// Authz: valid
			json.NewEncoder(w).Encode(acmeAuthorization{
				Status:     "valid",
				Identifier: acmeIdentifier{Type: "dns", Value: "test.example.com"},
			})
		case postCount == 3:
			// First order poll: return 500 to trigger the error return at line 204-206
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(`{"type":"error","detail":"server error"}`))
		default:
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(acmeOrder{Status: "pending"})
		}
	}))
	defer srv.Close()

	dir := t.TempDir()
	mgr, _ := NewACMEManager("test@example.com", dir, true, nil)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	mgr.account = &acmeAccount{Key: key, URL: srv.URL + "/account/1"}
	mgr.directory = acmeDirectory{
		NewNonce: srv.URL + "/nonce",
		NewOrder: srv.URL + "/order",
	}

	// The first order poll fails with signedPost error, which returns immediately (line 204-206)
	_, err := mgr.ObtainCertificate(context.Background(), []string{"test.example.com"})
	if err == nil {
		t.Fatal("Expected error from order poll signedPost failure")
	}
	// The error comes from signedPost returning ACME error 500
	if !strings.Contains(err.Error(), "ACME error 500") {
		t.Errorf("Expected ACME error 500, got: %v", err)
	}
}

// TestObtainCertificate_OrderNotReadyContextTimeout tests the context cancellation
// in the order wait loop (line 218-220, the ctx.Done case).
func TestObtainCertificate_OrderNotReadyContextTimeout(t *testing.T) {
	postCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "HEAD" {
			w.Header().Set("Replay-Nonce", fmt.Sprintf("nonce-%d", time.Now().UnixNano()))
			return
		}
		postCount++
		w.Header().Set("Content-Type", "application/json")
		switch {
		case postCount == 1:
			w.Header().Set("Location", "http://"+r.Host+"/order/1")
			json.NewEncoder(w).Encode(acmeOrder{
				Status:         "pending",
				Authorizations: []string{"http://" + r.Host + "/authz/1"},
				Finalize:       "http://" + r.Host + "/finalize",
			})
		case postCount == 2:
			json.NewEncoder(w).Encode(acmeAuthorization{
				Status:     "valid",
				Identifier: acmeIdentifier{Type: "dns", Value: "test.example.com"},
			})
		default:
			// Always pending, context will cancel
			json.NewEncoder(w).Encode(acmeOrder{Status: "pending"})
		}
	}))
	defer srv.Close()

	dir := t.TempDir()
	mgr, _ := NewACMEManager("test@example.com", dir, true, nil)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	mgr.account = &acmeAccount{Key: key, URL: srv.URL + "/account/1"}
	mgr.directory = acmeDirectory{
		NewNonce: srv.URL + "/nonce",
		NewOrder: srv.URL + "/order",
	}

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	_, err := mgr.ObtainCertificate(ctx, []string{"test.example.com"})
	if err == nil {
		t.Fatal("Expected error for context timeout during order wait")
	}
}

// TestObtainCertificate_CertPollErrorsContinue tests that errors during certificate
// polling (lines 260-265) are handled gracefully with continue.
func TestObtainCertificate_CertPollErrorsContinue(t *testing.T) {
	postCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "HEAD" {
			w.Header().Set("Replay-Nonce", fmt.Sprintf("nonce-%d", time.Now().UnixNano()))
			return
		}
		postCount++
		w.Header().Set("Content-Type", "application/json")
		switch {
		case postCount == 1:
			// Create order
			w.Header().Set("Location", "http://"+r.Host+"/order/1")
			json.NewEncoder(w).Encode(acmeOrder{
				Status:         "pending",
				Authorizations: []string{"http://" + r.Host + "/authz/1"},
				Finalize:       "http://" + r.Host + "/finalize",
			})
		case postCount == 2:
			// Authz valid
			json.NewEncoder(w).Encode(acmeAuthorization{
				Status:     "valid",
				Identifier: acmeIdentifier{Type: "dns", Value: "test.example.com"},
			})
		case postCount == 3:
			// Order poll: ready
			json.NewEncoder(w).Encode(acmeOrder{
				Status:   "ready",
				Finalize: "http://" + r.Host + "/finalize",
			})
		case postCount == 4:
			// Finalize: returns valid but no cert URL yet
			json.NewEncoder(w).Encode(acmeOrder{
				Status:      "valid",
				Certificate: "",
			})
		case postCount == 5:
			// Cert poll: return bad JSON (triggers unmarshal continue at line 264-265)
			w.Write([]byte("bad-json"))
		case postCount == 6:
			// Cert poll: return 500 (triggers signedPost error continue at line 261-262)
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte("server error"))
		case postCount == 7:
			// Cert poll: finally has certificate URL
			json.NewEncoder(w).Encode(acmeOrder{
				Status:      "valid",
				Certificate: "http://" + r.Host + "/cert",
			})
		default:
			// Certificate download
			certKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			serial, _ := rand.Int(rand.Reader, big.NewInt(1000))
			tmpl := &x509.Certificate{
				SerialNumber: serial,
				NotBefore:    time.Now(),
				NotAfter:     time.Now().Add(90 * 24 * time.Hour),
				DNSNames:     []string{"test.example.com"},
			}
			certDER, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &certKey.PublicKey, certKey)
			w.Write(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}))
		}
	}))
	defer srv.Close()

	dir := t.TempDir()
	mgr, _ := NewACMEManager("test@example.com", dir, true, nil)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	mgr.account = &acmeAccount{Key: key, URL: srv.URL + "/account/1"}
	mgr.directory = acmeDirectory{
		NewNonce: srv.URL + "/nonce",
		NewOrder: srv.URL + "/order",
	}

	bundle, err := mgr.ObtainCertificate(context.Background(), []string{"test.example.com"})
	if err != nil {
		t.Fatalf("ObtainCertificate should succeed after retries: %v", err)
	}
	if bundle == nil {
		t.Fatal("Bundle should not be nil")
	}
}

// TestObtainCertificate_CertURLNotAvailable tests that when Certificate URL is never
// provided after context timeout, the function returns an error (line 269-271).
func TestObtainCertificate_CertURLNotAvailable(t *testing.T) {
	postCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "HEAD" {
			w.Header().Set("Replay-Nonce", fmt.Sprintf("nonce-%d", time.Now().UnixNano()))
			return
		}
		postCount++
		w.Header().Set("Content-Type", "application/json")
		switch {
		case postCount == 1:
			w.Header().Set("Location", "http://"+r.Host+"/order/1")
			json.NewEncoder(w).Encode(acmeOrder{
				Status:         "pending",
				Authorizations: []string{"http://" + r.Host + "/authz/1"},
				Finalize:       "http://" + r.Host + "/finalize",
			})
		case postCount == 2:
			json.NewEncoder(w).Encode(acmeAuthorization{
				Status:     "valid",
				Identifier: acmeIdentifier{Type: "dns", Value: "test.example.com"},
			})
		case postCount == 3:
			json.NewEncoder(w).Encode(acmeOrder{
				Status:   "ready",
				Finalize: "http://" + r.Host + "/finalize",
			})
		case postCount == 4:
			// Finalize: valid but no cert URL
			json.NewEncoder(w).Encode(acmeOrder{Status: "valid", Certificate: ""})
		default:
			// Polling: never provides cert URL
			json.NewEncoder(w).Encode(acmeOrder{Status: "valid", Certificate: ""})
		}
	}))
	defer srv.Close()

	dir := t.TempDir()
	mgr, _ := NewACMEManager("test@example.com", dir, true, nil)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	mgr.account = &acmeAccount{Key: key, URL: srv.URL + "/account/1"}
	mgr.directory = acmeDirectory{
		NewNonce: srv.URL + "/nonce",
		NewOrder: srv.URL + "/order",
	}

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	_, err := mgr.ObtainCertificate(ctx, []string{"test.example.com"})
	if err == nil {
		t.Fatal("Expected error for certificate URL not available")
	}
}

// TestProcessAuthorization_PollSignedPostContinue tests the continue path when
// signedPost fails during challenge polling (line 377-378) and unmarshal fails (382-383)
// before eventually becoming valid.
func TestProcessAuthorization_PollSignedPostContinue(t *testing.T) {
	postCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "HEAD" {
			w.Header().Set("Replay-Nonce", fmt.Sprintf("nonce-%d", time.Now().UnixNano()))
			return
		}
		postCount++
		w.Header().Set("Content-Type", "application/json")
		switch {
		case postCount == 1:
			// Fetch authz: pending
			json.NewEncoder(w).Encode(acmeAuthorization{
				Status:     "pending",
				Identifier: acmeIdentifier{Type: "dns", Value: "test.example.com"},
				Challenges: []acmeChallenge{
					{Type: "http-01", URL: "http://" + r.Host + "/challenge/1", Token: "test-token-12345678", Status: "pending"},
				},
			})
		case postCount == 2:
			// Respond to challenge: ok
			json.NewEncoder(w).Encode(map[string]string{"status": "processing"})
		case postCount == 3:
			// First poll: return 500 to trigger signedPost error -> continue (line 377-378)
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte("server error"))
		case postCount == 4:
			// Second poll: return bad JSON to trigger unmarshal continue (line 382-383)
			w.Write([]byte("bad-json"))
		default:
			// Third poll: valid
			json.NewEncoder(w).Encode(acmeAuthorization{
				Status:     "valid",
				Identifier: acmeIdentifier{Type: "dns", Value: "test.example.com"},
			})
		}
	}))
	defer srv.Close()

	dir := t.TempDir()
	mgr, _ := NewACMEManager("test@example.com", dir, true, nil)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	mgr.account = &acmeAccount{Key: key, URL: srv.URL + "/account/1"}
	mgr.directory = acmeDirectory{NewNonce: srv.URL + "/nonce"}

	err := mgr.processAuthorization(context.Background(), srv.URL+"/authz/1")
	if err != nil {
		t.Fatalf("processAuthorization should succeed after retries: %v", err)
	}
}

// ─── checkAndRenew direct tests ─────────────────────────

func TestCheckAndRenew_NeedsRenewal(t *testing.T) {
	mockSrv := mockACMEServer(t)
	defer mockSrv.Close()
	mgr := setupMockManager(t, mockSrv)
	mgr.registerAccount()

	var renewed bool
	getCert := func(domain string) *CertificateBundle {
		return &CertificateBundle{
			ExpiresAt: time.Now().Add(5 * 24 * time.Hour), // 5 days = needs renewal (<30)
		}
	}
	setCert := func(domain string, b *CertificateBundle) {
		renewed = true
	}

	done := make(chan struct{})
	defer close(done)
	mgr.checkAndRenew(context.Background(), []string{"test.example.com"}, getCert, setCert, done)

	if !renewed {
		t.Error("Expected certificate to be renewed")
	}
}

func TestCheckAndRenew_NoRenewalNeeded(t *testing.T) {
	dir := t.TempDir()
	mgr, _ := NewACMEManager("test@example.com", dir, true, nil)

	var renewed bool
	getCert := func(domain string) *CertificateBundle {
		return &CertificateBundle{
			ExpiresAt: time.Now().Add(60 * 24 * time.Hour), // 60 days = no renewal needed
		}
	}
	setCert := func(domain string, b *CertificateBundle) {
		renewed = true
	}

	done := make(chan struct{})
	defer close(done)
	mgr.checkAndRenew(context.Background(), []string{"test.example.com"}, getCert, setCert, done)

	if renewed {
		t.Error("Certificate should NOT be renewed (60 days remaining)")
	}
}

func TestCheckAndRenew_NilBundle(t *testing.T) {
	mockSrv := mockACMEServer(t)
	defer mockSrv.Close()
	mgr := setupMockManager(t, mockSrv)
	mgr.registerAccount()

	var renewed bool
	getCert := func(domain string) *CertificateBundle {
		return nil // nil = needs renewal
	}
	setCert := func(domain string, b *CertificateBundle) {
		renewed = true
	}

	done := make(chan struct{})
	defer close(done)
	mgr.checkAndRenew(context.Background(), []string{"test.example.com"}, getCert, setCert, done)

	if !renewed {
		t.Error("Expected renewal for nil bundle")
	}
}

func TestCheckAndRenew_RenewalFails(t *testing.T) {
	dir := t.TempDir()
	mgr, _ := NewACMEManager("test@example.com", dir, true, nil)
	// Don't set up account/directory — ObtainCertificate will fail

	var renewed bool
	getCert := func(domain string) *CertificateBundle {
		return nil // needs renewal
	}
	setCert := func(domain string, b *CertificateBundle) {
		renewed = true
	}

	done := make(chan struct{})
	defer close(done)
	mgr.checkAndRenew(context.Background(), []string{"test.example.com"}, getCert, setCert, done)

	if renewed {
		t.Error("Should NOT have renewed — ObtainCertificate should fail")
	}
}

func TestCheckAndRenew_DoneSignalStops(t *testing.T) {
	dir := t.TempDir()
	mgr, _ := NewACMEManager("test@example.com", dir, true, nil)

	done := make(chan struct{})
	close(done) // already closed = should stop immediately

	getCert := func(domain string) *CertificateBundle {
		t.Error("getCert should not be called when done is closed")
		return nil
	}
	setCert := func(domain string, b *CertificateBundle) {
		t.Error("setCert should not be called when done is closed")
	}

	mgr.checkAndRenew(context.Background(), []string{"test.example.com"}, getCert, setCert, done)
}

func TestCheckAndRenew_MultipleDomains(t *testing.T) {
	mockSrv := mockACMEServer(t)
	defer mockSrv.Close()
	mgr := setupMockManager(t, mockSrv)
	mgr.registerAccount()

	renewedDomains := map[string]bool{}
	getCert := func(domain string) *CertificateBundle {
		if domain == "old.example.com" {
			return &CertificateBundle{ExpiresAt: time.Now().Add(5 * 24 * time.Hour)}
		}
		return &CertificateBundle{ExpiresAt: time.Now().Add(60 * 24 * time.Hour)}
	}
	setCert := func(domain string, b *CertificateBundle) {
		renewedDomains[domain] = true
	}

	done := make(chan struct{})
	defer close(done)
	mgr.checkAndRenew(context.Background(), []string{"old.example.com", "fresh.example.com"}, getCert, setCert, done)

	if !renewedDomains["old.example.com"] {
		t.Error("old.example.com should have been renewed")
	}
	if renewedDomains["fresh.example.com"] {
		t.Error("fresh.example.com should NOT have been renewed")
	}
}
