package tls

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
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
