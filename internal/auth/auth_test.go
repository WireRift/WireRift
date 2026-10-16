package auth

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"
)

func TestNewManager(t *testing.T) {
	m := NewManager()
	if m == nil {
		t.Fatal("NewManager returned nil")
	}
}

func TestTokenValidation(t *testing.T) {
	m := NewManager()

	token, account, err := m.ValidateToken(m.devToken.Secret)
	if err != nil {
		t.Fatalf("ValidateToken: %v", err)
	}
	if token == nil {
		t.Fatal("Token should not be nil")
	}
	if account == nil {
		t.Fatal("Account should not be nil")
	}
	if account.ID != "dev_account" {
		t.Errorf("Account ID = %q, want %q", account.ID, "dev_account")
	}
}

func TestInvalidToken(t *testing.T) {
	m := NewManager()

	_, _, err := m.ValidateToken("invalid_token")
	if err != ErrInvalidToken {
		t.Errorf("Error = %v, want %v", err, ErrInvalidToken)
	}
}

func TestTokenIsExpired(t *testing.T) {
	// Not expired
	token := &Token{
		ID:        "test",
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(1 * time.Hour),
	}
	if token.IsExpired() {
		t.Error("Token should not be expired")
	}

	// Expired
	expiredToken := &Token{
		ID:        "test",
		CreatedAt: time.Now().Add(-2 * time.Hour),
		ExpiresAt: time.Now().Add(-1 * time.Hour),
	}
	if !expiredToken.IsExpired() {
		t.Error("Token should be expired")
	}

	// Never expires (zero time)
	neverExpires := &Token{
		ID:        "test",
		CreatedAt: time.Now(),
		ExpiresAt: time.Time{},
	}
	if neverExpires.IsExpired() {
		t.Error("Token with zero ExpiresAt should not expire")
	}
}

func TestMiddleware(t *testing.T) {
	m := NewManager()

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	middleware := m.Middleware()
	protected := middleware(handler)

	// Test without auth
	req := httptest.NewRequest("GET", "/", nil)
	rec := httptest.NewRecorder()
	protected.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("Code = %d, want %d", rec.Code, http.StatusUnauthorized)
	}

	// Test with valid token
	req = httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer "+m.devToken.Secret)
	rec = httptest.NewRecorder()
	protected.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("Code = %d, want %d", rec.Code, http.StatusOK)
	}
}

func TestBasicAuth(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	middleware := BasicAuth("admin", "secret")
	protected := middleware(handler)

	// Test without auth
	req := httptest.NewRequest("GET", "/", nil)
	rec := httptest.NewRecorder()
	protected.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("Code = %d, want %d", rec.Code, http.StatusUnauthorized)
	}

	// Test with valid credentials
	req = httptest.NewRequest("GET", "/", nil)
	auth := base64.StdEncoding.EncodeToString([]byte("admin:secret"))
	req.Header.Set("Authorization", "Basic "+auth)
	rec = httptest.NewRecorder()
	protected.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("Code = %d, want %d", rec.Code, http.StatusOK)
	}

	// Test with invalid credentials
	req = httptest.NewRequest("GET", "/", nil)
	auth = base64.StdEncoding.EncodeToString([]byte("admin:wrong"))
	req.Header.Set("Authorization", "Basic "+auth)
	rec = httptest.NewRecorder()
	protected.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("Code = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

// TestDevToken tests the DevToken method
func TestDevToken(t *testing.T) {
	m := NewManager()

	// DevToken should return the development token secret
	token := m.DevToken()
	if token == "" {
		t.Error("DevToken should not be empty")
	}

	// DevToken should start with "dev_" prefix
	if len(token) < 4 || token[:4] != "dev_" {
		t.Errorf("DevToken should start with 'dev_', got: %s", token)
	}
}

// TestMiddlewareInvalidAuthHeader tests middleware with invalid auth headers
func TestMiddlewareInvalidAuthHeader(t *testing.T) {
	m := NewManager()

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	middleware := m.Middleware()
	protected := middleware(handler)

	// Test with Bearer prefix but empty token
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer ")
	rec := httptest.NewRecorder()
	protected.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("Code = %d, want %d", rec.Code, http.StatusUnauthorized)
	}

	// Test with non-Bearer prefix
	req = httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Basic dXNlcjpwYXNz")
	rec = httptest.NewRecorder()
	protected.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("Code = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

// TestValidateTokenExpiredInStore tests validation of a token found in the store that is expired
func TestValidateTokenExpiredInStore(t *testing.T) {
	m := NewManager()

	// Create account manually
	account := &Account{
		ID:     "acc_test123",
		Email:  "test@example.com",
		Name:   "Test User",
		Active: true,
	}
	m.accounts.Store(account.ID, account)

	// Manually store an expired token
	expiredToken := &Token{
		ID:        "tk_expired",
		AccountID: account.ID,
		Name:      "Expired Token",
		CreatedAt: time.Now().Add(-2 * time.Hour),
		ExpiresAt: time.Now().Add(-1 * time.Hour),
		Secret:    "sk_expired_secret_12345",
	}
	m.tokens.Store(expiredToken.ID, expiredToken)

	// Validate should return ErrInvalidToken because the token is expired
	_, _, err := m.ValidateToken(expiredToken.Secret)
	if err != ErrInvalidToken {
		t.Errorf("Error = %v, want %v", err, ErrInvalidToken)
	}
}

// TestValidateTokenAccountNotFound tests validation of a token whose account doesn't exist
func TestValidateTokenAccountNotFound(t *testing.T) {
	m := NewManager()

	// Store a token with an account ID that doesn't exist
	orphanToken := &Token{
		ID:        "tk_orphan",
		AccountID: "nonexistent_account",
		Name:      "Orphan Token",
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(1 * time.Hour),
		Secret:    "sk_orphan_secret_12345",
	}
	m.tokens.Store(orphanToken.ID, orphanToken)

	// Validate should return ErrInvalidToken because the account is not found
	_, _, err := m.ValidateToken(orphanToken.Secret)
	if err != ErrInvalidToken {
		t.Errorf("Error = %v, want %v", err, ErrInvalidToken)
	}
}

// TestDevTokenNil tests DevToken when devToken is nil
func TestDevTokenNil(t *testing.T) {
	m := &Manager{} // Create manager without calling NewManager, so devToken is nil

	token := m.DevToken()
	if token != "" {
		t.Errorf("DevToken() = %q, want empty string", token)
	}
}

// TestBasicAuthNonBasicPrefix tests BasicAuth with a non-Basic authorization prefix
func TestBasicAuthNonBasicPrefix(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	middleware := BasicAuth("admin", "secret")
	protected := middleware(handler)

	// Test with Bearer prefix instead of Basic
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer sometoken")
	rec := httptest.NewRecorder()
	protected.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("Code = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

// TestBasicAuthInvalidHeader tests BasicAuth with various invalid headers
func TestBasicAuthInvalidHeader(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	middleware := BasicAuth("admin", "secret")
	protected := middleware(handler)

	// Test with Basic prefix but empty credentials
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Basic ")
	rec := httptest.NewRecorder()
	protected.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("Code = %d, want %d", rec.Code, http.StatusUnauthorized)
	}

	// Test with Basic prefix but invalid base64
	req = httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Basic !!!invalid!!!")
	rec = httptest.NewRecorder()
	protected.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("Code = %d, want %d", rec.Code, http.StatusUnauthorized)
	}

	// Test with Basic prefix but missing colon in decoded string
	req = httptest.NewRequest("GET", "/", nil)
	auth := base64.StdEncoding.EncodeToString([]byte("adminonly"))
	req.Header.Set("Authorization", "Basic "+auth)
	rec = httptest.NewRecorder()
	protected.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("Code = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

// TestNewManagerWithEnvToken tests NewManager when WIRERIFT_TOKEN env var is set.
func TestNewManagerWithEnvToken(t *testing.T) {
	// Set env var
	os.Setenv("WIRERIFT_TOKEN", "env_token_12345")
	defer os.Unsetenv("WIRERIFT_TOKEN")

	m := NewManager()

	// DevToken should use the env var value
	token := m.DevToken()
	if token != "env_token_12345" {
		t.Errorf("DevToken = %q, want env_token_12345", token)
	}
}

// TestNewManagerWithExplicitToken tests that explicit token takes precedence over env.
func TestNewManagerWithExplicitToken(t *testing.T) {
	// Set env var
	os.Setenv("WIRERIFT_TOKEN", "env_token_12345")
	defer os.Unsetenv("WIRERIFT_TOKEN")

	// Explicit token should take precedence
	m := NewManager("explicit_token_67890")

	token := m.DevToken()
	if token != "explicit_token_67890" {
		t.Errorf("DevToken = %q, want explicit_token_67890", token)
	}
}

// TestValidateTokenNotFound tests validation when token is not found.
func TestValidateTokenNotFound(t *testing.T) {
	m := NewManager()

	// Try to validate a token that doesn't exist
	_, _, err := m.ValidateToken("nonexistent_token_12345")
	if err != ErrInvalidToken {
		t.Errorf("Error = %v, want %v", err, ErrInvalidToken)
	}
}

// TestValidateTokenExpiredInStore tests validation of an expired token in store.
func TestValidateTokenExpiredInStore2(t *testing.T) {
	m := NewManager()

	// Create account manually
	account := &Account{
		ID:     "acc_test123",
		Email:  "test@example.com",
		Name:   "Test User",
		Active: true,
	}
	m.accounts.Store(account.ID, account)

	// Manually store an expired token
	expiredToken := &Token{
		ID:        "tk_expired",
		AccountID: account.ID,
		Name:      "Expired Token",
		CreatedAt: time.Now().Add(-2 * time.Hour),
		ExpiresAt: time.Now().Add(-1 * time.Hour),
		Secret:    "sk_expired_secret_12345",
	}
	m.tokens.Store(expiredToken.ID, expiredToken)

	// Validate should return ErrInvalidToken because the token is expired
	_, _, err := m.ValidateToken(expiredToken.Secret)
	if err != ErrInvalidToken {
		t.Errorf("Error = %v, want %v", err, ErrInvalidToken)
	}
}

// TestValidateTokenValidInStore tests validation of a valid token in store.
func TestValidateTokenValidInStore(t *testing.T) {
	m := NewManager()

	// Create account manually
	account := &Account{
		ID:     "acc_valid",
		Email:  "valid@example.com",
		Name:   "Valid User",
		Active: true,
	}
	m.accounts.Store(account.ID, account)

	// Manually store a valid token (not expired)
	validToken := &Token{
		ID:        "tk_valid",
		AccountID: account.ID,
		Name:      "Valid Token",
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(1 * time.Hour),
		Secret:    "sk_valid_secret_12345",
	}
	m.tokens.Store(validToken.ID, validToken)

	// Validate should succeed
	token, acc, err := m.ValidateToken(validToken.Secret)
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
	if token == nil {
		t.Fatal("Token should not be nil")
	}
	if acc == nil {
		t.Fatal("Account should not be nil")
	}
	if token.ID != "tk_valid" {
		t.Errorf("Token ID = %q, want tk_valid", token.ID)
	}
}

// TestValidateTokenAccountNotFound tests validation when token's account doesn't exist.
func TestValidateTokenAccountNotFound2(t *testing.T) {
	m := NewManager()

	// Store a token with an account ID that doesn't exist
	orphanToken := &Token{
		ID:        "tk_orphan2",
		AccountID: "nonexistent_account_123",
		Name:      "Orphan Token",
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(1 * time.Hour),
		Secret:    "sk_orphan_secret_12345",
	}
	m.tokens.Store(orphanToken.ID, orphanToken)

	// Validate should return ErrInvalidToken because the account is not found
	_, _, err := m.ValidateToken(orphanToken.Secret)
	if err != ErrInvalidToken {
		t.Errorf("Error = %v, want %v", err, ErrInvalidToken)
	}
}
