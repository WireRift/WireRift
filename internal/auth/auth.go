package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// Errors returned by auth operations.
var (
	ErrInvalidToken = errors.New("invalid token")
	ErrUnauthorized = errors.New("unauthorized")
)

// Token represents an authentication token.
type Token struct {
	ID        string
	AccountID string
	Name      string
	CreatedAt time.Time
	ExpiresAt time.Time
	Secret    string
}

// IsExpired returns true if the token has expired.
func (t *Token) IsExpired() bool {
	return !t.ExpiresAt.IsZero() && time.Now().After(t.ExpiresAt)
}

// Account represents a user account.
type Account struct {
	ID         string
	Email      string
	Name       string
	Active     bool
	CreatedAt  time.Time
	MaxTunnels int
	RateLimit  int
}

// Manager manages authentication.
type Manager struct {
	tokens   sync.Map
	accounts sync.Map
	devToken *Token
	mu       sync.RWMutex
}

// NewManager creates a new auth manager.
// Token resolution order: explicit token > WIRERIFT_TOKEN env > random.
func NewManager(token ...string) *Manager {
	m := &Manager{}

	// Resolve token: explicit arg > env var > random
	var secret string
	if len(token) > 0 && token[0] != "" {
		secret = token[0]
	} else if env := os.Getenv("WIRERIFT_TOKEN"); env != "" {
		secret = env
	} else {
		secret = "dev_" + generateRandomString(32)
	}
	m.devToken = &Token{
		ID:        "dev_token",
		AccountID: "dev_account",
		Name:      "Development Token",
		CreatedAt: time.Now(),
		ExpiresAt: time.Time{},
		Secret:    secret,
	}
	m.tokens.Store(m.devToken.ID, m.devToken)

	// Create development account
	m.accounts.Store("dev_account", &Account{
		ID:         "dev_account",
		Email:      "dev@localhost",
		Name:       "Development Account",
		Active:     true,
		CreatedAt:  time.Now(),
		MaxTunnels: 100,
		RateLimit:  1000,
	})

	return m
}

// ValidateToken validates a token and returns the associated account.
func (m *Manager) ValidateToken(tokenSecret string) (*Token, *Account, error) {
	// Check development token
	if m.devToken != nil && subtle.ConstantTimeCompare([]byte(m.devToken.Secret), []byte(tokenSecret)) == 1 {
		account, _ := m.accounts.Load(m.devToken.AccountID)
		return m.devToken, account.(*Account), nil
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	var foundToken *Token
	var foundAccount *Account

	m.tokens.Range(func(key, value any) bool {
		t := value.(*Token)
		if subtle.ConstantTimeCompare([]byte(t.Secret), []byte(tokenSecret)) == 1 {
			if t.IsExpired() {
				return false
			}
			account, ok := m.accounts.Load(t.AccountID)
			if !ok {
				return false
			}
			foundToken = t
			foundAccount = account.(*Account)
			return false
		}
		return true
	})

	if foundToken == nil {
		return nil, nil, ErrInvalidToken
	}

	return foundToken, foundAccount, nil
}

// CreateToken creates a new token.
func (m *Manager) CreateToken(accountID, name string, expiresIn time.Duration) (*Token, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	account, ok := m.accounts.Load(accountID)
	if !ok || !account.(*Account).Active {
		return nil, ErrUnauthorized
	}

	token := &Token{
		ID:        "tk_" + generateRandomString(16),
		AccountID: accountID,
		Name:      name,
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(expiresIn),
		Secret:    "sk_" + generateRandomString(32),
	}

	m.tokens.Store(token.ID, token)
	return token, nil
}

// DevToken returns the development token secret for testing.
func (m *Manager) DevToken() string {
	if m.devToken != nil {
		return m.devToken.Secret
	}
	return ""
}

// RevokeToken revokes a token.
func (m *Manager) RevokeToken(tokenID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.tokens.Delete(tokenID)
	return nil
}

// CreateAccount creates a new account.
func (m *Manager) CreateAccount(email, name string) (*Account, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	account := &Account{
		ID:         "acc_" + generateRandomString(16),
		Email:      email,
		Name:       name,
		Active:     true,
		CreatedAt:  time.Now(),
		MaxTunnels: 10,
		RateLimit:  100,
	}

	m.accounts.Store(account.ID, account)
	return account, nil
}

// Middleware returns an HTTP middleware for token authentication.
func (m *Manager) Middleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			auth := r.Header.Get("Authorization")
			if auth == "" {
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}

			parts := strings.SplitN(auth, " ", 2)
			if len(parts) != 2 || parts[0] != "Bearer" {
				http.Error(w, "Invalid authorization header", http.StatusUnauthorized)
				return
			}

			_, _, err := m.ValidateToken(parts[1])
			if err != nil {
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// BasicAuth middleware checks for basic auth credentials.
func BasicAuth(username, password string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			auth := r.Header.Get("Authorization")
			if auth == "" {
				w.Header().Set("WWW-Authenticate", `Basic realm="WireRift"`)
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}

			parts := strings.SplitN(auth, " ", 2)
			if len(parts) != 2 || parts[0] != "Basic" {
				http.Error(w, "Invalid authorization", http.StatusUnauthorized)
				return
			}

			decoded, err := base64.StdEncoding.DecodeString(parts[1])
			if err != nil {
				http.Error(w, "Invalid encoding", http.StatusUnauthorized)
				return
			}

			creds := strings.SplitN(string(decoded), ":", 2)
			if len(creds) != 2 {
				http.Error(w, "Invalid credentials", http.StatusUnauthorized)
				return
			}

			// Use constant-time comparison to prevent timing attacks
			userMatch := subtle.ConstantTimeCompare([]byte(creds[0]), []byte(username))
			passMatch := subtle.ConstantTimeCompare([]byte(creds[1]), []byte(password))
			if userMatch&passMatch != 1 {
				w.Header().Set("WWW-Authenticate", `Basic realm="WireRift"`)
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// generateRandomString generates a cryptographically random string of the given length.
// Uses rejection sampling to avoid modulo bias.
func generateRandomString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	const maxByte = byte(256 - (256 % len(charset))) // 256 - (256%62) = 252
	result := make([]byte, length)
	buf := make([]byte, length+(length/4)) // extra bytes for rejected samples
	filled := 0
	for filled < length {
		rand.Read(buf)
		for _, b := range buf {
			if b < maxByte {
				result[filled] = charset[b%byte(len(charset))]
				filled++
				if filled == length {
					break
				}
			}
		}
	}
	return string(result)
}
