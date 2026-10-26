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
	Secret    string // plaintext secret: only the bootstrap token and in-memory tokens
	Hash      string // SHA-256 of the secret, for tokens loaded from the token file
	Revoked   bool
}

// IsExpired returns true if the token has expired.
func (t *Token) IsExpired() bool {
	return !t.ExpiresAt.IsZero() && time.Now().After(t.ExpiresAt)
}

// Account represents a user account.
type Account struct {
	ID          string
	Email       string
	Name        string
	Active      bool
	CreatedAt   time.Time
	MaxTunnels  int
	MaxSessions int // 0 = unlimited
	RateLimit   int
}

// Manager manages authentication.
type Manager struct {
	tokens   sync.Map
	accounts sync.Map
	devToken *Token
	mu       sync.RWMutex

	byHash         map[string]*Token // tokens from the token file, by secret digest
	loadedAccounts []string          // account IDs loaded from the token file
}

// DevAccountID is the account of the bootstrap token (-token, WIRERIFT_TOKEN or
// the generated one). It is unlimited and may see every tunnel.
const DevAccountID = "dev_account"

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
		account, ok := m.accounts.Load(m.devToken.AccountID)
		if !ok {
			return nil, nil, ErrInvalidToken
		}
		if !account.(*Account).Active {
			return nil, nil, ErrInvalidToken
		}
		return m.devToken, account.(*Account), nil
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	// Tokens from the token file: direct lookup by digest.
	if len(m.byHash) > 0 {
		if t, ok := m.byHash[HashSecret(tokenSecret)]; ok {
			return m.checkStored(t)
		}
	}

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
			if !account.(*Account).Active {
				return false // disabled accounts cannot authenticate
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

// checkStored validates a token found by digest. The caller holds m.mu.
func (m *Manager) checkStored(t *Token) (*Token, *Account, error) {
	if t.Revoked || t.IsExpired() {
		return nil, nil, ErrInvalidToken
	}
	account, ok := m.accounts.Load(t.AccountID)
	if !ok || !account.(*Account).Active {
		return nil, nil, ErrInvalidToken
	}
	return t, account.(*Account), nil
}

// LoadTokenFile replaces the tokens and accounts that came from a token file
// with the contents of path (a missing file means none). The bootstrap token and
// its account are untouched. It returns how many tokens are now loaded; on an
// error nothing changes.
func (m *Manager) LoadTokenFile(path string) (int, error) {
	f, err := LoadTokenFile(path)
	if err != nil {
		return 0, err
	}
	m.ApplyTokenFile(f)
	return len(f.Tokens), nil
}

// ApplyTokenFile is LoadTokenFile for an already parsed file.
func (m *Manager) ApplyTokenFile(f *TokenFile) {
	accounts := make(map[string]*Account, len(f.Accounts))
	for _, a := range f.Accounts {
		if a.ID == DevAccountID {
			continue // the bootstrap account cannot be redefined from a file
		}
		accounts[a.ID] = &Account{
			ID: a.ID, Name: a.Name, Active: a.Active, CreatedAt: a.CreatedAt,
			MaxTunnels: a.MaxTunnels, MaxSessions: a.MaxSessions, RateLimit: a.RateLimit,
		}
	}
	byHash := make(map[string]*Token, len(f.Tokens))
	for _, ft := range f.Tokens {
		if _, ok := accounts[ft.AccountID]; !ok || ft.Hash == "" {
			continue
		}
		t := &Token{ID: ft.ID, AccountID: ft.AccountID, Name: ft.Name, CreatedAt: ft.CreatedAt, Hash: ft.Hash, Revoked: ft.Revoked}
		if ft.ExpiresAt != nil {
			t.ExpiresAt = *ft.ExpiresAt
		}
		byHash[ft.Hash] = t
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	for _, id := range m.loadedAccounts {
		m.accounts.Delete(id)
	}
	m.loadedAccounts = m.loadedAccounts[:0]
	for id, a := range accounts {
		m.accounts.Store(id, a)
		m.loadedAccounts = append(m.loadedAccounts, id)
	}
	m.byHash = byHash
}

// StillValid reports whether a token returned earlier by ValidateToken would
// still be accepted: it has not been revoked or removed from the token file, has
// not expired, and its account is still active. Sessions use it to notice that
// their token was withdrawn after they logged in.
func (m *Manager) StillValid(t *Token) bool {
	if t == nil {
		return true
	}
	if t == m.devToken {
		return m.accountActive(t.AccountID)
	}
	if t.Hash != "" {
		m.mu.RLock()
		cur, ok := m.byHash[t.Hash]
		m.mu.RUnlock()
		return ok && !cur.Revoked && !cur.IsExpired() && m.accountActive(cur.AccountID)
	}
	if _, ok := m.tokens.Load(t.ID); !ok {
		return false
	}
	return !t.IsExpired() && m.accountActive(t.AccountID)
}

func (m *Manager) accountActive(id string) bool {
	a, ok := m.accounts.Load(id)
	return ok && a.(*Account).Active
}

// DevToken returns the development token secret for testing.
func (m *Manager) DevToken() string {
	if m.devToken != nil {
		return m.devToken.Secret
	}
	return ""
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
