package auth

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

// TokenPrefix starts every token secret issued by CreateToken.
const TokenPrefix = "wr_"

// Errors returned by the token file.
var (
	ErrTokenNotFound = errors.New("token not found")
	ErrBadAccount    = errors.New("invalid account name: use letters, digits, '-' and '_' (max 40)")
)

var accountName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,39}$`)

// TokenFile is the persistent set of accounts and tokens. Only a SHA-256 digest
// of each token secret is stored: secrets are 40 random characters, so a salted
// slow hash adds nothing, and the digest allows a direct lookup.
type TokenFile struct {
	Accounts []FileAccount `json:"accounts"`
	Tokens   []FileToken   `json:"tokens"`
}

// FileAccount is an account as stored in the token file. A zero limit means
// "server default / unlimited".
type FileAccount struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Active      bool      `json:"active"`
	MaxTunnels  int       `json:"max_tunnels,omitempty"`
	MaxSessions int       `json:"max_sessions,omitempty"`
	RateLimit   int       `json:"rate_limit,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
}

// FileToken is a token as stored in the token file.
type FileToken struct {
	ID        string     `json:"id"`
	AccountID string     `json:"account_id"`
	Name      string     `json:"name"`
	Hash      string     `json:"hash"`
	CreatedAt time.Time  `json:"created_at"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
	Revoked   bool       `json:"revoked,omitempty"`
}

// CreateOptions describe a token to create. A negative limit leaves the
// account's existing limit alone (or unset for a new account).
type CreateOptions struct {
	Account     string // account name; created when it does not exist
	Name        string // label of the token
	MaxTunnels  int
	MaxSessions int
	RateLimit   int
	Expires     time.Duration // zero: never
}

// LoadTokenFile reads path. A missing file is an empty set.
func LoadTokenFile(path string) (*TokenFile, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return &TokenFile{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read token file: %w", err)
	}
	var f TokenFile
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("parse token file %s: %w", path, err)
	}
	return &f, nil
}

// Save writes the file atomically with mode 0600.
func (f *TokenFile) Save(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create token dir: %w", err)
	}
	data, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tokens-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name()) // no-op after a successful rename
	if err := tmp.Chmod(0o600); err != nil && !errors.Is(err, errors.ErrUnsupported) {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(append(data, '\n')); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// HashSecret returns the stored digest of a token secret.
func HashSecret(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(sum[:])
}

// CreateToken adds a token (and its account when new) and returns the secret,
// which is not stored and cannot be shown again.
func (f *TokenFile) CreateToken(o CreateOptions) (secret string, tok FileToken, err error) {
	if !accountName.MatchString(o.Account) {
		return "", FileToken{}, ErrBadAccount
	}
	id := "acct_" + strings.ToLower(o.Account)
	if id == "acct_dev_account" || id == DevAccountID {
		return "", FileToken{}, ErrBadAccount
	}

	var acct *FileAccount
	for i := range f.Accounts {
		if f.Accounts[i].ID == id {
			acct = &f.Accounts[i]
		}
	}
	if acct == nil {
		f.Accounts = append(f.Accounts, FileAccount{ID: id, Name: o.Account, Active: true, CreatedAt: time.Now().UTC()})
		acct = &f.Accounts[len(f.Accounts)-1]
	}
	if o.MaxTunnels >= 0 {
		acct.MaxTunnels = o.MaxTunnels
	}
	if o.MaxSessions >= 0 {
		acct.MaxSessions = o.MaxSessions
	}
	if o.RateLimit >= 0 {
		acct.RateLimit = o.RateLimit
	}

	secret = TokenPrefix + generateRandomString(40)
	tok = FileToken{
		ID:        "tok_" + strings.ToLower(generateRandomString(8)),
		AccountID: id,
		Name:      o.Name,
		Hash:      HashSecret(secret),
		CreatedAt: time.Now().UTC(),
	}
	if o.Expires > 0 {
		exp := tok.CreatedAt.Add(o.Expires)
		tok.ExpiresAt = &exp
	}
	f.Tokens = append(f.Tokens, tok)
	return secret, tok, nil
}

// Revoke marks the token revoked. Revoking twice is not an error.
func (f *TokenFile) Revoke(id string) error {
	for i := range f.Tokens {
		if f.Tokens[i].ID == id {
			f.Tokens[i].Revoked = true
			return nil
		}
	}
	return fmt.Errorf("%w: %s", ErrTokenNotFound, id)
}

// Sorted returns the tokens ordered by creation time.
func (f *TokenFile) Sorted() []FileToken {
	out := append([]FileToken(nil), f.Tokens...)
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	return out
}

// Account returns the account with the given ID.
func (f *TokenFile) Account(id string) (FileAccount, bool) {
	for _, a := range f.Accounts {
		if a.ID == id {
			return a, true
		}
	}
	return FileAccount{}, false
}
