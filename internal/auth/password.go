package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// Passwords are stored as "pbkdf2-sha256$<iterations>$<salt>$<hash>" (base64).
// PBKDF2 is implemented here because the project uses the standard library
// only and the Go version it supports predates crypto/pbkdf2.
const (
	pbkdf2Iterations = 210000
	// MinPasswordLength is the shortest dashboard password accepted.
	MinPasswordLength = 10
	maxPasswordLength = 256
)

// ErrWeakPassword is returned by HashPassword for a password that is too short or too long.
var ErrWeakPassword = fmt.Errorf("the password must be %d to %d characters", MinPasswordLength, maxPasswordLength)

func pbkdf2(password, salt []byte, iter int) []byte {
	prf := hmac.New(sha256.New, password)
	var block [4]byte
	binary.BigEndian.PutUint32(block[:], 1)
	prf.Write(salt)
	prf.Write(block[:])
	u := prf.Sum(nil)
	out := append([]byte(nil), u...)
	for i := 1; i < iter; i++ {
		prf.Reset()
		prf.Write(u)
		u = prf.Sum(u[:0])
		for j := range out {
			out[j] ^= u[j]
		}
	}
	return out
}

// HashPassword returns the stored form of password.
func HashPassword(password string) (string, error) {
	if len(password) < MinPasswordLength || len(password) > maxPasswordLength {
		return "", ErrWeakPassword
	}
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	h := pbkdf2([]byte(password), salt, pbkdf2Iterations)
	enc := base64.RawStdEncoding.EncodeToString
	return fmt.Sprintf("pbkdf2-sha256$%d$%s$%s", pbkdf2Iterations, enc(salt), enc(h)), nil
}

// dummyHash makes a login for an unknown user cost as much as a real one.
var dummyHash, _ = HashPassword("not-a-real-password")

// CheckPassword reports whether password matches the stored hash.
func CheckPassword(stored, password string) bool {
	parts := strings.Split(stored, "$")
	if len(parts) != 4 || parts[0] != "pbkdf2-sha256" || len(password) > maxPasswordLength {
		return false
	}
	iter, err := strconv.Atoi(parts[1])
	if err != nil || iter < 1 || iter > 5_000_000 {
		return false
	}
	dec := base64.RawStdEncoding.DecodeString
	salt, err1 := dec(parts[2])
	want, err2 := dec(parts[3])
	if err1 != nil || err2 != nil || len(want) == 0 {
		return false
	}
	return subtle.ConstantTimeCompare(pbkdf2([]byte(password), salt, iter), want) == 1
}

// ErrBadLogin is returned for any failed username/password login.
var ErrBadLogin = errors.New("invalid username or password")

// VerifyPassword checks a dashboard login. The username is the account name
// (case-insensitive). Unknown, inactive and passwordless accounts all fail the
// same way and cost the same time.
func (m *Manager) VerifyPassword(username, password string) (*Account, error) {
	id := "acct_" + strings.ToLower(strings.TrimSpace(username))
	m.mu.RLock()
	hash := m.passwords[id]
	m.mu.RUnlock()
	acct, ok := m.AccountByID(id)
	if hash == "" {
		CheckPassword(dummyHash, password)
		return nil, ErrBadLogin
	}
	if !CheckPassword(hash, password) || !ok || !acct.Active {
		return nil, ErrBadLogin
	}
	return acct, nil
}

// AccountByID returns a copy of the account.
func (m *Manager) AccountByID(id string) (*Account, bool) {
	v, ok := m.accounts.Load(id)
	if !ok {
		return nil, false
	}
	a := *v.(*Account)
	return &a, true
}
