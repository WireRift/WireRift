package dashboard

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/wirerift/wirerift/internal/auth"
)

const (
	loginSessionPrefix = "wrs_"
	loginSessionTTL    = 12 * time.Hour
	maxLoginSessions   = 1000
)

type loginSession struct {
	accountID string
	expires   time.Time
}

// loginSessions are the dashboard sessions opened with a username and
// password. They live in memory only, so a server restart signs everyone out.
type loginSessions struct {
	mu sync.Mutex
	m  map[string]loginSession
}

func (s *loginSessions) create(accountID string) (string, time.Time, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", time.Time{}, err
	}
	secret := loginSessionPrefix + base64.RawURLEncoding.EncodeToString(b)
	exp := time.Now().Add(loginSessionTTL)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.m == nil {
		s.m = make(map[string]loginSession)
	}
	now := time.Now()
	for k, v := range s.m {
		if now.After(v.expires) {
			delete(s.m, k)
		}
	}
	for len(s.m) >= maxLoginSessions { // drop the one closest to expiry
		var oldest string
		for k, v := range s.m {
			if oldest == "" || v.expires.Before(s.m[oldest].expires) {
				oldest = k
			}
		}
		delete(s.m, oldest)
	}
	s.m[secret] = loginSession{accountID: accountID, expires: exp}
	return secret, exp, nil
}

func (s *loginSessions) lookup(secret string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.m[secret]
	if !ok || time.Now().After(v.expires) {
		delete(s.m, secret)
		return "", false
	}
	return v.accountID, true
}

func (s *loginSessions) delete(secret string) {
	s.mu.Lock()
	delete(s.m, secret)
	s.mu.Unlock()
}

func (s *loginSessions) deleteAccount(accountID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, v := range s.m {
		if v.accountID == accountID {
			delete(s.m, k)
		}
	}
}

// handleLogin handles POST /api/login: a username (the account name) and
// password give a dashboard session token used like any API token. Failures
// count against the same per-IP lockout as wrong tokens.
func (d *Dashboard) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		d.jsonError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	ip := remoteIP(r)
	if d.guard.locked(ip) {
		w.Header().Set("Retry-After", "300")
		d.jsonError(w, "Too many failed attempts", http.StatusTooManyRequests)
		return
	}
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil {
		d.jsonError(w, "Invalid request", http.StatusBadRequest)
		return
	}
	acct, err := d.authManager.VerifyPassword(req.Username, req.Password)
	if err != nil {
		d.guard.fail(ip)
		d.jsonError(w, "Invalid username or password", http.StatusUnauthorized)
		return
	}
	secret, exp, err := d.sessions.create(acct.ID)
	if err != nil {
		d.jsonError(w, "Cannot create a session", http.StatusInternalServerError)
		return
	}
	d.guard.reset(ip)
	d.server.RecordAdminEvent(acct.ID, "dashboard login with a password")
	w.Header().Set("Cache-Control", "no-store")
	d.jsonResponse(w, map[string]any{"token": secret, "expires_at": exp})
}

// handleLogout handles POST /api/logout: ends the session named by the Bearer
// token (other kinds of token are unaffected).
func (d *Dashboard) handleLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		d.jsonError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if tok, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer "); ok && strings.HasPrefix(tok, loginSessionPrefix) {
		d.sessions.delete(tok)
	}
	d.jsonResponse(w, map[string]string{"status": "ok"})
}

// sessionAccount resolves a session token to its account.
func (d *Dashboard) sessionAccount(secret string) (*auth.Account, bool) {
	id, ok := d.sessions.lookup(secret)
	if !ok {
		return nil, false
	}
	acct, ok := d.authManager.AccountByID(id)
	if !ok || !acct.Active {
		d.sessions.delete(secret)
		return nil, false
	}
	return acct, true
}

// handleAdminPassword handles POST /api/admin/accounts/{name}/password with
// {"password": "..."}: sets the dashboard password of an existing account and
// ends its open password sessions.
func (d *Dashboard) handleAdminPassword(w http.ResponseWriter, r *http.Request) {
	if !d.tokensEnabled(w) {
		return
	}
	name, ok := strings.CutSuffix(strings.TrimPrefix(r.URL.Path, "/api/admin/accounts/"), "/password")
	if !ok || name == "" || strings.Contains(name, "/") {
		d.jsonError(w, "Not found", http.StatusNotFound)
		return
	}
	if r.Method != http.MethodPost {
		d.jsonError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Password string `json:"password"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil {
		d.jsonError(w, "Invalid request", http.StatusBadRequest)
		return
	}
	d.tokenMu.Lock()
	f, err := auth.LoadTokenFile(d.tokenFile)
	if err == nil {
		err = f.SetPassword(name, req.Password)
		if err == nil {
			err = f.Save(d.tokenFile)
		}
	}
	d.tokenMu.Unlock()
	switch {
	case errors.Is(err, auth.ErrWeakPassword):
		d.jsonError(w, err.Error(), http.StatusBadRequest)
		return
	case errors.Is(err, auth.ErrBadAccount):
		d.jsonError(w, "Account not found: create a token for it first", http.StatusNotFound)
		return
	case err != nil:
		d.jsonError(w, "Cannot update the token file", http.StatusInternalServerError)
		return
	}
	d.sessions.deleteAccount("acct_" + strings.ToLower(name))
	d.afterTokenChange("dashboard password set for account "+name, r)
	d.jsonResponse(w, map[string]string{"status": "ok"})
}
