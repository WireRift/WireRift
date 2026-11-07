package dashboard

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/wirerift/wirerift/internal/auth"
)

// tokenRow is one token as the Admin tab shows it. The secret is never part of
// it: only a digest is stored.
type tokenRow struct {
	ID          string     `json:"id"`
	Account     string     `json:"account"`
	Name        string     `json:"name"`
	Admin       bool       `json:"admin"`
	MaxTunnels  int        `json:"max_tunnels"`
	MaxSessions int        `json:"max_sessions"`
	RateLimit   int        `json:"rate_limit"`
	CreatedAt   time.Time  `json:"created_at"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
	Status      string     `json:"status"` // active, expired, revoked, account disabled
}

// createTokenRequest is the body of POST /api/admin/tokens. A limit left out
// keeps the account's current limit (0 on a new account: the server default).
type createTokenRequest struct {
	Account     string `json:"account"`
	Name        string `json:"name"`
	MaxTunnels  *int   `json:"max_tunnels"`
	MaxSessions *int   `json:"max_sessions"`
	RateLimit   *int   `json:"rate_limit"`
	Admin       *bool  `json:"admin"`
	Expires     string `json:"expires"` // "12h", "30d"; empty: never
}

func orKeep(v *int) int {
	if v == nil {
		return -1
	}
	return *v
}

func (d *Dashboard) tokensEnabled(w http.ResponseWriter) bool {
	if d.tokenFile == "" {
		d.jsonError(w, "Token management needs a token file (start the server with -tokens or a cert directory)", http.StatusNotImplemented)
		return false
	}
	return true
}

// admin returns the signed-in account's ID for the activity log.
func adminID(r *http.Request) string {
	if acct, _ := r.Context().Value(whoKey{}).(*auth.Account); acct != nil {
		return acct.ID
	}
	return "?"
}

// handleAdminTokens lists the tokens (GET) or creates one (POST).
func (d *Dashboard) handleAdminTokens(w http.ResponseWriter, r *http.Request) {
	if !d.tokensEnabled(w) {
		return
	}
	switch r.Method {
	case http.MethodGet:
		d.listTokens(w)
	case http.MethodPost:
		d.createToken(w, r)
	default:
		d.jsonError(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (d *Dashboard) listTokens(w http.ResponseWriter) {
	d.tokenMu.Lock()
	f, err := auth.LoadTokenFile(d.tokenFile)
	d.tokenMu.Unlock()
	if err != nil {
		d.jsonError(w, "Cannot read the token file", http.StatusInternalServerError)
		return
	}
	rows := make([]tokenRow, 0, len(f.Tokens))
	for _, t := range f.Sorted() {
		a, _ := f.Account(t.AccountID)
		row := tokenRow{
			ID: t.ID, Account: a.Name, Name: t.Name, Admin: a.Admin,
			MaxTunnels: a.MaxTunnels, MaxSessions: a.MaxSessions, RateLimit: a.RateLimit,
			CreatedAt: t.CreatedAt, ExpiresAt: t.ExpiresAt, Status: "active",
		}
		switch {
		case t.Revoked:
			row.Status = "revoked"
		case !a.Active:
			row.Status = "account disabled"
		case t.ExpiresAt != nil && time.Now().After(*t.ExpiresAt):
			row.Status = "expired"
		}
		rows = append(rows, row)
	}
	d.jsonResponse(w, rows)
}

func (d *Dashboard) createToken(w http.ResponseWriter, r *http.Request) {
	var req createTokenRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil {
		d.jsonError(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	opts := auth.CreateOptions{
		Account: strings.TrimSpace(req.Account), Name: strings.TrimSpace(req.Name),
		MaxTunnels: orKeep(req.MaxTunnels), MaxSessions: orKeep(req.MaxSessions), RateLimit: orKeep(req.RateLimit),
		Admin: req.Admin,
	}
	if opts.MaxTunnels < -1 || opts.MaxSessions < -1 || opts.RateLimit < -1 {
		d.jsonError(w, "Limits must not be negative", http.StatusBadRequest)
		return
	}
	if req.Expires != "" {
		life, err := auth.ParseLifetime(req.Expires)
		if err != nil {
			d.jsonError(w, "Invalid lifetime (use for example 12h or 30d)", http.StatusBadRequest)
			return
		}
		opts.Expires = life
	}

	d.tokenMu.Lock()
	f, err := auth.LoadTokenFile(d.tokenFile)
	if err != nil {
		d.tokenMu.Unlock()
		d.jsonError(w, "Cannot read the token file", http.StatusInternalServerError)
		return
	}
	secret, tok, err := f.CreateToken(opts)
	if err == nil {
		err = f.Save(d.tokenFile)
	}
	d.tokenMu.Unlock()
	if errors.Is(err, auth.ErrBadAccount) {
		d.jsonError(w, "Account names are 1-40 letters, digits, '-' or '_', starting with a letter or digit", http.StatusBadRequest)
		return
	}
	if err != nil {
		d.jsonError(w, "Cannot save the token file", http.StatusInternalServerError)
		return
	}
	d.afterTokenChange("token "+tok.ID+" created for account "+opts.Account, r)
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusCreated)
	d.jsonResponse(w, map[string]any{"id": tok.ID, "account": opts.Account, "secret": secret, "expires_at": tok.ExpiresAt})
}

// handleAdminTokenAction handles POST /api/admin/tokens/{id}/revoke.
func (d *Dashboard) handleAdminTokenAction(w http.ResponseWriter, r *http.Request) {
	if !d.tokensEnabled(w) {
		return
	}
	id, action, ok := strings.Cut(strings.TrimPrefix(r.URL.Path, "/api/admin/tokens/"), "/")
	if !ok || id == "" || action != "revoke" {
		d.jsonError(w, "Not found", http.StatusNotFound)
		return
	}
	if r.Method != http.MethodPost {
		d.jsonError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	d.tokenMu.Lock()
	f, err := auth.LoadTokenFile(d.tokenFile)
	if err == nil {
		err = f.Revoke(id)
		if err == nil {
			err = f.Save(d.tokenFile)
		}
	}
	d.tokenMu.Unlock()
	if errors.Is(err, auth.ErrTokenNotFound) {
		d.jsonError(w, "Token not found", http.StatusNotFound)
		return
	}
	if err != nil {
		d.jsonError(w, "Cannot update the token file", http.StatusInternalServerError)
		return
	}
	d.afterTokenChange("token "+id+" revoked", r)
	d.jsonResponse(w, map[string]string{"status": "revoked"})
}

// afterTokenChange logs the action and has the server apply the new file now.
func (d *Dashboard) afterTokenChange(what string, r *http.Request) {
	d.server.RecordAdminEvent(adminID(r), what)
	if d.tokensChanged != nil {
		d.tokensChanged()
	}
}
