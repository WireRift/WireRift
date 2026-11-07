package dashboard

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/wirerift/wirerift/internal/auth"
)

func isAdmin(r *http.Request) bool {
	v, _ := r.Context().Value(adminKey{}).(bool)
	return v
}

// adminOnly lets only administrator accounts through.
func (d *Dashboard) adminOnly(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !isAdmin(r) {
			d.jsonError(w, "Administrator access required", http.StatusForbidden)
			return
		}
		next(w, r)
	}
}

func (d *Dashboard) getOnly(w http.ResponseWriter, r *http.Request) bool {
	if r.Method != http.MethodGet {
		d.jsonError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return false
	}
	return true
}

// handleMe tells the page who is logged in and what it may see.
func (d *Dashboard) handleMe(w http.ResponseWriter, r *http.Request) {
	if !d.getOnly(w, r) {
		return
	}
	acct, _ := r.Context().Value(whoKey{}).(*auth.Account)
	out := map[string]any{"admin": isAdmin(r), "account": scope(r)}
	if acct != nil {
		out["account"] = acct.ID
		out["name"] = acct.Name
	}
	d.jsonResponse(w, out)
}

// handleEvents lists recent activity: everything for an administrator, only the
// caller's own account otherwise.
func (d *Dashboard) handleEvents(w http.ResponseWriter, r *http.Request) {
	if !d.getOnly(w, r) {
		return
	}
	limit := 100
	if l, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && l > 0 && l <= 500 {
		limit = l
	}
	d.jsonResponse(w, d.server.Events(limit, scope(r)))
}

func (d *Dashboard) handleAdminOverview(w http.ResponseWriter, r *http.Request) {
	if d.getOnly(w, r) {
		d.jsonResponse(w, d.server.AdminOverview())
	}
}

func (d *Dashboard) handleAdminHistory(w http.ResponseWriter, r *http.Request) {
	if d.getOnly(w, r) {
		d.jsonResponse(w, d.server.History())
	}
}

func (d *Dashboard) handleAdminCerts(w http.ResponseWriter, r *http.Request) {
	if !d.getOnly(w, r) {
		return
	}
	certs := []CertInfo{}
	if d.certs != nil {
		certs = d.certs()
	}
	d.jsonResponse(w, certs)
}

// handleAdminAccounts lists every account with its limits and current usage.
func (d *Dashboard) handleAdminAccounts(w http.ResponseWriter, r *http.Request) {
	if !d.getOnly(w, r) {
		return
	}
	usage := map[string][2]int{}
	for _, u := range d.server.AdminOverview().Accounts {
		usage[u.Account] = [2]int{u.Sessions, u.Tunnels}
	}
	type row struct {
		ID          string `json:"id"`
		Name        string `json:"name"`
		Active      bool   `json:"active"`
		Admin       bool   `json:"admin"`
		MaxTunnels  int    `json:"max_tunnels"`
		MaxSessions int    `json:"max_sessions"`
		RateLimit   int    `json:"rate_limit"`
		Sessions    int    `json:"sessions"`
		Tunnels     int    `json:"tunnels"`
	}
	rows := []row{}
	seen := map[string]bool{}
	for _, a := range d.authManager.ListAccounts() {
		u := usage[a.ID]
		seen[a.ID] = true
		rows = append(rows, row{a.ID, a.Name, a.Active, a.IsAdmin(), a.MaxTunnels, a.MaxSessions, a.RateLimit, u[0], u[1]})
	}
	for id, u := range usage { // accounts that are connected but no longer defined
		if !seen[id] {
			rows = append(rows, row{ID: id, Name: id, Sessions: u[0], Tunnels: u[1]})
		}
	}
	d.jsonResponse(w, rows)
}

// handleAdminSessionAction handles POST /api/admin/sessions/{id}/kick.
func (d *Dashboard) handleAdminSessionAction(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, "/api/admin/sessions/")
	id, action, ok := strings.Cut(rest, "/")
	if !ok || id == "" || action != "kick" {
		d.jsonError(w, "Not found", http.StatusNotFound)
		return
	}
	if r.Method != http.MethodPost {
		d.jsonError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	by := "?"
	if acct, _ := r.Context().Value(whoKey{}).(*auth.Account); acct != nil {
		by = acct.ID
	}
	if !d.server.KickSession(id, by) {
		d.jsonError(w, "Session not found", http.StatusNotFound)
		return
	}
	d.jsonResponse(w, map[string]string{"status": "disconnected"})
}
