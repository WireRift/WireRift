package dashboard

import (
	"container/list"
	"context"
	"crypto/rand"
	"embed"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/wirerift/wirerift/internal/auth"
	"github.com/wirerift/wirerift/internal/server"
)

//go:embed static/*
var staticFS embed.FS

// Dashboard provides a web UI for managing WireRift.
type Dashboard struct {
	server        *server.Server
	authManager   *auth.Manager
	port          int
	httpsEnabled  bool
	guard         authGuard
	allow         []*net.IPNet // empty = everyone
	sessions      loginSessions
	certs         func() []CertInfo
	tokenFile     string
	tokensChanged func()
	tokenMu       sync.Mutex
}

// CertInfo describes one certificate for the administrator view.
type CertInfo struct {
	Host     string    `json:"host"`
	Issuer   string    `json:"issuer"`
	NotAfter time.Time `json:"not_after"`
	DaysLeft int       `json:"days_left"`
}

// Config holds dashboard configuration.
type Config struct {
	Server       *server.Server
	AuthManager  *auth.Manager
	Port         int
	HTTPSEnabled bool
	Certs        func() []CertInfo // certificates held by the server (optional)
	// TokenFile is the token file the Admin tab manages ("" turns token
	// management off); OnTokensChanged runs after every change so the server
	// applies it at once.
	TokenFile       string
	OnTokensChanged func()
	// Allow limits who may reach the dashboard at all: addresses or CIDR
	// ranges. Empty = anyone who can reach it (sign-in is still required).
	Allow []string
}

// New creates a new dashboard.
func New(cfg Config) *Dashboard {
	if cfg.Port == 0 {
		cfg.Port = 4040
	}
	allow, _ := ParseAllowList(cfg.Allow) // main validates the flag; a bad entry here just stays out
	return &Dashboard{
		allow:         allow,
		server:        cfg.Server,
		authManager:   cfg.AuthManager,
		port:          cfg.Port,
		httpsEnabled:  cfg.HTTPSEnabled,
		certs:         cfg.Certs,
		tokenFile:     cfg.TokenFile,
		tokensChanged: cfg.OnTokensChanged,
	}
}

// Handler returns the HTTP handler for the dashboard.
func (d *Dashboard) Handler() http.Handler {
	mux := http.NewServeMux()

	// API endpoints
	mux.HandleFunc("/api/tunnels", d.authMiddleware(d.handleTunnels))
	mux.HandleFunc("/api/sessions", d.authMiddleware(d.handleSessions))
	mux.HandleFunc("/api/stats", d.authMiddleware(d.handleStats))
	mux.HandleFunc("/api/requests", d.authMiddleware(d.handleRequests))
	mux.HandleFunc("/api/requests/", d.authMiddleware(d.handleRequestActions))
	mux.HandleFunc("/api/login", d.handleLogin)
	mux.HandleFunc("/api/logout", d.handleLogout)
	mux.HandleFunc("/api/me", d.authMiddleware(d.handleMe))
	mux.HandleFunc("/api/connect", d.authMiddleware(d.handleConnect))
	mux.HandleFunc("/api/events", d.authMiddleware(d.handleEvents))
	mux.HandleFunc("/api/admin/overview", d.authMiddleware(d.adminOnly(d.handleAdminOverview)))
	mux.HandleFunc("/api/admin/history", d.authMiddleware(d.adminOnly(d.handleAdminHistory)))
	mux.HandleFunc("/api/admin/accounts", d.authMiddleware(d.adminOnly(d.handleAdminAccounts)))
	mux.HandleFunc("/api/admin/accounts/", d.authMiddleware(d.adminOnly(d.handleAdminPassword)))
	mux.HandleFunc("/api/admin/certs", d.authMiddleware(d.adminOnly(d.handleAdminCerts)))
	mux.HandleFunc("/api/admin/tokens", d.authMiddleware(d.adminOnly(d.handleAdminTokens)))
	mux.HandleFunc("/api/admin/tokens/", d.authMiddleware(d.adminOnly(d.handleAdminTokenAction)))
	mux.HandleFunc("/api/admin/sessions/", d.authMiddleware(d.adminOnly(d.handleAdminSessionAction)))
	// Unknown API paths are errors, not the web UI page the "/" catch-all would serve.
	mux.HandleFunc("/api/", func(w http.ResponseWriter, r *http.Request) {
		d.jsonError(w, "Not found", http.StatusNotFound)
	})

	// Static files - fs.Sub on embedded FS always succeeds
	staticContent, _ := fs.Sub(staticFS, "static")
	fileServer := http.FileServer(http.FS(staticContent))
	mux.Handle("/static/", http.StripPrefix("/static/", fileServer))
	mux.HandleFunc("/", d.serveIndex)

	return d.securityHeaders(mux)
}

// securityHeaders wraps a handler with standard security headers.
func (d *Dashboard) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !d.allowed(r) {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		next.ServeHTTP(w, r)
	})
}

// ParseAllowList parses addresses and CIDR ranges ("203.0.113.7",
// "198.51.100.0/24", "2001:db8::/32") for Config.Allow.
func ParseAllowList(entries []string) ([]*net.IPNet, error) {
	var nets []*net.IPNet
	for _, e := range entries {
		e = strings.TrimSpace(e)
		if e == "" {
			continue
		}
		if !strings.Contains(e, "/") {
			ip := net.ParseIP(e)
			if ip == nil {
				return nil, fmt.Errorf("invalid address %q", e)
			}
			bits := 128
			if ip.To4() != nil {
				ip, bits = ip.To4(), 32
			}
			nets = append(nets, &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)})
			continue
		}
		_, n, err := net.ParseCIDR(e)
		if err != nil {
			return nil, fmt.Errorf("invalid range %q", e)
		}
		nets = append(nets, n)
	}
	return nets, nil
}

// allowed reports whether the caller may reach the dashboard. A direct
// loopback connection (an SSH tunnel to the local port) is always allowed;
// requests relayed by the edge carry the visitor's address with port 0 and are
// checked like any other.
func (d *Dashboard) allowed(r *http.Request) bool {
	if len(d.allow) == 0 {
		return true
	}
	host, port, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return false
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	if ip.IsLoopback() && port != "0" {
		return true
	}
	for _, n := range d.allow {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

const (
	authMaxFailures   = 10
	authMaxTrackedIPs = 10000
	authWindow        = 5 * time.Minute
)

// authGuard throttles token guessing per client IP: authMaxFailures bad
// credentials within authWindow lock the IP out for authWindow.
type authGuard struct {
	mu    sync.Mutex
	fails map[string]*authFailure
	order list.List // least-recently-failed IP at the front
}

type authFailure struct {
	count int
	first time.Time
	until time.Time
	elem  *list.Element
}

func (g *authGuard) locked(ip string) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	f := g.fails[ip]
	return f != nil && time.Now().Before(f.until)
}

func (g *authGuard) fail(ip string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.fails == nil {
		g.fails = make(map[string]*authFailure)
	}
	now := time.Now()
	f := g.fails[ip]
	if f != nil && now.Sub(f.first) > authWindow && now.After(f.until) {
		g.remove(ip, f)
		f = nil
	}
	if f == nil {
		if len(g.fails) >= authMaxTrackedIPs {
			if oldest := g.order.Front(); oldest != nil {
				oldestIP, _ := oldest.Value.(string)
				delete(g.fails, oldestIP)
				g.order.Remove(oldest)
			}
		}
		f = &authFailure{first: now}
		f.elem = g.order.PushBack(ip)
		g.fails[ip] = f
	} else if f.elem != nil {
		g.order.MoveToBack(f.elem)
	}
	f.count++
	if f.count >= authMaxFailures {
		f.until = now.Add(authWindow)
		f.count = 0
		f.first = now
	}
}

func (g *authGuard) reset(ip string) {
	g.mu.Lock()
	if f := g.fails[ip]; f != nil {
		g.remove(ip, f)
	}
	g.mu.Unlock()
}

func (g *authGuard) remove(ip string, f *authFailure) {
	delete(g.fails, ip)
	if f.elem != nil {
		g.order.Remove(f.elem)
		f.elem = nil
	}
}

func remoteIP(r *http.Request) string {
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr
}

// authMiddleware checks for valid authentication.
func (d *Dashboard) authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ip := remoteIP(r)
		if d.guard.locked(ip) {
			w.Header().Set("Retry-After", "300")
			d.jsonError(w, "Too many failed attempts", http.StatusTooManyRequests)
			return
		}
		// Check for Bearer token
		authz := r.Header.Get("Authorization")
		if authz == "" {
			// Session cookies only allowed for safe (GET) requests to prevent CSRF
			if r.Method == http.MethodGet {
				cookie, err := r.Cookie("wirerift_session")
				if err == nil && cookie.Value != "" {
					_, acct, err := d.authManager.ValidateToken(cookie.Value)
					if err == nil {
						d.guard.reset(ip)
						next(w, withScope(r, acct))
						return
					}
					d.guard.fail(ip)
				}
			}
			d.jsonError(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		parts := strings.SplitN(authz, " ", 2)
		if len(parts) != 2 || parts[0] != "Bearer" {
			d.guard.fail(ip)
			d.jsonError(w, "Invalid authorization", http.StatusUnauthorized)
			return
		}

		var acct *auth.Account
		var err error
		if strings.HasPrefix(parts[1], loginSessionPrefix) {
			var ok bool
			if acct, ok = d.sessionAccount(parts[1]); !ok {
				// A dashboard session key is 256 random bits, so an unknown one is
				// an ended session (a restart drops them), not a guess. Counting it
				// would let a forgotten browser tab lock its owner out.
				d.jsonError(w, "Session ended", http.StatusUnauthorized)
				return
			}
		} else {
			_, acct, err = d.authManager.ValidateToken(parts[1])
		}
		if err != nil {
			d.guard.fail(ip)
			d.jsonError(w, "Invalid token", http.StatusUnauthorized)
			return
		}

		d.guard.reset(ip)
		next(w, withScope(r, acct))
	}
}

type scopeKey struct{}
type adminKey struct{}
type whoKey struct{}

// withScope records whose data the request may see: the bootstrap account is
// the administrator and sees everything (empty scope), any other account only
// its own tunnels, sessions and captured requests.
func withScope(r *http.Request, acct *auth.Account) *http.Request {
	scope := ""
	if acct != nil && !acct.IsAdmin() {
		scope = acct.ID
	}
	ctx := context.WithValue(r.Context(), scopeKey{}, scope)
	ctx = context.WithValue(ctx, adminKey{}, acct.IsAdmin())
	if acct != nil {
		ctx = context.WithValue(ctx, whoKey{}, acct)
	}
	return r.WithContext(ctx)
}

// scope returns the account a request is limited to ("" = unrestricted).
func scope(r *http.Request) string {
	s, _ := r.Context().Value(scopeKey{}).(string)
	return s
}

// handleTunnels handles GET /api/tunnels
func (d *Dashboard) handleTunnels(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		d.jsonError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	tunnels := d.server.ListTunnels()
	if acct := scope(r); acct != "" {
		own := make([]server.TunnelInfo, 0, len(tunnels))
		for _, t := range tunnels {
			if t.AccountID == acct {
				own = append(own, t)
			}
		}
		tunnels = own
	}
	d.jsonResponse(w, tunnels)
}

// handleSessions handles GET /api/sessions
func (d *Dashboard) handleSessions(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		d.jsonError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	sessions := d.server.ListSessions()
	if acct := scope(r); acct != "" {
		own := make([]server.SessionInfo, 0, len(sessions))
		for _, s := range sessions {
			if s.AccountID == acct {
				own = append(own, s)
			}
		}
		sessions = own
	}
	d.jsonResponse(w, sessions)
}

// handleStats handles GET /api/stats
func (d *Dashboard) handleStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		d.jsonError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	stats := d.server.StatsFor(scope(r))
	stats["uptime"] = time.Since(d.server.StartTime()).Seconds()
	stats["dashboard_port"] = d.port
	stats["https_enabled"] = d.httpsEnabled
	d.jsonResponse(w, stats)
}

// handleRequests handles GET /api/requests
func (d *Dashboard) handleRequests(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		d.jsonError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	tunnelID := r.URL.Query().Get("tunnel_id")
	limit := 50
	if l := r.URL.Query().Get("limit"); l != "" {
		if parsed, err := strconv.Atoi(l); err == nil && parsed > 0 {
			limit = parsed
			if limit > 500 {
				limit = 500
			}
		}
	}

	logs := d.server.GetRequestLogs(tunnelID, 0)
	if acct := scope(r); acct != "" {
		own := logs[:0:0]
		for _, l := range logs {
			if l.AccountID == acct {
				own = append(own, l)
			}
		}
		logs = own
	}
	if len(logs) > limit {
		logs = logs[:limit]
	}
	d.jsonResponse(w, logs)
}

// handleRequestActions handles POST /api/requests/{id}/replay
func (d *Dashboard) handleRequestActions(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/requests/")
	parts := strings.Split(path, "/")
	if len(parts) < 2 || parts[1] != "replay" {
		d.jsonError(w, "Not found", http.StatusNotFound)
		return
	}

	if r.Method != http.MethodPost {
		d.jsonError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	logID := parts[0]
	result, err := d.server.ReplayRequestAs(logID, scope(r))
	if err != nil {
		d.jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}
	d.jsonResponse(w, result)
}

// generateNonce creates a cryptographically random nonce for CSP.
func generateNonce() string {
	b := make([]byte, 16)
	rand.Read(b)
	return base64.StdEncoding.EncodeToString(b)
}

// serveIndex serves the main index.html with CSP nonce for inline script.
func (d *Dashboard) serveIndex(w http.ResponseWriter, r *http.Request) {
	nonce := generateNonce()
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Security-Policy",
		fmt.Sprintf("default-src 'self'; script-src 'nonce-%s'; style-src 'unsafe-inline'; connect-src 'self'", nonce))
	// Replace the script tag placeholder with the nonce
	html := strings.Replace(indexHTML, "<script>", fmt.Sprintf(`<script nonce="%s">`, nonce), 1)
	w.Write([]byte(html))
}

// jsonResponse writes a JSON response.
func (d *Dashboard) jsonResponse(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(data) // error is client disconnect — nothing to do
}

// jsonError writes a JSON error response.
func (d *Dashboard) jsonError(w http.ResponseWriter, message string, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": message})
}

// Addr returns the dashboard address.
func (d *Dashboard) Addr() string {
	return fmt.Sprintf(":%d", d.port)
}

// indexHTML is the embedded dashboard HTML — advanced monitoring dashboard.
// NOTE: No backtick characters allowed inside (Go raw string literal).
// JS uses string concatenation instead of template literals.
var indexHTML = `<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>WireRift Dashboard</title>
<style>
*,*::before,*::after{margin:0;padding:0;box-sizing:border-box}
:root{
--bg-0:#06080f;--bg-1:#0c1019;--bg-2:#151b2b;--bg-3:#1e293b;
--tx-0:#f1f5f9;--tx-1:#94a3b8;--tx-2:#64748b;
--ac:#3b82f6;--ac-h:#2563eb;
--ok:#22c55e;--wn:#f59e0b;--er:#ef4444;--pr:#a78bfa;--tl:#14b8a6;
--bd:#1e293b;--shadow:0 1px 3px rgba(0,0,0,.4);
}
[data-theme="light"]{
--bg-0:#f8fafc;--bg-1:#ffffff;--bg-2:#f1f5f9;--bg-3:#e2e8f0;
--tx-0:#0f172a;--tx-1:#475569;--tx-2:#94a3b8;
--ac:#2563eb;--ac-h:#1d4ed8;
--ok:#16a34a;--wn:#d97706;--er:#dc2626;--pr:#7c3aed;--tl:#0d9488;
--bd:#e2e8f0;--shadow:0 1px 3px rgba(0,0,0,.08);
}
body{
font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Oxygen,Ubuntu,sans-serif;
background:var(--bg-0);color:var(--tx-0);min-height:100vh;
transition:background .2s,color .2s;
}
.mono{font-family:'SF Mono',SFMono-Regular,Consolas,'Liberation Mono',Menlo,monospace;font-size:.8125rem}
a{color:var(--ac);text-decoration:none}

/* Layout */
.shell{max-width:1440px;margin:0 auto;padding:1rem 1.25rem 2rem}
@media(min-width:768px){.shell{padding:1.25rem 2rem 2.5rem}}

/* Header */
.hdr{display:flex;align-items:center;justify-content:space-between;padding:.75rem 0 1.25rem;border-bottom:1px solid var(--bd);margin-bottom:1.5rem}
.hdr-logo{font-size:1.375rem;font-weight:700;letter-spacing:-.02em;display:flex;align-items:center;gap:.5rem}
.hdr-logo span{color:var(--ac)}
.hdr-right{display:flex;align-items:center;gap:.625rem}
.hdr-badge{font-size:.6875rem;padding:.2rem .5rem;border-radius:9999px;background:var(--bg-3);color:var(--tx-2);font-weight:500}

/* Buttons */
.btn{
display:inline-flex;align-items:center;justify-content:center;gap:.375rem;
background:var(--ac);color:#fff;border:none;padding:.5rem 1rem;
border-radius:.5rem;cursor:pointer;font-size:.875rem;font-weight:500;
transition:background .2s,transform .1s;white-space:nowrap;
}
.btn:hover{background:var(--ac-h)}
.btn:active{transform:scale(.97)}
.btn-ghost{
background:transparent;color:var(--tx-1);border:1px solid var(--bd);
padding:.375rem .75rem;border-radius:.375rem;cursor:pointer;
font-size:.8125rem;transition:all .2s;
}
.btn-ghost:hover{background:var(--bg-3);color:var(--tx-0)}
.btn-sm{
background:var(--bg-3);color:var(--tx-1);border:none;
padding:.25rem .5rem;border-radius:.25rem;cursor:pointer;
font-size:.75rem;font-weight:500;transition:all .15s;
}
.btn-sm:hover{background:var(--ac);color:#fff}
.btn-icon{
background:transparent;border:none;color:var(--tx-2);cursor:pointer;
padding:.375rem;border-radius:.375rem;transition:all .15s;display:inline-flex;
align-items:center;justify-content:center;
}
.btn-icon:hover{background:var(--bg-3);color:var(--tx-0)}
.theme-toggle{font-size:1.125rem;width:2rem;height:2rem}

/* Stats Grid */
.stats{display:grid;grid-template-columns:repeat(5,1fr);gap:1rem;margin-bottom:1.5rem}
@media(max-width:1024px){.stats{grid-template-columns:repeat(3,1fr)}}
@media(max-width:640px){.stats{grid-template-columns:repeat(2,1fr)}}
.stat{
background:var(--bg-1);border:1px solid var(--bd);border-radius:.75rem;
padding:1rem 1.125rem;position:relative;overflow:hidden;
transition:border-color .2s,box-shadow .2s;box-shadow:var(--shadow);
}
.stat::before{
content:'';position:absolute;top:0;left:0;right:0;height:2px;
}
.stat:hover{border-color:var(--tx-2)}
.stat--blue::before{background:var(--ac)}
.stat--green::before{background:var(--ok)}
.stat--amber::before{background:var(--wn)}
.stat--purple::before{background:var(--pr)}
.stat--teal::before{background:var(--tl)}
.stat-label{font-size:.75rem;color:var(--tx-2);text-transform:uppercase;letter-spacing:.04em;margin-bottom:.375rem;font-weight:500}
.stat-val{font-size:1.625rem;font-weight:700;line-height:1.2;transition:color .2s}
.stat--blue .stat-val{color:var(--ac)}
.stat--green .stat-val{color:var(--ok)}
.stat--amber .stat-val{color:var(--wn)}
.stat--purple .stat-val{color:var(--pr)}
.stat--teal .stat-val{color:var(--tl)}

/* Tabs */
.tabs{display:flex;gap:0;border-bottom:2px solid var(--bd);margin-bottom:1.25rem}
.tab{
padding:.625rem 1.125rem;cursor:pointer;font-size:.875rem;font-weight:500;
color:var(--tx-2);border-bottom:2px solid transparent;margin-bottom:-2px;
transition:color .15s,border-color .15s;display:flex;align-items:center;gap:.5rem;
user-select:none;
}
.tab:hover{color:var(--tx-0)}
.tab.active{color:var(--ac);border-bottom-color:var(--ac)}
.tab-badge{
font-size:.6875rem;min-width:1.25rem;height:1.25rem;padding:0 .375rem;
border-radius:9999px;background:var(--bg-3);color:var(--tx-2);
display:inline-flex;align-items:center;justify-content:center;font-weight:600;
}
.tab.active .tab-badge{background:rgba(59,130,246,.15);color:var(--ac)}

/* Activity filter chips */
.chips{display:inline-flex;gap:6px;flex-wrap:wrap;margin-left:10px}
.chip{background:var(--bg-2);color:var(--tx-1);border:1px solid var(--bd);border-radius:999px;padding:4px 11px;font:inherit;font-size:12px;cursor:pointer}
.chip:hover{color:var(--tx-0)}
.chip.on{background:var(--ac);border-color:var(--ac);color:#fff}
tr.row-warn td{background:color-mix(in srgb,var(--wn) 9%,transparent)}
tr.row-warn td:first-child{box-shadow:inset 3px 0 0 var(--wn)}
/* Tabs on narrow screens, links, duration bars */
.tabs{overflow-x:auto;scrollbar-width:none}.tabs::-webkit-scrollbar{display:none}.tab{flex:none;white-space:nowrap}
@media(max-width:640px){.tab .kbd{display:none}.tab{padding:.625rem .75rem}}
.lnk{color:var(--ac);text-decoration:none}.lnk:hover{text-decoration:underline}
.dur-cell{white-space:nowrap}.dur-t{display:inline-block;min-width:4.5rem}
.dur{display:inline-block;vertical-align:middle;width:3.5rem;height:.3125rem;background:var(--bg-3);border-radius:999px;overflow:hidden}
.dur b{display:block;height:100%;background:var(--ac);border-radius:999px}.dur.slow b{background:var(--wn)}
.panel-bar-left .chips{margin-left:.25rem}
/* Admin console */
.adm-hero{display:flex;align-items:center;justify-content:space-between;gap:1rem;flex-wrap:wrap;margin-top:1rem;padding:1rem 1.25rem;border:1px solid var(--bd);border-radius:.75rem;background:var(--bg-1);box-shadow:var(--shadow);position:relative;overflow:hidden}
.adm-hero::before{content:'';position:absolute;left:0;top:0;bottom:0;width:4px;background:var(--ok)}
.adm-hero.warn::before{background:var(--wn)}.adm-hero.bad::before{background:var(--er)}
.hero-main{display:flex;align-items:center;gap:.875rem;min-width:0}
.hero-dot{width:.875rem;height:.875rem;border-radius:50%;background:var(--ok);box-shadow:0 0 0 4px color-mix(in srgb,var(--ok) 22%,transparent);flex:none}
.adm-hero.warn .hero-dot{background:var(--wn);box-shadow:0 0 0 4px color-mix(in srgb,var(--wn) 22%,transparent)}
.adm-hero.bad .hero-dot{background:var(--er);box-shadow:0 0 0 4px color-mix(in srgb,var(--er) 22%,transparent)}
.hero-t{font-size:1.125rem;font-weight:700;color:var(--tx-0)}
.hero-s{font-size:.8125rem;color:var(--tx-1);margin-top:.25rem;display:flex;flex-wrap:wrap;gap:.375rem;align-items:center}
.hero-meta{display:flex;flex-wrap:wrap;gap:.375rem}
.hero-meta span{font-size:.75rem;color:var(--tx-1);background:var(--bg-2);border:1px solid var(--bd);border-radius:999px;padding:.1875rem .625rem}
.tiles-label{font-size:.6875rem;font-weight:600;color:var(--tx-2);text-transform:uppercase;letter-spacing:.06em;margin:1.125rem 0 .5rem}
.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(11.5rem,1fr));gap:.75rem}
.tile{position:relative;overflow:hidden;background:var(--bg-1);border:1px solid var(--bd);border-radius:.75rem;padding:.8125rem 1rem .5rem;box-shadow:var(--shadow);min-height:6.75rem;display:flex;flex-direction:column}
.tile-k{font-size:.6875rem;color:var(--tx-2);text-transform:uppercase;letter-spacing:.05em;font-weight:600}
.tile-v{font-size:1.5rem;font-weight:700;color:var(--tx-0);margin-top:.1875rem;line-height:1.15;word-break:break-word}
.tile-s{font-size:.6875rem;color:var(--tx-2);margin-top:.1875rem}
.tile.warn{border-color:color-mix(in srgb,var(--wn) 55%,var(--bd))}.tile.warn .tile-v{color:var(--wn)}
.tile-spark{width:100%;height:1.75rem;display:block;margin-top:auto;padding-top:.375rem}
.meter{height:.375rem;background:var(--bg-3);border-radius:999px;overflow:hidden;margin-top:.5rem}
.meter i{display:block;height:100%;border-radius:999px}
.adm-panel{background:var(--bg-1);border:1px solid var(--bd);border-radius:.75rem;padding:.875rem 1rem;box-shadow:var(--shadow);min-width:0}
.adm-panel-h{display:flex;align-items:center;justify-content:space-between;gap:.75rem;flex-wrap:wrap;margin-bottom:.625rem;font-size:.8125rem;color:var(--tx-0)}
.adm-sub{font-size:.6875rem;color:var(--tx-2)}
.seg{display:inline-flex;border:1px solid var(--bd);border-radius:.5rem;overflow:hidden}
.seg button{background:transparent;border:none;color:var(--tx-1);font:inherit;font-size:.75rem;padding:.3125rem .875rem;cursor:pointer}
.seg button.on{background:var(--ac);color:#fff}
.adm-legend{display:flex;gap:1rem;flex-wrap:wrap;font-size:.75rem;color:var(--tx-1)}
.adm-legend i,.adm-tip i{display:inline-block;width:.625rem;height:.625rem;border-radius:2px;margin-right:.375rem}
.adm-legend b,.adm-tip b{color:var(--tx-0);font-weight:600}
.adm-chart{position:relative;min-height:14.5rem}
.adm-chart svg{display:block;max-width:100%}
.ax-grid{stroke:var(--bd);stroke-width:1}.ax-t{fill:var(--tx-2);font-size:10.5px}.ax-x{stroke:var(--tx-2);stroke-width:1;stroke-dasharray:3 3}
.adm-tip{position:absolute;pointer-events:none;background:var(--bg-3);border:1px solid var(--bd);border-radius:.5rem;padding:.4375rem .625rem;font-size:.75rem;color:var(--tx-1);box-shadow:0 6px 18px rgba(0,0,0,.35);white-space:nowrap;z-index:3}
.adm-tip .tt{color:var(--tx-2);font-size:.6875rem;margin:.0625rem 0 .1875rem}
.adm-tbl{margin-top:.5rem}.adm-tbl summary{cursor:pointer;font-size:.75rem;color:var(--tx-2)}.adm-tbl .tbl-wrap{margin-top:.5rem;max-height:14rem;overflow:auto}
.two{margin-top:.75rem}
.lh-row{display:flex;align-items:flex-end;gap:2px;height:8.5rem}
.lh{flex:1;min-width:0;display:flex;flex-direction:column;align-items:center;height:100%}
.lh-b{flex:1;width:100%;display:flex;align-items:flex-end}
.lh-b i{display:block;width:100%;border-radius:3px 3px 0 0;min-height:1px}
.lh span{font-size:.5625rem;color:var(--tx-2);margin-top:.25rem;white-space:nowrap}
.lh-stats{display:flex;flex-wrap:wrap;gap:.375rem 1.125rem;margin-top:.75rem;font-size:.75rem;color:var(--tx-2)}.lh-stats b{color:var(--tx-0)}
.stackbar{display:flex;gap:2px;height:.875rem;border-radius:.4375rem;overflow:hidden;margin:.25rem 0 .875rem}
.stackbar i{display:block;min-width:3px}
.sl{display:flex;align-items:center;justify-content:space-between;gap:.75rem;padding:.3125rem 0;font-size:.8125rem;border-bottom:1px solid var(--bd);color:var(--tx-1)}
.sl:last-child{border-bottom:none}.sl i{display:inline-block;width:.625rem;height:.625rem;border-radius:2px;margin-right:.5rem}
.sl em{font-style:normal;color:var(--tx-2);margin-left:.25rem}.sl b{margin-left:auto;color:var(--tx-0)}.sl u{text-decoration:none;color:var(--tx-2);width:3.5rem;text-align:right}
.accts{display:grid;grid-template-columns:repeat(auto-fill,minmax(19rem,1fr));gap:.75rem}
.acct{background:var(--bg-1);border:1px solid var(--bd);border-radius:.75rem;padding:.875rem 1rem;box-shadow:var(--shadow);display:flex;flex-direction:column;gap:.75rem}
.acct.off{opacity:.65}
.acct-h{display:flex;align-items:center;justify-content:space-between;gap:.5rem}.acct-h b{font-size:1rem;color:var(--tx-0);overflow:hidden;text-overflow:ellipsis}
.lims{display:grid;grid-template-columns:1fr 1fr;gap:.75rem}
.lim-h{display:flex;justify-content:space-between;font-size:.6875rem;color:var(--tx-2);text-transform:uppercase;letter-spacing:.04em}.lim-h b{color:var(--tx-0);font-size:.8125rem;text-transform:none;letter-spacing:0}
.lim-n{font-size:.6875rem;color:var(--tx-2);margin-top:.5rem}
.acct-n{font-size:.6875rem;color:var(--tx-2);margin-top:.375rem}
.acct-a{display:flex;gap:.5rem;margin-top:auto}
.mono{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:.75rem}
.adm-nav a.on{color:#fff;background:var(--ac);border-color:var(--ac)}
.adm-forms>details{margin:0}
@media(max-width:480px){.tiles{grid-template-columns:repeat(2,minmax(0,1fr));gap:.5rem}.tile-v{font-size:1.1875rem}.lims{grid-template-columns:1fr}.adm-hero{padding:.875rem}}
/* Admin / Activity */
.cards{display:grid;grid-template-columns:repeat(auto-fill,minmax(10.5rem,1fr));gap:.75rem;margin-bottom:1rem}
@media(max-width:480px){.cards{grid-template-columns:repeat(2,minmax(0,1fr));gap:.5rem}.card .v{font-size:1.0625rem}}
.card{background:var(--bg-1);border:1px solid var(--bd);border-radius:.625rem;padding:.75rem .875rem;box-shadow:var(--shadow)}
.card .k{font-size:.6875rem;color:var(--tx-2);text-transform:uppercase;letter-spacing:.04em;font-weight:500}
.card .v{font-size:1.25rem;font-weight:700;margin-top:.25rem;word-break:break-word}
.card .s{font-size:.6875rem;color:var(--tx-2);margin-top:.125rem}
.card.ok .v{color:var(--ok)}.card.warn .v{color:var(--wn)}.card.bad .v{color:var(--er)}
.sec-title{font-size:.8125rem;font-weight:600;color:var(--tx-1);margin:1.25rem 0 .5rem;text-transform:uppercase;letter-spacing:.05em}
.adm-nav{position:sticky;top:0;z-index:5;display:flex;flex-wrap:wrap;gap:.375rem;margin:.75rem 0 0;padding:.5rem 0;background:var(--bg-0);border-bottom:1px solid var(--bd)}
.adm-nav a{font-size:.75rem;color:var(--tx-1);text-decoration:none;padding:.25rem .625rem;border:1px solid var(--bd);border-radius:999px;background:var(--bg-1)}
.adm-nav a:hover{color:var(--ac);border-color:var(--ac)}
.adm-forms{display:grid;grid-template-columns:minmax(0,3fr) minmax(0,2fr);gap:.75rem;margin-top:.75rem;align-items:start}
@media(max-width:900px){.adm-forms{grid-template-columns:minmax(0,1fr)}}
.adm-card{background:var(--bg-1);border:1px solid var(--bd);border-radius:.625rem;padding:.75rem 1rem}
.adm-card>summary{font-weight:600;font-size:.875rem;color:var(--tx-0);cursor:pointer}
.adm-find{margin:.25rem 0 .5rem;max-width:18rem}
.sec-title{scroll-margin-top:3.5rem}
.pill{display:inline-block;padding:.0625rem .5rem;border-radius:9999px;font-size:.6875rem;font-weight:600;background:var(--bg-3);color:var(--tx-1)}
.pill.ok{background:rgba(34,197,94,.15);color:var(--ok)}.pill.warn{background:rgba(245,158,11,.15);color:var(--wn)}.pill.bad{background:rgba(239,68,68,.15);color:var(--er)}
.two{display:grid;grid-template-columns:repeat(auto-fit,minmax(20rem,1fr));gap:1rem}
.btn-danger{background:transparent;color:var(--er);border:1px solid var(--er);border-radius:.375rem;padding:.1875rem .5rem;cursor:pointer;font-size:.75rem}
.btn-danger:hover{background:var(--er);color:#fff}

/* Panels */
.panel{display:none}
.panel.active{display:block}
.panel-bar{display:flex;align-items:center;justify-content:space-between;gap:.75rem;margin-bottom:1rem;flex-wrap:wrap}
.panel-bar-left{display:flex;align-items:center;gap:.5rem;flex:1;min-width:0}
.search-box{
flex:1;max-width:20rem;padding:.4375rem .75rem;background:var(--bg-1);
border:1px solid var(--bd);border-radius:.375rem;color:var(--tx-0);
font-size:.8125rem;transition:border-color .15s;
}
.search-box:focus{outline:none;border-color:var(--ac)}
.search-box::placeholder{color:var(--tx-2)}

/* Tables */
.tbl-wrap{overflow-x:auto;border:1px solid var(--bd);border-radius:.625rem;background:var(--bg-1)}
table{width:100%;border-collapse:collapse}
th,td{text-align:left;padding:.625rem .875rem;white-space:nowrap}
th{
font-size:.6875rem;font-weight:600;text-transform:uppercase;letter-spacing:.04em;
color:var(--tx-2);background:var(--bg-2);border-bottom:1px solid var(--bd);
position:sticky;top:0;z-index:1;
}
td{border-bottom:1px solid var(--bd);font-size:.8125rem;color:var(--tx-1)}
tr:last-child td{border-bottom:none}
tbody tr{transition:background .1s}
tbody tr:hover{background:var(--bg-2)}

/* Status dot */
.status-dot{
display:inline-flex;align-items:center;gap:.375rem;font-size:.8125rem;font-weight:500;
}
.status-dot::before{
content:'';width:.5rem;height:.5rem;border-radius:50%;
background:var(--ok);animation:pulse 2s ease-in-out infinite;
}
@keyframes pulse{
0%,100%{opacity:1;box-shadow:0 0 0 0 rgba(34,197,94,.4)}
50%{opacity:.7;box-shadow:0 0 0 4px rgba(34,197,94,0)}
}

/* Protection badges */
.badge{
display:inline-block;padding:.125rem .4375rem;border-radius:.25rem;
font-size:.6875rem;font-weight:600;letter-spacing:.02em;
}
.badge--ip{background:rgba(59,130,246,.12);color:var(--ac)}
.badge--pin{background:rgba(167,139,250,.12);color:var(--pr)}
.badge--auth{background:rgba(20,184,166,.12);color:var(--tl)}
.badge--inspect{background:rgba(245,158,11,.12);color:var(--wn)}

/* Method badges */
.method{
font-family:'SF Mono',SFMono-Regular,Consolas,monospace;
font-size:.6875rem;font-weight:700;padding:.125rem .375rem;
border-radius:.25rem;letter-spacing:.02em;
}
.method-GET{background:rgba(34,197,94,.12);color:var(--ok)}
.method-POST{background:rgba(59,130,246,.12);color:var(--ac)}
.method-PUT{background:rgba(245,158,11,.12);color:var(--wn)}
.method-DELETE{background:rgba(239,68,68,.12);color:var(--er)}
.method-PATCH{background:rgba(167,139,250,.12);color:var(--pr)}
.method-HEAD{background:rgba(100,116,139,.12);color:var(--tx-2)}
.method-OPTIONS{background:rgba(100,116,139,.12);color:var(--tx-2)}

/* Status codes */
.sc{font-family:'SF Mono',SFMono-Regular,Consolas,monospace;font-weight:600;font-size:.8125rem}
.sc-2{color:var(--ok)}
.sc-3{color:var(--ac)}
.sc-4{color:var(--wn)}
.sc-5{color:var(--er)}

/* Expandable detail */
.detail-row{display:none}
.detail-row.open{display:table-row}
.detail-cell{padding:0 !important;background:var(--bg-0) !important;border-bottom:1px solid var(--bd) !important}
.detail-inner{padding:.875rem;display:flex;flex-direction:column;gap:.75rem}
.detail-cols{display:grid;grid-template-columns:1fr 1fr;gap:.75rem}
@media(max-width:768px){.detail-cols{grid-template-columns:1fr}}
.detail-section{background:var(--bg-1);border:1px solid var(--bd);border-radius:.5rem;overflow:hidden}
.detail-section-title{
font-size:.6875rem;font-weight:600;text-transform:uppercase;letter-spacing:.04em;
color:var(--tx-2);padding:.5rem .75rem;background:var(--bg-2);border-bottom:1px solid var(--bd);
}
.detail-section pre{
padding:.75rem;font-size:.75rem;line-height:1.5;white-space:pre-wrap;word-break:break-all;
color:var(--tx-1);max-height:16rem;overflow-y:auto;margin:0;
font-family:'SF Mono',SFMono-Regular,Consolas,monospace;
}
.detail-actions{display:flex;gap:.5rem;padding:.25rem 0 0}

/* JSON syntax */
.json-key{color:#22d3ee}
.json-str{color:var(--ok)}
.json-num{color:var(--wn)}
.json-bool{color:var(--pr)}
.json-null{color:var(--tx-2)}
.json-brace{color:var(--tx-2)}

/* Session expandable */
.sess-detail-row{display:none}
.sess-detail-row.open{display:table-row}
.sess-detail-cell{padding:.75rem !important;background:var(--bg-0) !important}
.sess-kv{display:grid;grid-template-columns:auto 1fr;gap:.25rem .75rem;font-size:.8125rem}
.sess-kv dt{color:var(--tx-2);font-weight:500}
.sess-kv dd{color:var(--tx-1)}

/* Copy feedback */
.copy-ok{color:var(--ok) !important;transition:color .15s}


/* Connect page */
.cn-grid{display:grid;grid-template-columns:minmax(0,22rem) minmax(0,1fr);gap:1.5rem;align-items:start}
@media (max-width:860px){.cn-grid{grid-template-columns:minmax(0,1fr)}}
.cn-form label{display:block;font-size:.75rem;color:var(--tx-1);margin:.75rem 0 .25rem}
.cn-form input[type=text],.cn-form input[type=password],.cn-form input[type=number],.cn-form select,.cn-out select{
width:100%;padding:.4375rem .625rem;background:var(--bg-1);border:1px solid var(--bd);
border-radius:.375rem;color:var(--tx-0);font-size:.8125rem}
.cn-form input:focus,.cn-form select:focus,.cn-out select:focus{outline:none;border-color:var(--ac)}
.cn-form input.bad{border-color:var(--err,#ef4444)}
.cn-form .hint{color:var(--tx-2);font-weight:400}
.cn-form .chk{display:flex;align-items:center;gap:.5rem;font-size:.8125rem;color:var(--tx-0);margin:.75rem 0 0}
.cn-seg{display:flex;border:1px solid var(--bd);border-radius:.5rem;overflow:hidden}
.cn-seg button{flex:1;padding:.5rem .75rem;background:var(--bg-1);color:var(--tx-1);border:none;cursor:pointer;font-size:.8125rem}
.cn-seg button.on{background:var(--ac);color:#fff}
.cn-url{margin-top:.75rem;padding:.5rem .75rem;background:var(--bg-2);border-radius:.375rem;word-break:break-all}
.cn-form details{margin-top:.75rem}
.cn-form summary{cursor:pointer;font-size:.8125rem;color:var(--tx-1)}
.cn-box{position:relative;background:var(--bg-2);border:1px solid var(--bd);border-radius:.5rem;padding:.75rem 4.5rem .75rem .875rem;margin:.375rem 0 1rem;overflow-x:auto}
.cn-box pre{margin:0;white-space:pre-wrap;word-break:break-all}
.cn-box .btn-sm{position:absolute;top:.5rem;right:.5rem}
.cn-status{padding:.625rem .875rem;border-radius:.5rem;background:var(--bg-2);font-size:.8125rem}
.cn-status.ok{border:1px solid var(--ok);color:var(--ok)}
.cn-note{color:var(--tx-2);font-size:.75rem;margin:-.5rem 0 1rem}


/* Token management */
.tok-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(11rem,1fr));gap:.25rem .75rem;margin-top:.5rem}
.tok-secret{margin-top:1rem;padding:.875rem 1rem;border:1px solid var(--ok);border-radius:.5rem;background:var(--bg-2)}
.tok-secret code{display:block;margin:.5rem 0;padding:.5rem .75rem;background:var(--bg-1);border-radius:.375rem;word-break:break-all;user-select:all}
.tok-off{opacity:.55}
#tokNew .cn-note{margin:.75rem 0}

/* Empty state */
.empty{text-align:center;padding:2.5rem 1rem;color:var(--tx-2);font-size:.875rem}

/* Toast container */
.toasts{position:fixed;top:1rem;right:1rem;z-index:9999;display:flex;flex-direction:column;gap:.5rem;pointer-events:none}
.toast{
pointer-events:auto;display:flex;align-items:center;gap:.625rem;
padding:.625rem 1rem;border-radius:.5rem;font-size:.8125rem;font-weight:500;
box-shadow:0 4px 12px rgba(0,0,0,.25);min-width:14rem;max-width:22rem;
transform:translateX(110%);opacity:0;transition:transform .3s ease,opacity .3s ease;
}
.toast.show{transform:translateX(0);opacity:1}
.toast.hide{transform:translateX(110%);opacity:0}
.toast--ok{background:#166534;color:#bbf7d0;border:1px solid #22c55e}
.toast--er{background:#7f1d1d;color:#fecaca;border:1px solid #ef4444}
.toast--info{background:#1e3a5f;color:#bfdbfe;border:1px solid #3b82f6}
[data-theme="light"] .toast--ok{background:#dcfce7;color:#166534;border-color:#86efac}
[data-theme="light"] .toast--er{background:#fee2e2;color:#7f1d1d;border-color:#fca5a5}
[data-theme="light"] .toast--info{background:#dbeafe;color:#1e3a5f;border-color:#93c5fd}

/* Login overlay */
.overlay{
display:none;position:fixed;inset:0;z-index:1000;
background:rgba(0,0,0,.6);backdrop-filter:blur(6px);-webkit-backdrop-filter:blur(6px);
justify-content:center;align-items:center;
}
.overlay.show{display:flex}
.login-box{
background:var(--bg-1);border:1px solid var(--bd);border-radius:1rem;
padding:2rem;width:100%;max-width:24rem;box-shadow:0 8px 32px rgba(0,0,0,.3);
}
.login-box h2{text-align:center;margin-bottom:.375rem;font-size:1.25rem}
.login-box .sub{text-align:center;color:var(--tx-2);font-size:.8125rem;margin-bottom:1.5rem}
.field{margin-bottom:1rem}
.field label{display:block;font-size:.8125rem;font-weight:500;color:var(--tx-2);margin-bottom:.375rem}
.field input{
width:100%;padding:.5rem .75rem;background:var(--bg-0);color:var(--tx-0);
border:1px solid var(--bd);border-radius:.5rem;font-size:.875rem;
transition:border-color .15s;
}
.field input:focus{outline:none;border-color:var(--ac);box-shadow:0 0 0 3px rgba(59,130,246,.15)}
.login-err{color:var(--er);font-size:.8125rem;text-align:center;margin-top:.75rem;min-height:1.25rem}

/* Tunnel filter select */
.sel{
padding:.375rem .625rem;background:var(--bg-1);color:var(--tx-0);
border:1px solid var(--bd);border-radius:.375rem;font-size:.8125rem;
cursor:pointer;transition:border-color .15s;
}
.sel:focus{outline:none;border-color:var(--ac)}

/* Keyboard shortcut hints */
.kbd{
display:inline-block;padding:.0625rem .3125rem;background:var(--bg-3);
border:1px solid var(--bd);border-radius:.25rem;font-size:.625rem;
font-family:'SF Mono',Consolas,monospace;color:var(--tx-2);line-height:1.4;
vertical-align:middle;margin-left:.25rem;
}

/* Scrollbar */
::-webkit-scrollbar{width:6px;height:6px}
::-webkit-scrollbar-track{background:transparent}
::-webkit-scrollbar-thumb{background:var(--bg-3);border-radius:3px}
::-webkit-scrollbar-thumb:hover{background:var(--tx-2)}

/* Inspector row pointer */
.insp-row{cursor:pointer;transition:background .1s}
.insp-row:hover{background:var(--bg-2)}

/* Responsive table */
@media(max-width:640px){
th,td{padding:.5rem .625rem;font-size:.75rem}
.stat-val{font-size:1.25rem}
.stats{gap:.625rem}
}
</style>
</head>
<body>
<div class="toasts" id="toasts"></div>
<div class="shell" id="app" style="display:none">
<!-- Header -->
<header class="hdr">
<div class="hdr-logo">Wire<span>Rift</span> <span class="hdr-badge">Dashboard</span></div>
<div class="hdr-right">
<button class="btn-icon theme-toggle" id="themeBtn" title="Toggle theme (dark/light)">&#9790;</button>
<button class="btn" id="authBtn">Login</button>
</div>
</header>

<!-- Stats -->
<div class="stats">
<div class="stat stat--blue"><div class="stat-label">Active Tunnels</div><div class="stat-val" id="sTunnels">-</div></div>
<div class="stat stat--green"><div class="stat-label">Sessions</div><div class="stat-val" id="sSessions">-</div></div>
<div class="stat stat--amber"><div class="stat-label">Bytes In</div><div class="stat-val" id="sBytesIn">-</div></div>
<div class="stat stat--purple"><div class="stat-label">Bytes Out</div><div class="stat-val" id="sBytesOut">-</div></div>
<div class="stat stat--teal"><div class="stat-label">Uptime</div><div class="stat-val" id="sUptime">-</div></div>
</div>

<!-- Tabs -->
<div class="tabs" id="tabBar">
<div class="tab active" data-tab="tunnels">Tunnels <span class="tab-badge" id="badgeTunnels">0</span> <span class="kbd">T</span></div>
<div class="tab" data-tab="connect">Connect <span class="kbd">C</span></div>
<div class="tab" data-tab="sessions">Sessions <span class="tab-badge" id="badgeSessions">0</span> <span class="kbd">S</span></div>
<div class="tab" data-tab="inspector">Inspector <span class="tab-badge" id="badgeInspector">0</span> <span class="kbd">I</span></div>
<div class="tab" data-tab="activity">Activity <span class="tab-badge" id="badgeActivity">0</span> <span class="kbd">A</span></div>
<div class="tab" data-tab="admin" id="tabAdmin" style="display:none">Admin <span class="kbd">D</span></div>
</div>

<!-- Tunnels Panel -->
<div class="panel active" id="panelTunnels">
<div class="panel-bar">
<div class="panel-bar-left"><input class="search-box" id="searchTunnels" type="text" placeholder="Filter tunnels..."></div>
<button class="btn-ghost" id="refreshTunnels">Refresh <span class="kbd">R</span></button>
</div>
<div class="tbl-wrap">
<table><thead><tr><th>ID</th><th>Type</th><th>URL / Port</th><th>Target</th><th>Protection</th><th>Status</th><th>Created</th><th></th></tr></thead>
<tbody id="tbodyTunnels"></tbody></table>
</div>
<div class="empty" id="emptyTunnels" style="display:none">No active tunnels</div>
</div>

<!-- Sessions Panel -->
<div class="panel" id="panelSessions">
<div class="panel-bar">
<div class="panel-bar-left"><input class="search-box" id="searchSessions" type="text" placeholder="Filter sessions..."></div>
<button class="btn-ghost" id="refreshSessions">Refresh <span class="kbd">R</span></button>
</div>
<div class="tbl-wrap">
<table><thead><tr><th>ID</th><th>Account</th><th>Remote Address</th><th>Connected</th><th>Last Heartbeat</th><th>Uptime</th><th>Tunnels</th></tr></thead>
<tbody id="tbodySessions"></tbody></table>
</div>
<div class="empty" id="emptySessions" style="display:none">No connected sessions</div>
</div>

<!-- Inspector Panel -->
<div class="panel" id="panelInspector">
<div class="panel-bar">
<div class="panel-bar-left">
<input class="search-box" id="searchInspector" type="text" placeholder="Filter by path, method, status...">
<select class="sel" id="tunnelFilter"><option value="">All Tunnels</option></select>
<span class="chips" id="inspChips"><button class="chip on" data-sc="">All</button><button class="chip" data-sc="2">2xx</button><button class="chip" data-sc="3">3xx</button><button class="chip" data-sc="4">4xx</button><button class="chip" data-sc="5">5xx</button><button class="chip" data-sc="slow" title="Took 500 ms or more">Slow</button></span>
</div>
<button class="btn-ghost" id="refreshRequests">Refresh <span class="kbd">R</span></button>
</div>
<div class="tbl-wrap">
<table><thead><tr><th>Time</th><th>Method</th><th>Path</th><th>Status</th><th>Duration</th><th>Client IP</th><th>Actions</th></tr></thead>
<tbody id="tbodyRequests"></tbody></table>
</div>
<div class="empty" id="emptyRequests" style="display:none">No captured requests</div>
</div>

<!-- Connect Panel -->
<div class="panel" id="panelConnect">
<div class="cn-grid">
<div class="cn-form">
<div class="sec-title" style="margin-top:0">1. What do you want to publish?</div>
<div class="cn-seg" id="cnType"><button class="on" data-v="http">Web (HTTP / HTTPS)</button><button data-v="tcp">TCP</button></div>
<label for="cnPort">Local port (forwarded from localhost)</label>
<input id="cnPort" type="number" min="1" max="65535" value="3000">
<div id="cnSubWrap"><label for="cnSub">Subdomain <span class="hint">(empty = a random one)</span></label>
<input id="cnSub" type="text" placeholder="myapp" autocomplete="off" spellcheck="false"></div>
<div class="cn-url mono" id="cnUrl"></div>
<details><summary>More options</summary>
<div id="cnHttpOpts">
<label class="chk"><input type="checkbox" id="cnInspect"> Inspect traffic (Inspector tab)</label>
<label for="cnAuth">Basic auth <span class="hint">user:password</span></label>
<input id="cnAuth" type="text" autocomplete="off" spellcheck="false">
<label for="cnPin">PIN <span class="hint">visitors enter it once</span></label>
<input id="cnPin" type="text" autocomplete="off" spellcheck="false">
<label for="cnAllow">IP allow-list <span class="hint">1.2.3.4,10.0.0.0/8</span></label>
<input id="cnAllow" type="text" autocomplete="off" spellcheck="false">
</div>
<label for="cnTtl">Close automatically after</label>
<select id="cnTtl"><option value="">never</option><option value="30m">30 minutes</option><option value="2h">2 hours</option><option value="8h">8 hours</option><option value="24h">24 hours</option></select>
</details>
<label class="chk"><input type="checkbox" id="cnTok" checked> Put my token in the command</label>
</div>
<div class="cn-out">
<div class="sec-title" style="margin-top:0">2. Where will it run?</div>
<select id="cnOS">
<option value="linux-amd64">Linux (x86-64)</option><option value="linux-arm64">Linux (ARM64)</option>
<option value="darwin-arm64">macOS (Apple silicon)</option><option value="darwin-amd64">macOS (Intel)</option>
<option value="windows-amd64">Windows (PowerShell)</option>
</select>
<div class="sec-title">Install the client <span class="hint">(once)</span></div>
<div class="cn-box"><pre class="mono" id="cnInstall"></pre><button class="btn-sm" id="cnCopyInstall">Copy</button></div>
<div class="sec-title">3. Run this on that machine</div>
<div class="cn-box"><pre class="mono" id="cnCmd"></pre><button class="btn-sm" id="cnCopyCmd">Copy</button></div>
<div class="cn-note" id="cnNote"></div>
<div class="cn-status" id="cnStatus">Waiting for the connection...</div>
</div>
</div>
</div>

<!-- Activity Panel -->
<div class="panel" id="panelActivity">
<div class="panel-bar">
<div class="panel-bar-left"><input class="search-box" id="searchActivity" type="text" placeholder="Filter activity...">
<span class="chips" id="actChips"><button class="chip on" data-lvl="">All</button><button class="chip" data-lvl="warn">Warnings</button><button class="chip" data-kind="auth">Auth</button><button class="chip" data-kind="session">Sessions</button><button class="chip" data-kind="tunnel">Tunnels</button><button class="chip" data-kind="admin">Admin</button><button class="chip" data-kind="server">Server</button></span></div>
<button class="btn-ghost" id="refreshActivity">Refresh <span class="kbd">R</span></button>
</div>
<div class="tbl-wrap">
<table><thead><tr><th>Time</th><th>Level</th><th>Kind</th><th>Account</th><th>Remote</th><th>Event</th></tr></thead>
<tbody id="tbodyActivity"></tbody></table>
</div>
<div class="empty" id="emptyActivity" style="display:none">No activity yet</div>
</div>

<!-- Admin Panel -->
<div class="panel" id="panelAdmin">
<div class="panel-bar"><div class="panel-bar-left"><span class="pill" id="adminStamp">loading...</span></div>
<button class="btn-ghost" id="refreshAdmin">Refresh <span class="kbd">R</span></button></div>
<nav class="adm-nav" id="admNav" aria-label="Admin sections"><a href="#secHealth" data-jump="secHealth">Overview</a><a href="#secCharts" data-jump="secCharts">Last hour</a><a href="#secAccounts" data-jump="secAccounts">Accounts</a><a href="#secTokens" data-jump="secTokens">Tokens</a><a href="#secSessions" data-jump="secSessions">Sessions</a><a href="#secHeld" data-jump="secHeld">Reserved</a><a href="#secCerts" data-jump="secCerts">Certificates</a><a href="#secConfig" data-jump="secConfig">Configuration</a></nav>
<div id="secHealth" class="adm-hero-wrap"><div class="adm-hero" id="admHero"></div></div>
<div class="tiles-label">Traffic</div>
<div class="tiles" id="admTilesTraffic"></div>
<div class="tiles-label">Capacity</div>
<div class="tiles" id="admTilesCap"></div>
<div class="sec-title" id="secCharts">Last hour</div>
<div class="adm-panel">
<div class="adm-panel-h"><div class="seg" id="admChartTabs"><button class="on" data-ct="req">Requests</button><button data-ct="traffic">Traffic</button></div><div class="adm-legend" id="admLegend"></div></div>
<div class="adm-chart" id="admChartBox"></div>
<details class="adm-tbl"><summary>Show the values as a table</summary><div class="tbl-wrap"><table><thead id="admChartHead"></thead><tbody id="admChartRows"></tbody></table></div></details>
</div>
<div class="two">
<div class="adm-panel"><div class="adm-panel-h"><b>Response time</b><span class="adm-sub" id="admLatSub"></span></div><div id="adminLatency"></div></div>
<div class="adm-panel"><div class="adm-panel-h"><b>Responses by status</b><span class="adm-sub" id="admStatSub"></span></div><div id="adminStatus"></div></div>
</div>
<div class="sec-title" id="secAccounts">Accounts</div>
<div class="accts" id="admAccounts"></div>
<div class="sec-title" id="secTokens">Access tokens</div>
<input class="search-box adm-find" type="text" placeholder="Filter tokens..." data-find="tbodyTokens">
<div class="tbl-wrap"><table><thead><tr><th>ID</th><th>Account</th><th>Name</th><th>Role</th><th>Limits</th><th>Created</th><th>Expires</th><th>Status</th><th></th></tr></thead><tbody id="tbodyTokens"></tbody></table></div>
<div class="cn-note" id="tokensOff" style="display:none"></div>
<div class="adm-forms">
<details class="cn-form adm-card" id="tokNew" open><summary>Create a token</summary>
<div class="tok-grid">
<div><label for="tokAccount">Account <span class="hint">new or existing</span></label><input id="tokAccount" type="text" list="tokAccounts" autocomplete="off" spellcheck="false" placeholder="alice"><datalist id="tokAccounts"></datalist></div>
<div><label for="tokName">Label</label><input id="tokName" type="text" autocomplete="off" placeholder="laptop"></div>
<div><label for="tokExpires">Valid for</label><select id="tokExpires"><option value="">forever</option><option value="1h">1 hour</option><option value="24h">1 day</option><option value="7d">7 days</option><option value="30d">30 days</option><option value="90d">90 days</option><option value="365d">1 year</option></select></div>
<div><label for="tokRole">Role</label><select id="tokRole"><option value="">unchanged (new: user)</option><option value="admin">administrator</option><option value="user">regular user</option></select></div>
<div><label for="tokMaxT">Max tunnels <span class="hint">empty = unchanged</span></label><input id="tokMaxT" type="number" min="0"></div>
<div><label for="tokMaxS">Max sessions</label><input id="tokMaxS" type="number" min="0"></div>
<div><label for="tokRate">Tunnel creations / s</label><input id="tokRate" type="number" min="0"></div>
</div>
<p class="cn-note">Every token has its own secret and can be revoked on its own. Account limits and role are shared by all tokens of an account, so setting them here changes them for its other tokens too.</p>
<button class="btn" id="tokCreate">Create token</button>
</details>
<details class="cn-form adm-card" id="pwSet" open><summary>Set a dashboard password</summary>
<div class="tok-grid">
<div><label for="pwAccount">Account <span class="hint">the username for signing in</span></label><input id="pwAccount" type="text" list="tokAccounts" autocomplete="off" spellcheck="false"></div>
<div><label for="pwValue">New password <span class="hint">at least 10 characters</span></label><input id="pwValue" type="password" autocomplete="new-password"></div>
</div>
<p class="cn-note">The account signs in to this dashboard with its name and this password; its role (administrator or regular user) decides what it sees. Setting a new password signs that account out of the dashboard. API tokens keep working.</p>
<button class="btn" id="pwSave">Set password</button>
</details>
</div>
<div class="tok-secret" id="tokSecret" style="display:none"></div>
<div class="sec-title" id="secSessions">All sessions</div>
<input class="search-box adm-find" type="text" placeholder="Filter sessions..." data-find="tbodyAdminSessions">
<div class="tbl-wrap"><table><thead><tr><th>ID</th><th>Account</th><th>Remote</th><th>Connected</th><th>Last heartbeat</th><th>Tunnels</th><th></th></tr></thead><tbody id="tbodyAdminSessions"></tbody></table></div>
<div class="sec-title" id="secHeld">Reserved subdomains and TCP ports (client dropped, waiting for reconnect)</div>
<div class="tbl-wrap"><table><thead><tr><th>Subdomain / tcp:port</th><th>Account</th><th>Held for</th></tr></thead><tbody id="tbodyHeld"></tbody></table></div>
<div class="sec-title" id="secCerts">Certificates</div>
<div class="tbl-wrap"><table><thead><tr><th>Host</th><th>Issuer</th><th>Expires</th><th>Days left</th></tr></thead><tbody id="tbodyCerts"></tbody></table></div>
<div class="sec-title" id="secConfig">Configuration in effect</div>
<div class="cards" id="adminConfig"></div>
</div>
</div>

<!-- Login Overlay -->
<div class="overlay" id="loginOverlay">
<div class="login-box">
<h2>WireRift</h2>
<div class="sub" id="loginSub">Sign in with your username and password</div>
<div id="loginPw">
<div class="field">
<label for="userInput">Username</label>
<input type="text" id="userInput" placeholder="account name" autocomplete="username" spellcheck="false">
</div>
<div class="field">
<label for="passInput">Password</label>
<input type="password" id="passInput" placeholder="password" autocomplete="current-password">
</div>
</div>
<div id="loginTk" style="display:none">
<div class="field">
<label for="tokenInput">API Token</label>
<input type="password" id="tokenInput" placeholder="Enter your API token" autocomplete="off">
</div>
</div>
<button class="btn" id="loginBtn" style="width:100%">Sign in</button>
<div class="login-err" id="loginErr"></div>
<div style="text-align:center;margin-top:.5rem"><a href="#" id="loginSwitch" style="font-size:.8125rem;color:var(--ac)">Use an API token instead</a></div>
</div>
</div>

<script>
(function(){
"use strict";

/* -- Helpers ------------------------------------------------ */
var $ = function(id){ return document.getElementById(id); };
var qs = function(sel, ctx){ return (ctx||document).querySelector(sel); };
var qsa = function(sel, ctx){ return (ctx||document).querySelectorAll(sel); };

/* -- State -------------------------------------------------- */
var apiToken = '';
var currentTab = 'tunnels';
var statsInterval = null;
var reqInterval = null;
var uptimeBase = 0;
var uptimeRef = 0;
var uptimeTimer = null;
var animBytesIn = {current:0, target:0, el:null};
var animBytesOut = {current:0, target:0, el:null};
var animFrame = null;
var tunnelsCache = [];
var sessionsCache = [];
var requestsCache = [], inspClass = '';
var SLOW_NS = 500e6; // the API's duration_ms field holds nanoseconds

/* -- Theme -------------------------------------------------- */
function initTheme(){
    var saved = null;
    try { saved = localStorage.getItem('wr_th'); } catch(e){}
    if(!saved) saved = 'dark';
    document.documentElement.setAttribute('data-theme', saved);
    updateThemeIcon(saved);
}
function toggleTheme(){
    var cur = document.documentElement.getAttribute('data-theme');
    var next = cur === 'dark' ? 'light' : 'dark';
    document.documentElement.setAttribute('data-theme', next);
    try { localStorage.setItem('wr_th', next); } catch(e){}
    updateThemeIcon(next);
}
function updateThemeIcon(theme){
    $('themeBtn').innerHTML = theme === 'dark' ? '&#9790;' : '&#9728;';
}

/* -- Toast -------------------------------------------------- */
function toast(msg, type){
    type = type || 'info';
    var el = document.createElement('div');
    el.className = 'toast toast--' + type;
    el.textContent = msg;
    $('toasts').appendChild(el);
    setTimeout(function(){ el.classList.add('show'); }, 20);
    setTimeout(function(){
        el.classList.remove('show');
        el.classList.add('hide');
        setTimeout(function(){ if(el.parentNode) el.parentNode.removeChild(el); }, 350);
    }, 3000);
}

/* -- Auth --------------------------------------------------- */
function showLogin(){
    $('loginOverlay').classList.add('show');
    $('app').style.display = 'none';
    setTimeout(function(){ $(loginByToken ? 'tokenInput' : 'userInput').focus(); }, 100);
}
function hideLogin(){
    $('loginOverlay').classList.remove('show');
    $('app').style.display = 'block';
}
// stopPolling ends every background refresh. A rejected session must not keep
// polling: each failed request counts against the sign-in lockout of the visitor's IP.
function stopPolling(){
    var had = !!(statsInterval || reqInterval);
    if(statsInterval){ clearInterval(statsInterval); statsInterval = null; }
    if(reqInterval){ clearInterval(reqInterval); reqInterval = null; }
    if(adminInterval){ clearInterval(adminInterval); adminInterval = null; }
    if(cnTimer){ clearInterval(cnTimer); cnTimer = null; }
    if(had){
        try { sessionStorage.removeItem('wr_t'); } catch(e){}
        apiToken = '';
        $('loginErr').textContent = 'Your session ended, sign in again';
        showLogin();
    }
}
function logout(){
    if(apiToken.indexOf('wrs_') === 0){ fetch('/api/logout', {method: 'POST', headers: {'Authorization': 'Bearer ' + apiToken}}).catch(function(){}); }
    try { sessionStorage.removeItem('wr_t'); } catch(e){}
    apiToken = '';
    if(statsInterval){ clearInterval(statsInterval); statsInterval = null; }
    if(reqInterval){ clearInterval(reqInterval); reqInterval = null; }
    if(uptimeTimer){ clearInterval(uptimeTimer); uptimeTimer = null; }
    if(animFrame){ cancelAnimationFrame(animFrame); animFrame = null; }
    showLogin();
}
var loginByToken = false;
function setLoginMode(tk){
    loginByToken = tk;
    $('loginPw').style.display = tk ? 'none' : '';
    $('loginTk').style.display = tk ? '' : 'none';
    $('loginSub').textContent = tk ? 'Enter your API token to authenticate' : 'Sign in with your username and password';
    $('loginSwitch').textContent = tk ? 'Use a username and password instead' : 'Use an API token instead';
    $('loginBtn').textContent = tk ? 'Authenticate' : 'Sign in';
    $('loginErr').textContent = '';
    setTimeout(function(){ $(tk ? 'tokenInput' : 'userInput').focus(); }, 50);
}
function doLogin(){
    $('loginErr').textContent = '';
    if(loginByToken){
        var val = $('tokenInput').value.trim();
        if(!val){ $('loginErr').textContent = 'Please enter a token'; return; }
        apiToken = val;
        verifyAndLoad();
        return;
    }
    var u = $('userInput').value.trim(), pw = $('passInput').value;
    if(!u || !pw){ $('loginErr').textContent = 'Enter your username and password'; return; }
    fetch('/api/login', {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({username: u, password: pw})})
    .then(function(r){ return r.json().catch(function(){ return {}; }).then(function(j){
        if(!r.ok) throw new Error(r.status === 429 ? 'Too many failed attempts, wait a few minutes' : (j.error || 'Sign-in failed'));
        return j;
    }); })
    .then(function(j){ $('passInput').value = ''; apiToken = j.token; verifyAndLoad(); })
    .catch(function(e){ $('loginErr').textContent = e.message === 'Failed to fetch' ? 'Connection failed' : e.message; });
}

function verifyAndLoad(){
    apiFetch('/api/stats').then(function(s){
        try { sessionStorage.setItem('wr_t', apiToken); } catch(e){}
        hideLogin();
        $('authBtn').textContent = 'Logout';
        $('authBtn').onclick = logout;
        processStats(s);
        loadTunnels();
        loadSessions();
        loadRequests();
        if(statsInterval) clearInterval(statsInterval);
        statsInterval = setInterval(function(){ loadStats(); loadTunnels(); loadSessions(); }, 5000);
        if(reqInterval) clearInterval(reqInterval);
        reqInterval = setInterval(loadRequests, 2000);
        startByteAnimation();
        initRoles();
        toast('Authenticated successfully', 'ok');
    }).catch(function(e){
        try { sessionStorage.removeItem('wr_t'); } catch(ex){}
        $('loginErr').textContent = e.message === 'Unauthorized' ? (loginByToken ? 'Invalid token' : 'Session rejected, sign in again') : 'Connection failed';
        showLogin();
    });
}

/* -- API ---------------------------------------------------- */
function apiFetch(path, opts){
    opts = opts || {};
    var headers = { 'Authorization': 'Bearer ' + apiToken };
    if(opts.method === 'POST'){
        headers['Content-Type'] = 'application/json';
    }
    return fetch(path, {
        method: opts.method || 'GET',
        headers: headers,
        body: opts.body || null
    }).then(function(r){
        if(r.status === 401){ stopPolling(); throw new Error('Unauthorized'); }
        if(!r.ok) throw new Error('API error ' + r.status);
        var ct = r.headers.get('content-type') || '';
        if(ct.indexOf('application/json') !== -1) return r.json();
        return r.text();
    });
}

/* -- Format ------------------------------------------------- */
function fmtBytes(b){
    if(!b || b === 0) return '0 B';
    var k = 1024;
    var sizes = ['B','KB','MB','GB','TB','PB'];
    var i = Math.floor(Math.log(b) / Math.log(k));
    if(i >= sizes.length) i = sizes.length - 1;
    return (b / Math.pow(k, i)).toFixed(1) + ' ' + sizes[i];
}
function fmtTime(t){
    if(!t) return '-';
    var d = new Date(t);
    var hh = String(d.getHours()).length < 2 ? '0' + d.getHours() : '' + d.getHours();
    var mm = String(d.getMinutes()).length < 2 ? '0' + d.getMinutes() : '' + d.getMinutes();
    var ss = String(d.getSeconds()).length < 2 ? '0' + d.getSeconds() : '' + d.getSeconds();
    return hh + ':' + mm + ':' + ss;
}
function fmtTimeDate(t){
    if(!t) return '-';
    return new Date(t).toLocaleString();
}
function fmtDuration(ns){
    if(!ns && ns !== 0) return '-';
    var ms = ns / 1000000;
    if(ms < 1) return (ns / 1000).toFixed(0) + 'us';
    if(ms < 1000) return ms.toFixed(1) + 'ms';
    return (ms / 1000).toFixed(2) + 's';
}
function fmtUptime(sec){
    if(!sec && sec !== 0) return '-';
    sec = Math.floor(sec);
    if(sec < 60) return sec + 's';
    if(sec < 3600) return Math.floor(sec / 60) + 'm ' + (sec % 60) + 's';
    var h = Math.floor(sec / 3600);
    var m = Math.floor((sec % 3600) / 60);
    if(h < 24) return h + 'h ' + m + 'm';
    var d = Math.floor(h / 24);
    return d + 'd ' + (h % 24) + 'h';
}
function fmtAgo(t){
    if(!t) return '-';
    var diff = Math.floor((Date.now() - new Date(t).getTime()) / 1000);
    if(diff < 0) diff = 0;
    if(diff < 5) return 'just now';
    if(diff < 60) return diff + 's ago';
    if(diff < 3600) return Math.floor(diff / 60) + 'm ago';
    return Math.floor(diff / 3600) + 'h ago';
}
function escHtml(s){
    if(!s) return '';
    return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

/* -- JSON Syntax Highlighting ------------------------------- */
function highlightJson(str){
    if(!str) return '';
    try {
        var obj = typeof str === 'string' ? JSON.parse(str) : str;
        return colorize(JSON.stringify(obj, null, 2));
    } catch(e){
        return escHtml(str);
    }
}
function colorize(json){
    var result = '';
    var inStr = false;
    var strChar = '';
    var i = 0;
    var len = json.length;
    var buf = '';

    while(i < len){
        var ch = json[i];
        if(inStr){
            buf += ch;
            if(ch === '\\' && i + 1 < len){ buf += json[i+1]; i += 2; continue; }
            if(ch === strChar){
                inStr = false;
                var rest = json.substring(i+1).replace(/^\s*/, '');
                if(rest.charAt(0) === ':'){
                    result += '<span class="json-key">' + escHtml(buf) + '</span>';
                } else {
                    result += '<span class="json-str">' + escHtml(buf) + '</span>';
                }
                buf = '';
            }
            i++;
            continue;
        }
        if(ch === '"' || ch === "'"){
            inStr = true;
            strChar = ch;
            buf = ch;
            i++;
            continue;
        }
        if((ch >= '0' && ch <= '9') || ch === '-'){
            var num = '';
            while(i < len && (json[i] >= '0' && json[i] <= '9' || json[i] === '.' || json[i] === '-' || json[i] === 'e' || json[i] === 'E' || json[i] === '+')){
                num += json[i]; i++;
            }
            result += '<span class="json-num">' + escHtml(num) + '</span>';
            continue;
        }
        if(json.substring(i, i+4) === 'true'){
            result += '<span class="json-bool">true</span>'; i += 4; continue;
        }
        if(json.substring(i, i+5) === 'false'){
            result += '<span class="json-bool">false</span>'; i += 5; continue;
        }
        if(json.substring(i, i+4) === 'null'){
            result += '<span class="json-null">null</span>'; i += 4; continue;
        }
        if(ch === '{' || ch === '}' || ch === '[' || ch === ']'){
            result += '<span class="json-brace">' + ch + '</span>';
            i++; continue;
        }
        result += escHtml(ch);
        i++;
    }
    return result;
}

/* -- Animated Byte Counters --------------------------------- */
function startByteAnimation(){
    animBytesIn.el = $('sBytesIn');
    animBytesOut.el = $('sBytesOut');
    if(animFrame) cancelAnimationFrame(animFrame);
    function tick(){
        var changed = false;
        if(Math.abs(animBytesIn.current - animBytesIn.target) > 1){
            animBytesIn.current += (animBytesIn.target - animBytesIn.current) * 0.12;
            if(Math.abs(animBytesIn.current - animBytesIn.target) < 2) animBytesIn.current = animBytesIn.target;
            animBytesIn.el.textContent = fmtBytes(Math.round(animBytesIn.current));
            changed = true;
        }
        if(Math.abs(animBytesOut.current - animBytesOut.target) > 1){
            animBytesOut.current += (animBytesOut.target - animBytesOut.current) * 0.12;
            if(Math.abs(animBytesOut.current - animBytesOut.target) < 2) animBytesOut.current = animBytesOut.target;
            animBytesOut.el.textContent = fmtBytes(Math.round(animBytesOut.current));
            changed = true;
        }
        animFrame = requestAnimationFrame(tick);
    }
    tick();
}

/* -- Live Uptime Counter ------------------------------------ */
function startUptimeCounter(baseSec){
    uptimeBase = baseSec;
    uptimeRef = Date.now() / 1000;
    if(uptimeTimer) clearInterval(uptimeTimer);
    updateUptimeDisplay();
    uptimeTimer = setInterval(updateUptimeDisplay, 1000);
}
function updateUptimeDisplay(){
    var elapsed = (Date.now() / 1000) - uptimeRef;
    $('sUptime').textContent = fmtUptime(uptimeBase + elapsed);
}

/* -- Stats -------------------------------------------------- */
function processStats(s){
    $('sTunnels').textContent = s.active_tunnels || 0;
    $('sSessions').textContent = s.active_sessions || 0;

    var bi = s.bytes_in || 0;
    var bo = s.bytes_out || 0;
    animBytesIn.target = bi;
    animBytesOut.target = bo;
    if(animBytesIn.current === 0 && bi > 0){
        animBytesIn.current = bi;
        $('sBytesIn').textContent = fmtBytes(bi);
    }
    if(animBytesOut.current === 0 && bo > 0){
        animBytesOut.current = bo;
        $('sBytesOut').textContent = fmtBytes(bo);
    }

    startUptimeCounter(s.uptime || 0);

    $('badgeTunnels').textContent = s.active_tunnels || 0;
    $('badgeSessions').textContent = s.active_sessions || 0;
}
function loadStats(){
    apiFetch('/api/stats').then(processStats).catch(function(e){
        if(e.message === 'Unauthorized') logout();
    });
}

/* -- Tunnels ------------------------------------------------ */
function loadTunnels(){
    apiFetch('/api/tunnels').then(function(list){
        tunnelsCache = list || [];
        renderTunnels();
    }).catch(function(e){
        if(e.message === 'Unauthorized') logout();
    });
}
function renderTunnels(){
    var filter = ($('searchTunnels').value || '').toLowerCase();
    var tbody = $('tbodyTunnels');
    var items = tunnelsCache;
    if(filter){
        items = items.filter(function(t){
            return (t.id && t.id.toLowerCase().indexOf(filter) !== -1) ||
                   (t.type && t.type.toLowerCase().indexOf(filter) !== -1) ||
                   (t.url && t.url.toLowerCase().indexOf(filter) !== -1) ||
                   (t.target && t.target.toLowerCase().indexOf(filter) !== -1);
        });
    }
    if(!items.length){
        tbody.textContent = '';
        tbody.removeAttribute('data-sig');
        $('emptyTunnels').style.display = 'block';
        return;
    }
    $('emptyTunnels').style.display = 'none';
    var sig = items.map(function(t){ return t.id + t.status + Math.floor(Date.now() / 30000); }).join('|');
    if(tbody.getAttribute('data-sig') === sig) return;
    tbody.setAttribute('data-sig', sig);

    var frag = document.createDocumentFragment();
    for(var i = 0; i < items.length; i++){
        var t = items[i];
        var tr = document.createElement('tr');
        var c1 = document.createElement('td');
        var sp1 = document.createElement('span'); sp1.className = 'mono'; sp1.textContent = t.id || '-'; c1.appendChild(sp1);
        tr.appendChild(c1);
        var c2 = document.createElement('td');
        var typ = document.createElement('span'); typ.className = 'pill ' + (t.type === 'tcp' ? 'warn' : 'ok'); typ.textContent = (t.type || '-').toUpperCase();
        c2.appendChild(typ); tr.appendChild(c2);
        var c3 = document.createElement('td');
        var sp3;
        if(t.type === 'http' && /^https?:\/\//.test(t.url || '')){
            sp3 = document.createElement('a'); sp3.href = t.url; sp3.target = '_blank'; sp3.rel = 'noopener noreferrer'; sp3.className = 'mono lnk';
            sp3.textContent = t.url;
        } else {
            sp3 = document.createElement('span'); sp3.className = 'mono';
            sp3.textContent = t.type === 'http' ? (t.url || '-') : 'Port ' + (t.port || '-');
        }
        c3.appendChild(sp3); tr.appendChild(c3);
        var c4 = document.createElement('td');
        var sp4 = document.createElement('span'); sp4.className = 'mono'; sp4.textContent = t.target || '-'; c4.appendChild(sp4);
        tr.appendChild(c4);
        var c5 = document.createElement('td');
        if(t.allowed_ips && t.allowed_ips.length){ var b1 = document.createElement('span'); b1.className='badge badge--ip'; b1.textContent='IP'; c5.appendChild(b1); c5.appendChild(document.createTextNode(' ')); }
        if(t.has_pin){ var b2 = document.createElement('span'); b2.className='badge badge--pin'; b2.textContent='PIN'; c5.appendChild(b2); c5.appendChild(document.createTextNode(' ')); }
        if(t.has_auth){ var b3 = document.createElement('span'); b3.className='badge badge--auth'; b3.textContent='AUTH'; c5.appendChild(b3); c5.appendChild(document.createTextNode(' ')); }
        if(t.inspect){ var b4 = document.createElement('span'); b4.className='badge badge--inspect'; b4.textContent='INSPECT'; c5.appendChild(b4); }
        if(!c5.childNodes.length) c5.textContent = '-';
        tr.appendChild(c5);
        var c6 = document.createElement('td');
        var dot = document.createElement('span'); dot.className = 'status-dot'; dot.textContent = 'Active';
        c6.appendChild(dot); tr.appendChild(c6);
        var c7 = document.createElement('td'); c7.textContent = fmtAgo(t.created_at); c7.title = fmtTimeDate(t.created_at); tr.appendChild(c7);
        var c8 = document.createElement('td');
        if(t.url){
            var cpBtn = document.createElement('button'); cpBtn.className = 'btn-sm'; cpBtn.textContent = 'Copy';
            cpBtn.setAttribute('data-copy', t.url);
            cpBtn.onclick = function(){ copyUrl(this); };
            c8.appendChild(cpBtn);
        }
        tr.appendChild(c8);
        frag.appendChild(tr);
    }
    tbody.textContent = '';
    tbody.appendChild(frag);
}

/* -- Sessions ----------------------------------------------- */
function loadSessions(){
    apiFetch('/api/sessions').then(function(list){
        sessionsCache = list || [];
        renderSessions();
    }).catch(function(e){
        if(e.message === 'Unauthorized') logout();
    });
}
function renderSessions(){
    var filter = ($('searchSessions').value || '').toLowerCase();
    var tbody = $('tbodySessions');
    var items = sessionsCache;
    if(filter){
        items = items.filter(function(s){
            return (s.id && s.id.toLowerCase().indexOf(filter) !== -1) ||
                   (s.account_id && s.account_id.toLowerCase().indexOf(filter) !== -1) ||
                   (s.remote_addr && s.remote_addr.toLowerCase().indexOf(filter) !== -1);
        });
    }
    if(!items.length){
        tbody.textContent = '';
        tbody.removeAttribute('data-sig');
        $('emptySessions').style.display = 'block';
        return;
    }
    $('emptySessions').style.display = 'none';

    var sig = items.map(function(s){ return s.id + s.tunnel_count + Math.floor(s.uptime_seconds || 0); }).join('|');
    if(tbody.getAttribute('data-sig') === sig) return;
    tbody.setAttribute('data-sig', sig);

    var frag = document.createDocumentFragment();
    for(var i = 0; i < items.length; i++){
        var s = items[i];
        var tr = document.createElement('tr');
        tr.className = 'insp-row';
        var c1 = document.createElement('td');
        var sp1 = document.createElement('span'); sp1.className = 'mono'; sp1.textContent = s.id || '-'; c1.appendChild(sp1);
        tr.appendChild(c1);
        var c2 = document.createElement('td'); c2.textContent = s.account_id || 'dev'; tr.appendChild(c2);
        var c3 = document.createElement('td');
        var sp3 = document.createElement('span'); sp3.className = 'mono'; sp3.textContent = s.remote_addr || '-'; c3.appendChild(sp3);
        tr.appendChild(c3);
        var c4 = document.createElement('td'); c4.textContent = fmtTimeDate(s.connected_at); tr.appendChild(c4);
        var c5 = document.createElement('td');
        if(s.last_heartbeat && s.last_heartbeat !== '0001-01-01T00:00:00Z'){
            var hbAge = (Date.now() - new Date(s.last_heartbeat).getTime()) / 1000;
            var hp = document.createElement('span');
            hp.className = 'pill ' + (hbAge > 90 ? 'bad' : hbAge > 45 ? 'warn' : 'ok');
            hp.textContent = fmtAgo(s.last_heartbeat);
            c5.appendChild(hp);
            c5.title = fmtTimeDate(s.last_heartbeat);
        } else { c5.textContent = '-'; }
        tr.appendChild(c5);
        var c6 = document.createElement('td'); c6.textContent = fmtUptime(s.uptime_seconds || 0); tr.appendChild(c6);
        var c7 = document.createElement('td'); var tp = document.createElement('span'); tp.className = 'pill' + (s.tunnel_count ? ' ok' : ''); tp.textContent = s.tunnel_count || 0; c7.appendChild(tp); tr.appendChild(c7);

        /* detail row */
        var detailTr = document.createElement('tr');
        detailTr.className = 'sess-detail-row';
        var detailTd = document.createElement('td');
        detailTd.colSpan = 7;
        detailTd.className = 'sess-detail-cell';
        var dl = document.createElement('dl');
        dl.className = 'sess-kv';
        addKV(dl, 'Session ID', s.id);
        addKV(dl, 'Account', s.account_id || 'dev');
        addKV(dl, 'Remote Address', s.remote_addr || '-');
        addKV(dl, 'Connected At', fmtTimeDate(s.connected_at));
        addKV(dl, 'Last Seen', fmtTimeDate(s.last_seen));
        addKV(dl, 'Last Heartbeat', s.last_heartbeat && s.last_heartbeat !== '0001-01-01T00:00:00Z' ? fmtAgo(s.last_heartbeat) + ' ago' : 'N/A');
        addKV(dl, 'Session Uptime', fmtUptime(s.uptime_seconds || 0));
        addKV(dl, 'Active Tunnels', String(s.tunnel_count || 0));
        detailTd.appendChild(dl);
        detailTr.appendChild(detailTd);

        (function(dtr){ tr.onclick = function(){ dtr.classList.toggle('open'); }; })(detailTr);

        frag.appendChild(tr);
        frag.appendChild(detailTr);
    }
    tbody.textContent = '';
    tbody.appendChild(frag);
}
function addKV(dl, key, val){
    var dt = document.createElement('dt'); dt.textContent = key; dl.appendChild(dt);
    var dd = document.createElement('dd'); dd.textContent = val; dl.appendChild(dd);
}

/* -- Requests / Inspector ----------------------------------- */
function loadRequests(){
    var tid = $('tunnelFilter').value;
    var url = '/api/requests?limit=50';
    if(tid) url += '&tunnel_id=' + encodeURIComponent(tid);
    apiFetch(url).then(function(list){
        requestsCache = list || [];
        $('badgeInspector').textContent = requestsCache.length;
        renderRequests();
        updateTunnelFilter(requestsCache);
    }).catch(function(e){
        if(e.message === 'Unauthorized') logout();
    });
}
function renderRequests(){
    var filter = ($('searchInspector').value || '').toLowerCase();
    var tbody = $('tbodyRequests');
    var items = requestsCache;
    if(inspClass){
        items = items.filter(function(r){
            return inspClass === 'slow' ? (r.duration_ms || 0) >= SLOW_NS : String(Math.floor((r.status_code || 0) / 100)) === inspClass;
        });
    }
    if(filter){
        items = items.filter(function(r){
            return (r.path && r.path.toLowerCase().indexOf(filter) !== -1) ||
                   (r.method && r.method.toLowerCase().indexOf(filter) !== -1) ||
                   (r.client_ip && r.client_ip.indexOf(filter) !== -1) ||
                   (String(r.status_code).indexOf(filter) !== -1);
        });
    }
    if(!items.length){
        tbody.textContent = '';
        tbody.removeAttribute('data-sig');
        $('emptyRequests').style.display = 'block';
        return;
    }
    $('emptyRequests').style.display = 'none';

    var sig = items.map(function(r){ return r.id; }).join('|');
    if(tbody.getAttribute('data-sig') === sig && !filter && !inspClass) return;
    tbody.setAttribute('data-sig', sig);

    var maxDur = 1;
    for(var mi = 0; mi < items.length; mi++) if((items[mi].duration_ms || 0) > maxDur) maxDur = items[mi].duration_ms;
    var frag = document.createDocumentFragment();
    for(var idx = 0; idx < items.length; idx++){
        var r = items[idx];
        var sc = r.status_code || 0;
        var scClass = sc < 300 ? 'sc-2' : sc < 400 ? 'sc-3' : sc < 500 ? 'sc-4' : 'sc-5';

        var tr = document.createElement('tr');
        tr.className = 'insp-row';
        var c1 = document.createElement('td'); c1.textContent = fmtTime(r.timestamp); tr.appendChild(c1);
        var c2 = document.createElement('td');
        var mSpan = document.createElement('span'); mSpan.className = 'method method-' + (r.method || 'GET'); mSpan.textContent = r.method || 'GET';
        c2.appendChild(mSpan); tr.appendChild(c2);
        var c3 = document.createElement('td');
        var sp3 = document.createElement('span'); sp3.className = 'mono'; sp3.textContent = r.path || '/'; c3.appendChild(sp3);
        tr.appendChild(c3);
        var c4 = document.createElement('td');
        var scSpan = document.createElement('span'); scSpan.className = 'sc ' + scClass; scSpan.textContent = sc;
        c4.appendChild(scSpan); tr.appendChild(c4);
        var c5 = document.createElement('td'); c5.className = 'dur-cell';
        var durTxt = document.createElement('span'); durTxt.className = 'dur-t'; durTxt.textContent = fmtDuration(r.duration_ms); c5.appendChild(durTxt);
        var durBar = document.createElement('i'); durBar.className = 'dur' + ((r.duration_ms || 0) >= SLOW_NS ? ' slow' : '');
        var durFill = document.createElement('b'); durFill.style.width = Math.max(2, Math.min(100, (r.duration_ms || 0) / maxDur * 100)).toFixed(0) + '%';
        durBar.appendChild(durFill); c5.appendChild(durBar); tr.appendChild(c5);
        var c6 = document.createElement('td');
        var sp6 = document.createElement('span'); sp6.className = 'mono'; sp6.textContent = r.client_ip || '-'; c6.appendChild(sp6);
        tr.appendChild(c6);
        var c7 = document.createElement('td');
        c7.style.whiteSpace = 'nowrap';
        var rpBtn = document.createElement('button'); rpBtn.className = 'btn-sm'; rpBtn.textContent = 'Replay';
        (function(rid){ rpBtn.onclick = function(e){ e.stopPropagation(); replayReq(rid); }; })(r.id);
        c7.appendChild(rpBtn);
        c7.appendChild(document.createTextNode(' '));
        var curlBtn = document.createElement('button'); curlBtn.className = 'btn-sm'; curlBtn.textContent = 'cURL';
        (function(ix){ curlBtn.onclick = function(e){ e.stopPropagation(); exportCurl(ix); }; })(idx);
        c7.appendChild(curlBtn);
        tr.appendChild(c7);

        /* detail row */
        var detailTr = document.createElement('tr');
        detailTr.className = 'detail-row';
        var detailTd = document.createElement('td');
        detailTd.colSpan = 7;
        detailTd.className = 'detail-cell';
        var inner = document.createElement('div');
        inner.className = 'detail-inner';

        /* headers side by side */
        var cols = document.createElement('div'); cols.className = 'detail-cols';
        cols.appendChild(buildSection('Request Headers', formatHeadersText(r.req_headers)));
        cols.appendChild(buildSection('Response Headers', formatHeadersText(r.res_headers)));
        inner.appendChild(cols);

        /* bodies */
        if(r.req_body){
            var reqSec = document.createElement('div'); reqSec.className = 'detail-section';
            var reqTitle = document.createElement('div'); reqTitle.className = 'detail-section-title'; reqTitle.textContent = 'Request Body';
            reqSec.appendChild(reqTitle);
            var reqPre = document.createElement('pre'); reqPre.innerHTML = highlightJson(r.req_body);
            reqSec.appendChild(reqPre);
            inner.appendChild(reqSec);
        }
        if(r.res_body){
            var resSec = document.createElement('div'); resSec.className = 'detail-section';
            var resTitle = document.createElement('div'); resTitle.className = 'detail-section-title'; resTitle.textContent = 'Response Body';
            resSec.appendChild(resTitle);
            var resPre = document.createElement('pre'); resPre.innerHTML = highlightJson(r.res_body);
            resSec.appendChild(resPre);
            inner.appendChild(resSec);
        }

        /* detail actions */
        var acts = document.createElement('div'); acts.className = 'detail-actions';
        var rpBtn2 = document.createElement('button'); rpBtn2.className = 'btn-sm'; rpBtn2.textContent = 'Replay Request';
        (function(rid){ rpBtn2.onclick = function(){ replayReq(rid); }; })(r.id);
        acts.appendChild(rpBtn2);
        var curlBtn2 = document.createElement('button'); curlBtn2.className = 'btn-sm'; curlBtn2.textContent = 'Export cURL';
        (function(ix){ curlBtn2.onclick = function(){ exportCurl(ix); }; })(idx);
        acts.appendChild(curlBtn2);
        inner.appendChild(acts);

        detailTd.appendChild(inner);
        detailTr.appendChild(detailTd);

        (function(dtr){ tr.onclick = function(){ dtr.classList.toggle('open'); }; })(detailTr);

        frag.appendChild(tr);
        frag.appendChild(detailTr);
    }
    tbody.textContent = '';
    tbody.appendChild(frag);
}
function buildSection(title, content){
    var sec = document.createElement('div'); sec.className = 'detail-section';
    var ttl = document.createElement('div'); ttl.className = 'detail-section-title'; ttl.textContent = title;
    sec.appendChild(ttl);
    var pre = document.createElement('pre');
    pre.innerHTML = content;
    sec.appendChild(pre);
    return sec;
}
function formatHeadersText(hdrs){
    if(!hdrs) return '<span style="color:var(--tx-2)">(none)</span>';
    var keys = Object.keys(hdrs);
    if(!keys.length) return '<span style="color:var(--tx-2)">(none)</span>';
    var out = '';
    for(var i = 0; i < keys.length; i++){
        out += '<span class="json-key">' + escHtml(keys[i]) + '</span>: ' + escHtml(hdrs[keys[i]]);
        if(i < keys.length - 1) out += '\n';
    }
    return out;
}

/* -- Tunnel Filter Dropdown --------------------------------- */
function updateTunnelFilter(logs){
    var sel = $('tunnelFilter');
    var current = sel.value;
    var ids = {};
    for(var i = 0; i < logs.length; i++){
        if(logs[i].tunnel_id) ids[logs[i].tunnel_id] = true;
    }
    var existing = {};
    for(var j = 1; j < sel.options.length; j++) existing[sel.options[j].value] = true;
    var idKeys = Object.keys(ids);
    for(var k = 0; k < idKeys.length; k++){
        if(!existing[idKeys[k]]){
            var opt = document.createElement('option');
            opt.value = idKeys[k];
            opt.textContent = idKeys[k];
            sel.appendChild(opt);
        }
    }
    sel.value = current;
}

/* -- cURL Export -------------------------------------------- */
function shSingle(s){
    // Quote for POSIX shell: embedded single quotes become '\'' (end the
    // quoted string, an escaped quote, reopen). Keeps attacker-controlled
    // header values and paths from breaking out into extra shell commands.
    return "'" + String(s).replace(/'/g, "'\\''") + "'";
}
function exportCurl(index){
    var r = requestsCache[index];
    if(!r){ toast('Request not found', 'er'); return; }
    var cmd = 'curl -X ' + shSingle(r.method || 'GET');
    if(r.req_headers){
        var hKeys = Object.keys(r.req_headers);
        for(var i = 0; i < hKeys.length; i++){
            cmd += ' -H ' + shSingle(hKeys[i] + ': ' + r.req_headers[hKeys[i]]);
        }
    }
    if(r.req_body){
        var body = typeof r.req_body === 'string' ? r.req_body : JSON.stringify(r.req_body);
        cmd += ' -d ' + shSingle(body);
    }
    var replayUrl = r.path || '/';
    if(r.query){
        replayUrl += (replayUrl.indexOf('?') >= 0 ? '&' : '?') + r.query;
    }
    cmd += ' ' + shSingle(replayUrl);
    copyToClipboard(cmd);
    toast('cURL command copied', 'ok');
}

/* -- Replay ------------------------------------------------- */
function replayReq(id){
    apiFetch('/api/requests/' + id + '/replay', { method: 'POST' }).then(function(){
        toast('Request replayed', 'ok');
        loadRequests();
    }).catch(function(){
        toast('Replay failed', 'er');
    });
}

/* -- Copy to Clipboard -------------------------------------- */
function copyToClipboard(text){
    if(navigator.clipboard && navigator.clipboard.writeText){
        navigator.clipboard.writeText(text);
    } else {
        var ta = document.createElement('textarea');
        ta.value = text;
        ta.style.position = 'fixed';
        ta.style.left = '-9999px';
        document.body.appendChild(ta);
        ta.select();
        try { document.execCommand('copy'); } catch(e){}
        document.body.removeChild(ta);
    }
}
function copyUrl(btn){
    var url = btn.getAttribute('data-copy');
    copyToClipboard(url);
    var orig = btn.textContent;
    btn.textContent = 'Copied!';
    btn.classList.add('copy-ok');
    setTimeout(function(){
        btn.textContent = orig;
        btn.classList.remove('copy-ok');
    }, 1200);
    toast('URL copied to clipboard', 'ok');
}

/* -- Tab Switching ------------------------------------------ */
function switchTab(name){
    currentTab = name;
    // The Admin tab has its own health cards; the top counters would only repeat them.
    qs('.stats').style.display = name === 'admin' ? 'none' : '';
    if(name === 'connect' && typeof cnRender === 'function') cnRender();
    var tabs = qsa('.tab');
    for(var i = 0; i < tabs.length; i++){
        var t = tabs[i];
        if(t.getAttribute('data-tab') === name) t.classList.add('active');
        else t.classList.remove('active');
    }
    var panels = qsa('.panel');
    for(var j = 0; j < panels.length; j++){
        var p = panels[j];
        if(p.id === 'panel' + name.charAt(0).toUpperCase() + name.slice(1)) p.classList.add('active');
        else p.classList.remove('active');
    }
}



/* -- Connect ------------------------------------------------ */
var cnInfo = null, cnBase = {}, cnTimer = null, cnType = 'http';
var CN_REPO = 'https://github.com/WireRift/WireRift/releases/latest/download/';
function cnQuote(v, win, force){
    if(!force && /^[A-Za-z0-9_.:\/@%+=,-]+$/.test(v)) return v;
    if(win) return "'" + v.replace(/'/g, "''") + "'";
    return "'" + v.replace(/'/g, "'\\''") + "'";
}
function cnMaskToken(t){ return t.length > 6 ? t.slice(0, 4) + '...' : '...'; }
/* o: {type, port, sub, inspect, auth, pin, allow, ttl, server, token, os}; returns the shell text */
function cnBuild(o){
    var win = o.os.indexOf('windows') === 0;
    var args = [win ? '.\\wirerift.exe' : './wirerift', o.type];
    if(o.type === 'http'){
        if(o.inspect) args.push('-inspect');
        if(o.auth) args.push('-auth', cnQuote(o.auth, win));
        if(o.pin) args.push('-pin', cnQuote(o.pin, win));
        if(o.allow) args.push('-whitelist', cnQuote(o.allow, win));
    }
    if(o.ttl) args.push('-ttl', o.ttl);
    args.push('-server', cnQuote(o.server, win), String(o.port));
    if(o.type === 'http' && o.sub) args.push(o.sub);
    var tok = o.token || 'YOUR_TOKEN';
    if(win) return "$env:WIRERIFT_TOKEN = " + cnQuote(tok, true, true) + "\n" + args.join(' ');
    return 'WIRERIFT_TOKEN=' + cnQuote(tok, false, true) + ' ' + args.join(' ');
}
function cnInstallText(os){
    var asset = 'wirerift-' + os + (os.indexOf('windows') === 0 ? '.exe' : '');
    if(os.indexOf('windows') === 0) return 'Invoke-WebRequest -Uri ' + CN_REPO + asset + ' -OutFile wirerift.exe';
    return 'curl -fsSL -o wirerift ' + CN_REPO + asset + ' && chmod +x wirerift';
}
function cnGuessOS(){
    var ua = (navigator.userAgent || '') + ' ' + (navigator.platform || '');
    if(/Win/i.test(ua)) return 'windows-amd64';
    if(/Mac/i.test(ua)) return 'darwin-arm64';
    if(/aarch64|arm64/i.test(ua)) return 'linux-arm64';
    return 'linux-amd64';
}
function cnValues(maskToken){
    var info = cnInfo || {};
    var tok = $('cnTok').checked ? apiToken : '';
    return {
        type: cnType,
        port: parseInt($('cnPort').value, 10) || 0,
        sub: $('cnSub').value.trim().toLowerCase(),
        inspect: $('cnInspect').checked,
        auth: $('cnAuth').value.trim(), pin: $('cnPin').value.trim(), allow: $('cnAllow').value.trim().replace(/\s+/g, ''),
        ttl: $('cnTtl').value,
        server: info.server_arg || (location.hostname + ':4443'),
        token: maskToken && tok ? cnMaskToken(tok) : tok,
        os: $('cnOS').value
    };
}
function cnSubProblem(sub, info){
    if(!sub) return '';
    if(!/^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/.test(sub)) return 'letters, digits and hyphens only (not at the ends)';
    if(info && info.reserved_subdomains && info.reserved_subdomains.indexOf(sub) >= 0) return 'this name is reserved';
    return '';
}
function cnPublicURL(o){
    var info = cnInfo || {};
    var dom = info.domain || location.hostname;
    if(o.type === 'tcp') return 'tcp://' + dom + ':' + (info.tcp_port_start ? info.tcp_port_start + '-' + info.tcp_port_end : '...');
    var sch = info.public_scheme || 'https', port = info.public_port;
    var hostPort = (!port || (sch === 'http' && port === 80) || (sch === 'https' && port === 443)) ? '' : ':' + port;
    return sch + '://' + (o.sub || '<random>') + '.' + dom + hostPort;
}
function cnRender(){
    var o = cnValues(false), m = cnValues(true);
    var bad = cnSubProblem(o.sub, cnInfo);
    $('cnSub').classList.toggle('bad', !!bad);
    $('cnSubWrap').style.display = cnType === 'http' ? '' : 'none';
    $('cnHttpOpts').style.display = cnType === 'http' ? '' : 'none';
    $('cnUrl').textContent = bad ? 'Subdomain: ' + bad : (cnType === 'tcp' ? 'Public address: ' : 'Public URL: ') + cnPublicURL(o) + (cnType === 'tcp' ? '  (the port is assigned)' : '');
    $('cnInstall').textContent = cnInstallText(o.os);
    $('cnCmd').textContent = cnBuild(m);
    $('cnNote').textContent = $('cnTok').checked
        ? 'The token is hidden here but copied in full. Anyone with the command can open tunnels as you.'
        : 'Replace YOUR_TOKEN with your token.';
}
function cnCopy(which){
    var o = cnValues(false);
    var text = which === 'cmd' ? cnBuild(o) : cnInstallText(o.os);
    copyToClipboard(text);
    toast(which === 'cmd' ? 'Command copied' : 'Install command copied', 'ok');
    if(which === 'cmd') cnSnapshot();
}
function cnSnapshot(){
    apiFetch('/api/tunnels').then(function(list){
        cnBase = {};
        (list || []).forEach(function(t){ cnBase[t.id] = true; });
        cnStatus(null);
    }).catch(function(){});
}
function cnStatus(t){
    var el = $('cnStatus');
    if(!t){ el.className = 'cn-status'; el.textContent = 'Waiting for the connection...'; return; }
    el.className = 'cn-status ok';
    el.textContent = 'Connected: ' + (t.url || ('tcp port ' + t.port));
}
function cnPoll(){
    if(currentTab !== 'connect') return;
    var o = cnValues(false);
    apiFetch('/api/tunnels').then(function(list){
        var hit = null;
        (list || []).forEach(function(t){
            if(cnBase[t.id] || t.type !== o.type || hit) return;
            if(o.type === 'http' && o.sub && (t.url || '').indexOf('//' + o.sub + '.') < 0) return;
            hit = t;
        });
        if(hit) cnStatus(hit);
    }).catch(function(){});
}
var cnBound = false;
function initConnect(){
    if(!cnBound){ cnBound = true; cnBind(); }
    apiFetch('/api/connect').then(function(info){ cnInfo = info; cnRender(); }).catch(function(){ cnRender(); });
    cnSnapshot();
    if(cnTimer) clearInterval(cnTimer);
    cnTimer = setInterval(cnPoll, 3000);
}
function cnBind(){
    $('cnOS').value = cnGuessOS();
    var ids = ['cnPort', 'cnSub', 'cnInspect', 'cnAuth', 'cnPin', 'cnAllow', 'cnTtl', 'cnTok', 'cnOS'];
    ids.forEach(function(id){ $(id).addEventListener('input', cnRender); $(id).addEventListener('change', cnRender); });
    var btns = qsa('#cnType button');
    for(var i = 0; i < btns.length; i++){
        (function(b){
            b.onclick = function(){
                cnType = b.getAttribute('data-v');
                for(var j = 0; j < btns.length; j++) btns[j].classList.toggle('on', btns[j] === b);
                cnRender();
            };
        })(btns[i]);
    }
    $('cnCopyInstall').onclick = function(){ cnCopy('install'); };
    $('cnCopyCmd').onclick = function(){ cnCopy('cmd'); };
    cnRender();
}

/* -- Activity & Admin --------------------------------------- */
var isAdminUser = false, adminInterval = null, activityCache = [], actLevel = '', actKind = '';
function initRoles(){
    initConnect();
    apiFetch('/api/me').then(function(me){
        isAdminUser = !!(me && me.admin);
        $('tabAdmin').style.display = isAdminUser ? '' : 'none';
        loadActivity();
        if(adminInterval) clearInterval(adminInterval);
        adminInterval = setInterval(function(){
            loadActivity();
            if(isAdminUser && currentTab === 'admin') loadAdmin();
        }, 5000);
        if(isAdminUser) loadAdmin();
    }).catch(function(){});
}
function levelPill(l){ return '<span class="pill ' + (l === 'warn' ? 'warn' : 'ok') + '">' + escHtml(l) + '</span>'; }
function loadActivity(){
    apiFetch('/api/events?limit=200').then(function(ev){
        activityCache = ev || [];
        $('badgeActivity').textContent = activityCache.length;
        renderActivity();
    }).catch(function(){});
}
function renderActivity(){
    var q = ($('searchActivity').value || '').toLowerCase();
    var rows = '', n = 0;
    for(var i = 0; i < activityCache.length; i++){
        var e = activityCache[i];
        var hay = (e.kind + ' ' + (e.account||'') + ' ' + (e.remote||'') + ' ' + e.message).toLowerCase();
        if(q && hay.indexOf(q) === -1) continue;
        if(actLevel && e.level !== actLevel) continue;
        if(actKind && e.kind !== actKind) continue;
        n++;
        rows += '<tr class="' + (e.level === 'warn' ? 'row-warn' : '') + '"><td>' + fmtTime(e.time) + '</td><td>' + levelPill(e.level) + '</td><td>' + escHtml(e.kind) +
            '</td><td>' + escHtml(e.account || '-') + '</td><td>' + escHtml(e.remote || '-') +
            '</td><td>' + escHtml(e.message) + '</td></tr>';
    }
    $('tbodyActivity').innerHTML = rows;
    $('emptyActivity').style.display = n ? 'none' : '';
}
function card(k, v, sub, cls){
    return '<div class="card ' + (cls||'') + '"><div class="k">' + escHtml(k) + '</div><div class="v">' + escHtml(String(v)) +
        '</div>' + (sub ? '<div class="s">' + escHtml(String(sub)) + '</div>' : '') + '</div>';
}
function rates(h, key){
    var out = [];
    for(var i = 1; i < h.length; i++){
        var dt = h[i].t - h[i-1].t; if(dt <= 0) dt = 1;
        var d = h[i][key] - h[i-1][key]; if(d < 0) d = 0;
        out.push(d / dt);
    }
    return out;
}
function gauge(h, key){ var o = []; for(var i = 0; i < h.length; i++) o.push(h[i][key]); return o; }
function fRate(v){ return (v < 10 ? v.toFixed(1) : Math.round(v)) + '/s'; }
function fBps(v){ return fmtBytes(v) + '/s'; }
function fNum(v){ return String(Math.round(v * 10) / 10); }

/* -- Admin console rendering --------------------------------- */
var admData = {h: [], o: null}, admTab = 'req';
function sumDelta(h, key){
    var t = 0;
    for(var i = 1; i < h.length; i++){ var d = h[i][key] - h[i-1][key]; if(d > 0) t += d; }
    return t;
}
function tspark(vals, color){
    var W = 120, H = 30, n = vals.length, max = 0, i, pts = '';
    for(i = 0; i < n; i++) if(vals[i] > max) max = vals[i];
    if(n < 2) return '';
    for(i = 0; i < n; i++){
        var x = i * W / (n - 1), y = max > 0 ? H - 2 - (vals[i] / max) * (H - 5) : H - 2;
        pts += x.toFixed(1) + ',' + y.toFixed(1) + ' ';
    }
    return '<svg class="tile-spark" viewBox="0 0 ' + W + ' ' + H + '" preserveAspectRatio="none" style="color:' + color + '" aria-hidden="true">' +
        '<polygon fill="currentColor" opacity=".13" points="0,' + H + ' ' + pts + W + ',' + H + '"/>' +
        '<polyline fill="none" stroke="currentColor" stroke-width="1.5" vector-effect="non-scaling-stroke" points="' + pts + '"/></svg>';
}
function tile(label, val, sub, vals, color, cls, extra){
    return '<div class="tile ' + (cls || '') + '"><div class="tile-k">' + escHtml(label) + '</div><div class="tile-v">' + escHtml(String(val)) +
        '</div><div class="tile-s">' + escHtml(String(sub || '')) + '</div>' + (extra || '') + (vals ? tspark(vals, color) : '') + '</div>';
}
function meter(pct, color){
    pct = Math.max(0, Math.min(100, pct));
    return '<div class="meter"><i style="width:' + pct.toFixed(1) + '%;background:' + color + '"></i></div>';
}
function renderHero(o, h){
    var issues = [], certDays = o.cert_expiry ? Math.floor((new Date(o.cert_expiry) - new Date()) / 86400000) : null;
    if(!o.ready) issues.push(['bad', 'Server is not ready']);
    if(certDays !== null && certDays < 14) issues.push([certDays < 5 ? 'bad' : 'warn', 'Certificate expires in ' + certDays + ' days']);
    if(o.persistence_errors) issues.push(['bad', o.persistence_errors + ' write error(s) to the state files']);
    if(o.open_fds > 800) issues.push(['warn', o.open_fds + ' open files']);
    var tot = sumDelta(h, 'requests'), e5 = sumDelta(h, 'err5xx');
    if(tot >= 50 && e5 / tot > 0.05) issues.push(['warn', Math.round(e5 / tot * 100) + '% of responses were 5xx in the last hour']);
    var held = (o.held_subdomains || []).length;
    if(held) issues.push(['warn', held + ' name(s) held for a client that dropped']);
    var lvl = 'ok', k;
    for(k = 0; k < issues.length; k++){ if(issues[k][0] === 'bad') lvl = 'bad'; else if(lvl !== 'bad') lvl = 'warn'; }
    var title = lvl === 'ok' ? 'All systems normal' : (lvl === 'warn' ? 'Worth a look' : 'Needs attention');
    var list = '';
    for(k = 0; k < issues.length; k++) list += '<span class="pill ' + issues[k][0] + '">' + escHtml(issues[k][1]) + '</span> ';
    var meta = '<span title="Server version">v' + escHtml(o.version || '?') + '</span><span title="Time since the server started">up ' + escHtml(fmtUptime(o.uptime_seconds)) + '</span><span>' + escHtml(o.domain || '') + '</span>';
    if(o.dashboard_host) meta += '<span title="Dashboard host on the HTTPS edge">' + escHtml(o.dashboard_host) + '</span>';
    $('admHero').className = 'adm-hero ' + lvl;
    $('admHero').innerHTML = '<div class="hero-main"><span class="hero-dot"></span><div><div class="hero-t">' + title + '</div><div class="hero-s">' +
        (list || 'Ready, no warnings. ' + o.sessions + ' client(s) and ' + (o.http_tunnels + o.tcp_tunnels) + ' tunnel(s) connected.') + '</div></div></div><div class="hero-meta">' + meta + '</div>';
}
function renderTiles(o, h){
    var reqR = rates(h, 'requests'), e4 = rates(h, 'err4xx'), e5 = rates(h, 'err5xx'), inR = rates(h, 'bytes_in'), outR = rates(h, 'bytes_out');
    var now = function(a){ return a.length ? a[a.length - 1] : 0; };
    var tot = sumDelta(h, 'requests'), bad = sumDelta(h, 'err4xx') + sumDelta(h, 'err5xx');
    var errPct = tot ? bad / tot * 100 : 0, errRate = [];
    for(var i = 0; i < reqR.length; i++) errRate.push(reqR[i] > 0 ? (e4[i] + e5[i]) / reqR[i] * 100 : 0);
    $('admTilesTraffic').innerHTML =
        tile('Requests', fRate(now(reqR)), fNum(o.requests) + ' since start', reqR, 'var(--ac)') +
        tile('Error share', (tot ? errPct.toFixed(1) : '0') + '%', '4xx + 5xx, last hour', errRate, 'var(--wn)', errPct > 5 ? 'warn' : '') +
        tile('Traffic out', fBps(now(outR)), 'in ' + fBps(now(inR)) + ' - total ' + fmtBytes(o.bytes_out) + ' out', outR, 'var(--pr)') +
        tile('Response time', 'p95 ≤ ' + fNum(o.p95_ms) + ' ms', 'avg ' + fNum(o.avg_latency_ms) + ' ms, p99 ≤ ' + fNum(o.p99_ms) + ' ms', null);
    var portPct = o.tcp_ports_total ? o.tcp_ports_in_use / o.tcp_ports_total * 100 : 0;
    $('admTilesCap').innerHTML =
        tile('Sessions', o.sessions, 'connected clients', gauge(h, 'sessions'), 'var(--tl)') +
        tile('Tunnels', o.http_tunnels + o.tcp_tunnels, o.http_tunnels + ' http, ' + o.tcp_tunnels + ' tcp', gauge(h, 'tunnels'), 'var(--ac)') +
        tile('TCP ports', o.tcp_ports_in_use + ' / ' + o.tcp_ports_total, 'in use', null, '', '', meter(portPct, 'var(--tl)')) +
        tile('Memory', fNum(o.heap_mb) + ' MB', 'heap, sys ' + fNum(o.sys_mb) + ' MB', gauge(h, 'heap_mb'), 'var(--wn)') +
        tile('Goroutines', o.goroutines, o.cpus + ' CPU(s), ' + o.num_gc + ' GCs', gauge(h, 'goroutines'), 'var(--pr)') +
        tile('Open files', o.open_fds < 0 ? 'n/a' : o.open_fds, 'file descriptors', gauge(h, 'fds'), 'var(--tl)', o.open_fds > 800 ? 'warn' : '');
}
function niceMax(v){
    if(v <= 0) return 1;
    var e = Math.pow(10, Math.floor(Math.log10(v))), m = v / e;
    return (m <= 1 ? 1 : m <= 2 ? 2 : m <= 5 ? 5 : 10) * e;
}
function chartSeries(){
    var h = admData.h;
    if(admTab === 'req'){
        var tot = rates(h, 'requests'), e4 = rates(h, 'err4xx'), e5 = rates(h, 'err5xx'), ok = [];
        for(var i = 0; i < tot.length; i++) ok.push(Math.max(0, tot[i] - e4[i] - e5[i]));
        return {stack: true, fmt: fRate, series: [{n: 'OK (1xx-3xx)', c: 'var(--ok)', v: ok}, {n: '4xx', c: 'var(--wn)', v: e4}, {n: '5xx', c: 'var(--er)', v: e5}]};
    }
    return {stack: false, fmt: fBps, series: [{n: 'In', c: 'var(--ac)', v: rates(h, 'bytes_in')}, {n: 'Out', c: 'var(--pr)', v: rates(h, 'bytes_out')}]};
}
function drawChart(){
    var box = $('admChartBox'), h = admData.h;
    if(!box) return;
    if(h.length < 3){ box.innerHTML = '<div class="empty" style="padding:2rem 0">Collecting samples (one every 10 s)...</div>'; $('admLegend').innerHTML = ''; return; }
    var cs = chartSeries(), S = cs.series, n = S[0].v.length, times = h.slice(1).map(function(p){ return p.t; });
    var W = Math.max(280, box.clientWidth || 700), H = 230, pl = 52, pr = 10, pt = 12, pb = 24, pw = W - pl - pr, ph = H - pt - pb;
    var cum = [], k, i, maxv = 0;
    for(k = 0; k < S.length; k++){
        cum.push([]);
        for(i = 0; i < n; i++){
            var base = cs.stack && k > 0 ? cum[k-1][i] : 0;
            cum[k].push(base + S[k].v[i]);
            if(cum[k][i] > maxv) maxv = cum[k][i];
        }
    }
    var top = niceMax(maxv), X = function(i){ return pl + (n > 1 ? i * pw / (n - 1) : pw); }, Y = function(v){ return pt + ph - (v / top) * ph; };
    var g = '', t;
    for(t = 0; t <= 2; t++){
        var gv = top * t / 2, gy = Y(gv);
        g += '<line x1="' + pl + '" x2="' + (W - pr) + '" y1="' + gy.toFixed(1) + '" y2="' + gy.toFixed(1) + '" class="ax-grid"/><text x="' + (pl - 6) + '" y="' + (gy + 3.5).toFixed(1) + '" text-anchor="end" class="ax-t">' + escHtml(cs.fmt(gv)) + '</text>';
    }
    var xl = [0, Math.floor((n - 1) / 2), n - 1];
    for(t = 0; t < xl.length; t++){
        g += '<text x="' + X(xl[t]).toFixed(1) + '" y="' + (H - 6) + '" text-anchor="' + (t === 0 ? 'start' : t === 2 ? 'end' : 'middle') + '" class="ax-t">' + escHtml(t === 2 ? 'now' : fmtTime(new Date(times[xl[t]] * 1000))) + '</text>';
    }
    var layers = '';
    for(k = 0; k < S.length; k++){
        var up = '', lo = '';
        for(i = 0; i < n; i++){ up += X(i).toFixed(1) + ',' + Y(cum[k][i]).toFixed(1) + ' '; }
        if(cs.stack){
            for(i = n - 1; i >= 0; i--){ lo += X(i).toFixed(1) + ',' + Y(k > 0 ? cum[k-1][i] : 0).toFixed(1) + ' '; }
            layers += '<polygon points="' + up + lo + '" fill="' + S[k].c + '" opacity=".85" stroke="var(--bg-1)" stroke-width="1"/>';
        } else {
            layers += '<polygon points="' + up + X(n-1).toFixed(1) + ',' + Y(0) + ' ' + X(0).toFixed(1) + ',' + Y(0) + '" fill="' + S[k].c + '" opacity=".1"/>' +
                '<polyline points="' + up + '" fill="none" stroke="' + S[k].c + '" stroke-width="2" stroke-linejoin="round" vector-effect="non-scaling-stroke"/>';
        }
    }
    box.innerHTML = '<svg viewBox="0 0 ' + W + ' ' + H + '" width="' + W + '" height="' + H + '" role="img" aria-label="Chart of the last hour">' + g + layers +
        '<line id="admXh" y1="' + pt + '" y2="' + (pt + ph) + '" class="ax-x" style="display:none"/><g id="admDots"></g></svg><div class="adm-tip" id="admTip" style="display:none"></div>';
    var svg = box.firstChild, tip = $('admTip'), xh = $('admXh'), dots = $('admDots');
    function show(ev){
        var r = svg.getBoundingClientRect(), mx = (ev.clientX - r.left) * (W / r.width);
        var idx = Math.round((mx - pl) / pw * (n - 1));
        if(idx < 0) idx = 0; if(idx > n - 1) idx = n - 1;
        var x = X(idx), d = '', rows = '', tot = 0;
        for(var q = 0; q < S.length; q++){
            d += '<circle cx="' + x.toFixed(1) + '" cy="' + Y(cum[q][idx]).toFixed(1) + '" r="3.5" fill="' + S[q].c + '" stroke="var(--bg-1)" stroke-width="2"/>';
            rows += '<div><i style="background:' + S[q].c + '"></i>' + escHtml(S[q].n) + ' <b>' + escHtml(cs.fmt(S[q].v[idx])) + '</b></div>';
            tot += S[q].v[idx];
        }
        dots.innerHTML = d;
        xh.setAttribute('x1', x); xh.setAttribute('x2', x); xh.style.display = '';
        tip.innerHTML = '<div class="tt">' + escHtml(fmtTime(new Date(times[idx] * 1000))) + '</div>' + rows + (cs.stack ? '<div class="tt">total <b>' + escHtml(cs.fmt(tot)) + '</b></div>' : '');
        tip.style.display = '';
        var left = x / W * r.width + 12;
        if(left + tip.offsetWidth > r.width - 4) left = x / W * r.width - tip.offsetWidth - 12;
        tip.style.left = Math.max(4, left) + 'px'; tip.style.top = '8px';
    }
    svg.onmousemove = show;
    svg.onmouseleave = function(){ tip.style.display = 'none'; xh.style.display = 'none'; dots.innerHTML = ''; };
    var lg = '';
    for(k = 0; k < S.length; k++) lg += '<span><i style="background:' + S[k].c + '"></i>' + escHtml(S[k].n) + ' <b>' + escHtml(cs.fmt(S[k].v[n-1])) + '</b></span>';
    $('admLegend').innerHTML = lg;
    var head = '<tr><th>Time</th>', rowsT = '';
    for(k = 0; k < S.length; k++) head += '<th>' + escHtml(S[k].n) + '</th>';
    $('admChartHead').innerHTML = head + '</tr>';
    for(i = n - 1; i >= 0 && rowsT.length < 4000; i -= 6){
        rowsT += '<tr><td>' + escHtml(fmtTime(new Date(times[i] * 1000))) + '</td>';
        for(k = 0; k < S.length; k++) rowsT += '<td>' + escHtml(cs.fmt(S[k].v[i])) + '</td>';
        rowsT += '</tr>';
    }
    $('admChartRows').innerHTML = rowsT;
}
function renderLatency(o){
    var lb = o.latency_buckets || [], prev = 0, items = [], max = 0, total = o.requests || 0, i, i95 = lb.length;
    for(i = 0; i < lb.length; i++){
        var c = lb[i].count - prev; prev = lb[i].count;
        var lab = lb[i].le_ms ? (lb[i].le_ms >= 1000 ? (lb[i].le_ms / 1000) + ' s' : lb[i].le_ms + ' ms') : '> 10 s';
        items.push({c: c, lab: lab, le: lb[i].le_ms});
        if(c > max) max = c;
        if(lb[i].le_ms && lb[i].le_ms >= o.p95_ms && i95 === lb.length) i95 = i;
    }
    var bars = '';
    for(i = 0; i < items.length; i++){
        var it = items[i], hgt = max ? it.c / max * 100 : 0;
        bars += '<div class="lh" title="' + escHtml(it.lab + ': ' + it.c + ' request(s)' + (total ? ' (' + (it.c / total * 100).toFixed(1) + '%)' : '')) + '"><div class="lh-b"><i style="height:' +
            (it.c && hgt < 3 ? 3 : hgt).toFixed(1) + '%;background:' + (i <= i95 ? 'var(--ac)' : 'var(--wn)') + '"></i></div><span>' + escHtml(it.lab.replace(' ms', '')) + '</span></div>';
    }
    $('admLatSub').textContent = 'ms, slowest 5% in amber';
    $('adminLatency').innerHTML = '<div class="lh-row">' + bars + '</div><div class="lh-stats"><span>avg <b>' + fNum(o.avg_latency_ms) + ' ms</b></span><span>p50 <b>≤ ' + fNum(o.p50_ms) +
        '</b></span><span>p95 <b>≤ ' + fNum(o.p95_ms) + '</b></span><span>p99 <b>≤ ' + fNum(o.p99_ms) + '</b></span></div>';
}
function renderStatus(o){
    var st = o.status || {}, defs = [['2xx', 'Success', 'var(--ok)'], ['3xx', 'Redirect', 'var(--ac)'], ['4xx', 'Client error', 'var(--wn)'], ['5xx', 'Server error', 'var(--er)'], ['1xx', 'Informational', 'var(--tx-2)']];
    var total = 0, i;
    for(i = 0; i < defs.length; i++) total += st[defs[i][0]] || 0;
    var seg = '', leg = '';
    for(i = 0; i < defs.length; i++){
        var c = st[defs[i][0]] || 0, pct = total ? c / total * 100 : 0;
        if(c) seg += '<i style="flex:' + c + ';background:' + defs[i][2] + '" title="' + escHtml(defs[i][0] + ': ' + c) + '"></i>';
        if(c || i < 4) leg += '<div class="sl"><span><i style="background:' + defs[i][2] + '"></i>' + defs[i][0] + ' <em>' + defs[i][1] + '</em></span><b>' + fNum(c) + '</b><u>' + pct.toFixed(1) + '%</u></div>';
    }
    $('admStatSub').textContent = total ? fNum(total) + ' responses since start' : '';
    $('adminStatus').innerHTML = (total ? '<div class="stackbar">' + seg + '</div>' : '<div class="empty">No responses yet</div>') + '<div class="sl-list">' + leg + '</div>';
}
function renderAccounts(accts){
    var totalBytes = 0, i;
    for(i = 0; i < accts.length; i++) totalBytes += (accts[i].bytes_in || 0) + (accts[i].bytes_out || 0);
    var out = '';
    for(i = 0; i < accts.length; i++){
        var a = accts[i], name = a.name || a.id.replace(/^acct_/, ''), bytes = (a.bytes_in || 0) + (a.bytes_out || 0);
        var lim = function(used, max, label){
            return '<div class="lim"><div class="lim-h"><span>' + label + '</span><b>' + used + (max ? ' / ' + max : '') + '</b></div>' + (max ? meter(used / max * 100, used >= max ? 'var(--er)' : 'var(--ac)') : '<div class="lim-n">no limit</div>') + '</div>';
        };
        out += '<div class="acct' + (a.active ? '' : ' off') + '"><div class="acct-h"><b>' + escHtml(name) + '</b><span>' + (a.admin ? '<span class="pill warn">admin</span> ' : '') +
            (a.active ? '<span class="pill ok">active</span>' : '<span class="pill bad">disabled</span>') + '</span></div>' +
            '<div class="lims">' + lim(a.sessions, a.max_sessions, 'Sessions') + lim(a.tunnels, a.max_tunnels, 'Tunnels') + '</div>' +
            '<div class="acct-t"><div class="lim-h"><span>Traffic since start</span><b>' + fmtBytes(bytes) + '</b></div>' + meter(totalBytes ? bytes / totalBytes * 100 : 0, 'var(--pr)') +
            '<div class="acct-n">' + fNum(a.requests || 0) + ' requests - in ' + fmtBytes(a.bytes_in || 0) + ' - out ' + fmtBytes(a.bytes_out || 0) + (a.rate_limit ? ' - ' + a.rate_limit + ' creations/s' : '') + '</div></div>' +
            '<div class="acct-a"><button class="btn-sm" data-newtok="' + escHtml(a.id.replace(/^acct_/, '')) + '">New token</button><button class="btn-sm" data-setpw="' + escHtml(a.id.replace(/^acct_/, '')) + '">Set password</button></div></div>';
    }
    $('admAccounts').innerHTML = out || '<div class="empty">No accounts</div>';
}
function loadAdmin(){
    Promise.all([
        apiFetch('/api/admin/overview'), apiFetch('/api/admin/history'), apiFetch('/api/admin/accounts'),
        apiFetch('/api/admin/certs'), apiFetch('/api/sessions')
    ]).then(function(r){
        renderAdmin(r[0], r[1] || [], r[2] || [], r[3] || [], r[4] || []);
        loadTokens();
        $('adminStamp').textContent = 'updated ' + fmtTime(new Date());
        $('adminStamp').className = 'pill ok';
    }).catch(function(e){ $('adminStamp').textContent = 'update failed: ' + e.message; $('adminStamp').className = 'pill bad'; });
}
function renderAdmin(o, h, accts, certs, sess){
    admData = {h: h, o: o};
    renderHero(o, h);
    renderTiles(o, h);
    drawChart();
    renderLatency(o);
    renderStatus(o);
    renderAccounts(accts);
    var rows = '', i;
    for(i = 0; i < sess.length; i++){
        var s = sess[i];
        rows += '<tr><td class="mono">' + escHtml(s.id) + '</td><td>' + escHtml(s.account_id) + '</td><td class="mono">' + escHtml(s.remote_addr) + '</td><td>' + fmtAgo(s.connected_at) +
            '</td><td>' + (new Date(s.last_heartbeat).getFullYear() < 2000 ? '-' : fmtTime(s.last_heartbeat)) + '</td><td>' + s.tunnel_count + '</td><td><button class="btn-danger" data-kick="' + escHtml(s.id) + '">Disconnect</button></td></tr>';
    }
    $('tbodyAdminSessions').innerHTML = rows || '<tr><td colspan="7" style="color:var(--tx-2)">No sessions</td></tr>';
    reapplyFinds();
    rows = '';
    var held = o.held_subdomains || [];
    for(i = 0; i < held.length; i++){
        rows += '<tr><td>' + escHtml(held[i].subdomain) + '</td><td>' + escHtml(held[i].account) + '</td><td>' + fmtUptime((new Date(held[i].until) - new Date()) / 1000) + ' left</td></tr>';
    }
    $('tbodyHeld').innerHTML = rows || '<tr><td colspan="3" style="color:var(--tx-2)">None</td></tr>';
    rows = '';
    for(i = 0; i < certs.length; i++){
        var cd = certs[i].days_left, cls = cd < 5 ? 'bad' : (cd < 14 ? 'warn' : 'ok');
        rows += '<tr><td>' + escHtml(certs[i].host) + '</td><td>' + escHtml(certs[i].issuer) + '</td><td>' + fmtTimeDate(certs[i].not_after) +
            '</td><td><span class="pill ' + cls + '">' + cd + ' d</span></td></tr>';
    }
    $('tbodyCerts').innerHTML = rows || '<tr><td colspan="4" style="color:var(--tx-2)">No certificates in memory</td></tr>';
    $('adminConfig').innerHTML =
        card('Domain', o.domain) +
        card('Dashboard host', o.dashboard_host || 'not published', o.dashboard_host ? 'served on the HTTPS edge' : 'loopback only') +
        card('Edge rate limit', o.edge_rate_per_ip + '/s', 'burst ' + o.edge_burst + ' per visitor IP') +
        card('Offline grace', fmtUptime(o.offline_grace_seconds), 'names held after a drop') +
        card('Trusted proxies', o.trusted_proxy_cidrs, 'CIDR ranges');
}

/* -- Token management --------------------------------------- */
function tokCall(method, path, body){
    return fetch(path, {
        method: method,
        headers: {'Authorization': 'Bearer ' + apiToken, 'Content-Type': 'application/json'},
        body: body ? JSON.stringify(body) : null
    }).then(function(r){
        return r.json().catch(function(){ return {}; }).then(function(j){
            if(!r.ok){ var e = new Error(j.error || ('API error ' + r.status)); e.status = r.status; throw e; }
            return j;
        });
    });
}
function loadTokens(){
    tokCall('GET', '/api/admin/tokens').then(function(list){
        $('tokensOff').style.display = 'none';
        $('tokNew').style.display = '';
        renderTokens(list || []);
    }).catch(function(e){
        $('tbodyTokens').innerHTML = '';
        $('tokNew').style.display = 'none';
        $('tokensOff').style.display = '';
        $('tokensOff').textContent = e.status === 501 ? 'Token management is off: this server has no token file.' : 'Tokens unavailable: ' + e.message;
    });
}
function renderTokens(list){
    var rows = '', names = {}, i;
    for(i = 0; i < list.length; i++){
        var t = list[i], lim = [];
        names[t.account] = true;
        if(t.max_tunnels) lim.push('tunnels≤' + t.max_tunnels);
        if(t.max_sessions) lim.push('sessions≤' + t.max_sessions);
        if(t.rate_limit) lim.push('rate ' + t.rate_limit + '/s');
        var cls = t.status === 'active' ? 'ok' : (t.status === 'expired' ? 'warn' : 'bad');
        rows += '<tr' + (t.status === 'active' ? '' : ' class="tok-off"') + '><td class="mono">' + escHtml(t.id) + '</td><td>' + escHtml(t.account) + '</td><td>' + escHtml(t.name || '-') + '</td><td>' +
            (t.admin ? '<span class="pill warn">admin</span>' : 'user') + '</td><td>' + escHtml(lim.join(', ') || '-') + '</td><td>' + fmtAgo(t.created_at) + '</td><td>' +
            (t.expires_at ? fmtTimeDate(t.expires_at) : 'never') + '</td><td><span class="pill ' + cls + '">' + escHtml(t.status) + '</span></td><td>' +
            (t.status === 'revoked' ? '' : '<button class="btn-danger" data-revoke="' + escHtml(t.id) + '">Revoke</button>') + '</td></tr>';
    }
    $('tbodyTokens').innerHTML = rows || '<tr><td colspan="9" style="color:var(--tx-2)">No tokens in the token file</td></tr>';
    reapplyFinds();
    var opts = '';
    for(var n in names) opts += '<option value="' + escHtml(n) + '">';
    $('tokAccounts').innerHTML = opts;
}
function applyFind(inp){
    var q = inp.value.trim().toLowerCase(), rows = $(inp.getAttribute('data-find')).children;
    for(var i = 0; i < rows.length; i++){
        rows[i].style.display = !q || rows[i].textContent.toLowerCase().indexOf(q) >= 0 ? '' : 'none';
    }
}
function reapplyFinds(){ qsa('[data-find]').forEach(applyFind); }
function tokNum(id){ var v = $(id).value.trim(); return v === '' ? undefined : parseInt(v, 10); }
function createToken(){
    var body = {account: $('tokAccount').value.trim(), name: $('tokName').value.trim(), expires: $('tokExpires').value};
    var role = $('tokRole').value;
    if(role) body.admin = role === 'admin';
    var mt = tokNum('tokMaxT'), ms = tokNum('tokMaxS'), rt = tokNum('tokRate');
    if(mt !== undefined) body.max_tunnels = mt;
    if(ms !== undefined) body.max_sessions = ms;
    if(rt !== undefined) body.rate_limit = rt;
    if(!body.account){ toast('Give an account name', 'err'); return; }
    tokCall('POST', '/api/admin/tokens', body).then(function(res){
        showSecret(res);
        $('tokName').value = '';
        loadTokens(); loadAdmin(); loadActivity();
    }).catch(function(e){ toast('Failed: ' + e.message, 'err'); });
}
function showSecret(res){
    var info = cnInfo || {};
    var cmd = cnBuild({type: 'http', port: 8080, sub: '', inspect: false, auth: '', pin: '', allow: '', ttl: '',
        server: info.server_arg || (location.hostname + ':4443'), token: res.secret, os: cnGuessOS()});
    var box = $('tokSecret');
    box.style.display = '';
    box.innerHTML = '<strong>Token ' + escHtml(res.id) + ' for ' + escHtml(res.account) + '</strong> <span class="pill warn">shown only now</span>' +
        '<code id="tokSecretText"></code><button class="btn-sm" id="tokCopySecret">Copy token</button>' +
        '<p class="cn-note" style="margin:.75rem 0 .25rem">Try it (port 8080 as an example, change it in the Connect tab):</p><code id="tokCmdText"></code>' +
        '<button class="btn-sm" id="tokCopyCmd">Copy command</button> <button class="btn-ghost" id="tokHide">Hide</button>';
    $('tokSecretText').textContent = res.secret;
    $('tokCmdText').textContent = cmd;
    $('tokCopySecret').onclick = function(){ copyToClipboard(res.secret); toast('Token copied', 'ok'); };
    $('tokCopyCmd').onclick = function(){ copyToClipboard(cmd); toast('Command copied', 'ok'); };
    $('tokHide').onclick = function(){ box.style.display = 'none'; box.innerHTML = ''; };
    if(box.scrollIntoView) box.scrollIntoView({block: 'center', behavior: 'smooth'});
}

document.addEventListener('click', function(ev){
    var t = ev.target;
    if(t && t.getAttribute && t.getAttribute('data-newtok')){
        $('tokAccount').value = t.getAttribute('data-newtok');
        $('tokNew').open = true;
        $('tokNew').scrollIntoView({behavior: 'smooth', block: 'center'});
        $('tokName').focus();
        return;
    }
    if(t && t.getAttribute && t.getAttribute('data-setpw')){
        $('pwAccount').value = t.getAttribute('data-setpw');
        $('pwSet').open = true;
        $('pwSet').scrollIntoView({behavior: 'smooth', block: 'center'});
        $('pwValue').focus();
        return;
    }
    if(t && t.getAttribute && t.getAttribute('data-kick')){
        var id = t.getAttribute('data-kick');
        if(!confirm('Disconnect session ' + id + '? The client may reconnect; revoke its token to keep it out.')) return;
        apiFetch('/api/admin/sessions/' + encodeURIComponent(id) + '/kick', {method: 'POST'}).then(function(){
            toast('Session disconnected', 'ok'); loadAdmin(); loadActivity();
        }).catch(function(e){ toast('Failed: ' + e.message, 'err'); });
    }
    if(t && t.getAttribute && t.getAttribute('data-revoke')){
        var tid = t.getAttribute('data-revoke');
        if(!confirm('Revoke token ' + tid + '? Clients using it are disconnected at once and cannot log in again.')) return;
        tokCall('POST', '/api/admin/tokens/' + encodeURIComponent(tid) + '/revoke').then(function(){
            toast('Token revoked', 'ok'); loadTokens(); loadAdmin(); loadActivity();
        }).catch(function(e){ toast('Failed: ' + e.message, 'err'); });
    }
});

/* -- Keyboard Shortcuts ------------------------------------- */
function handleKey(e){
    var tag = (e.target.tagName || '').toLowerCase();
    if(tag === 'input' || tag === 'textarea' || tag === 'select') return;
    var key = e.key ? e.key.toUpperCase() : '';
    if(key === 'R'){
        e.preventDefault();
        if(currentTab === 'tunnels') loadTunnels();
        else if(currentTab === 'sessions') loadSessions();
        else if(currentTab === 'inspector') loadRequests();
        else if(currentTab === 'activity') loadActivity();
        else if(currentTab === 'admin' && isAdminUser) loadAdmin();
        toast('Refreshed', 'info');
    }
    if(key === 'T'){ e.preventDefault(); switchTab('tunnels'); }
    if(key === 'S'){ e.preventDefault(); switchTab('sessions'); }
    if(key === 'I'){ e.preventDefault(); switchTab('inspector'); }
    if(key === 'A'){ e.preventDefault(); switchTab('activity'); }
    if(key === 'C'){ e.preventDefault(); switchTab('connect'); }
    if(key === 'D' && isAdminUser){ e.preventDefault(); switchTab('admin'); loadAdmin(); }
}

/* -- Event Binding ------------------------------------------ */
function init(){
    initTheme();

    $('themeBtn').onclick = toggleTheme;
    $('authBtn').onclick = showLogin;
    $('loginBtn').onclick = doLogin;
    ['tokenInput', 'userInput', 'passInput'].forEach(function(id){
        $(id).addEventListener('keydown', function(e){ if(e.key === 'Enter') doLogin(); });
    });
    $('loginSwitch').onclick = function(e){ e.preventDefault(); setLoginMode(!loginByToken); };

    var tabEls = qsa('.tab');
    for(var i = 0; i < tabEls.length; i++){
        (function(el){
            el.onclick = function(){ switchTab(el.getAttribute('data-tab')); };
        })(tabEls[i]);
    }

    $('refreshTunnels').onclick = function(){ loadTunnels(); toast('Tunnels refreshed', 'info'); };
    $('refreshSessions').onclick = function(){ loadSessions(); toast('Sessions refreshed', 'info'); };
    $('refreshRequests').onclick = function(){ loadRequests(); toast('Inspector refreshed', 'info'); };
    $('inspChips').onclick = function(e){
        var b = e.target.closest('.chip');
        if(!b) return;
        inspClass = b.getAttribute('data-sc') || '';
        var all = $('inspChips').querySelectorAll('.chip');
        for(var i = 0; i < all.length; i++) all[i].classList.toggle('on', all[i] === b);
        renderRequests();
    };
    $('tokCreate').onclick = createToken;
    $('admChartTabs').onclick = function(e){
        var b = e.target.closest('button');
        if(!b) return;
        admTab = b.getAttribute('data-ct');
        var all = $('admChartTabs').querySelectorAll('button');
        for(var i = 0; i < all.length; i++) all[i].classList.toggle('on', all[i] === b);
        drawChart();
    };
    var rzT = null;
    window.addEventListener('resize', function(){ clearTimeout(rzT); rzT = setTimeout(function(){ if(currentTab === 'admin') drawChart(); }, 150); });
    var spyT = null;
    window.addEventListener('scroll', function(){
        if(currentTab !== 'admin' || spyT) return;
        spyT = setTimeout(function(){
            spyT = null;
            var links = $('admNav').querySelectorAll('a'), cur = null, i;
            for(i = 0; i < links.length; i++){
                var sec = $(links[i].getAttribute('data-jump'));
                if(sec && sec.getBoundingClientRect().top <= 90) cur = links[i];
            }
            for(i = 0; i < links.length; i++) links[i].classList.toggle('on', links[i] === cur);
        }, 80);
    }, {passive: true});
    $('admNav').onclick = function(e){
        var id = e.target.getAttribute && e.target.getAttribute('data-jump');
        if(!id) return;
        e.preventDefault();
        var el = $(id); if(el && el.scrollIntoView) el.scrollIntoView({behavior: 'smooth', block: 'start'});
    };
    qsa('[data-find]').forEach(function(inp){
        inp.addEventListener('input', function(){ applyFind(inp); });
    });
    $('pwSave').onclick = function(){
        var acct = $('pwAccount').value.trim(), pw = $('pwValue').value;
        if(!acct || !pw){ toast('Give an account and a password', 'err'); return; }
        tokCall('POST', '/api/admin/accounts/' + encodeURIComponent(acct) + '/password', {password: pw}).then(function(){
            $('pwValue').value = ''; toast('Password set for ' + acct, 'ok'); loadActivity();
        }).catch(function(e){ toast('Failed: ' + e.message, 'err'); });
    };
    $('refreshActivity').onclick = function(){ loadActivity(); toast('Activity refreshed', 'info'); };
    $('refreshAdmin').onclick = function(){ loadAdmin(); toast('Admin view refreshed', 'info'); };
    $('searchActivity').oninput = renderActivity;
    $('actChips').onclick = function(ev){
        var b = ev.target.closest('.chip');
        if(!b) return;
        actLevel = b.getAttribute('data-lvl') || '';
        actKind = b.getAttribute('data-kind') || '';
        var all = $('actChips').querySelectorAll('.chip');
        for(var i = 0; i < all.length; i++) all[i].classList.toggle('on', all[i] === b);
        renderActivity();
    };

    var debounceTimers = {};
    function debounceRender(key, fn){
        return function(){
            if(debounceTimers[key]) clearTimeout(debounceTimers[key]);
            debounceTimers[key] = setTimeout(fn, 150);
        };
    }
    $('searchTunnels').addEventListener('input', debounceRender('t', renderTunnels));
    $('searchSessions').addEventListener('input', debounceRender('s', renderSessions));
    $('searchInspector').addEventListener('input', debounceRender('i', renderRequests));
    $('tunnelFilter').onchange = function(){ loadRequests(); };

    document.addEventListener('keydown', handleKey);

    var saved = null;
    try { saved = sessionStorage.getItem('wr_t'); } catch(e){}
    if(saved){
        apiToken = saved;
        verifyAndLoad();
    } else {
        showLogin();
    }
}

/* -- Boot --------------------------------------------------- */
if(document.readyState === 'loading'){
    document.addEventListener('DOMContentLoaded', init);
} else {
    init();
}

})();
</script>
</body>
</html>`
