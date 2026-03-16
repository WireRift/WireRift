package dashboard

import (
	"crypto/rand"
	"embed"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/fs"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/wirerift/wirerift/internal/auth"
	"github.com/wirerift/wirerift/internal/config"
	"github.com/wirerift/wirerift/internal/server"
)

//go:embed static/*
var staticFS embed.FS

// Dashboard provides a web UI for managing WireRift.
type Dashboard struct {
	server       *server.Server
	authManager  *auth.Manager
	domainMgr    *config.DomainManager
	port         int
	httpsEnabled bool
}

// Config holds dashboard configuration.
type Config struct {
	Server       *server.Server
	AuthManager  *auth.Manager
	DomainMgr    *config.DomainManager
	Port         int
	HTTPSEnabled bool
}

// New creates a new dashboard.
func New(cfg Config) *Dashboard {
	if cfg.Port == 0 {
		cfg.Port = 4040
	}
	return &Dashboard{
		server:       cfg.Server,
		authManager:  cfg.AuthManager,
		domainMgr:    cfg.DomainMgr,
		port:         cfg.Port,
		httpsEnabled: cfg.HTTPSEnabled,
	}
}

// Handler returns the HTTP handler for the dashboard.
func (d *Dashboard) Handler() http.Handler {
	mux := http.NewServeMux()

	// API endpoints
	mux.HandleFunc("/api/tunnels", d.authMiddleware(d.handleTunnels))
	mux.HandleFunc("/api/sessions", d.authMiddleware(d.handleSessions))
	mux.HandleFunc("/api/stats", d.authMiddleware(d.handleStats))
	mux.HandleFunc("/api/domains", d.authMiddleware(d.handleDomains))
	mux.HandleFunc("/api/domains/", d.authMiddleware(d.handleDomainActions))
	mux.HandleFunc("/api/requests", d.authMiddleware(d.handleRequests))
	mux.HandleFunc("/api/requests/", d.authMiddleware(d.handleRequestActions))

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
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		next.ServeHTTP(w, r)
	})
}

// authMiddleware checks for valid authentication.
func (d *Dashboard) authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Check for Bearer token
		auth := r.Header.Get("Authorization")
		if auth == "" {
			// Session cookies only allowed for safe (GET) requests to prevent CSRF
			if r.Method == http.MethodGet {
				cookie, err := r.Cookie("wirerift_session")
				if err == nil && cookie.Value != "" {
					_, _, err := d.authManager.ValidateToken(cookie.Value)
					if err == nil {
						next(w, r)
						return
					}
				}
			}
			d.jsonError(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		parts := strings.SplitN(auth, " ", 2)
		if len(parts) != 2 || parts[0] != "Bearer" {
			d.jsonError(w, "Invalid authorization", http.StatusUnauthorized)
			return
		}

		_, _, err := d.authManager.ValidateToken(parts[1])
		if err != nil {
			d.jsonError(w, "Invalid token", http.StatusUnauthorized)
			return
		}

		next(w, r)
	}
}

// handleTunnels handles GET /api/tunnels
func (d *Dashboard) handleTunnels(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		d.jsonError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	tunnels := d.server.ListTunnels()
	d.jsonResponse(w, tunnels)
}

// handleSessions handles GET /api/sessions
func (d *Dashboard) handleSessions(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		d.jsonError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	sessions := d.server.ListSessions()
	d.jsonResponse(w, sessions)
}

// handleStats handles GET /api/stats
func (d *Dashboard) handleStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		d.jsonError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	stats := d.server.Stats()
	stats["uptime"] = time.Since(d.server.StartTime()).Seconds()
	stats["dashboard_port"] = d.port
	stats["https_enabled"] = d.httpsEnabled
	d.jsonResponse(w, stats)
}

// handleDomains handles GET/POST /api/domains
func (d *Dashboard) handleDomains(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		// List domains - for now return empty list if no domain manager
		if d.domainMgr == nil {
			d.jsonResponse(w, []interface{}{})
			return
		}
		domains := d.domainMgr.ListDomains("")
		d.jsonResponse(w, domains)

	case http.MethodPost:
		// Limit request body to 1 MB to prevent abuse
		r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
		var req struct {
			Domain    string `json:"domain"`
			AccountID string `json:"account_id"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			d.jsonError(w, "Invalid request", http.StatusBadRequest)
			return
		}

		if d.domainMgr == nil {
			d.jsonError(w, "Domain management not available", http.StatusServiceUnavailable)
			return
		}

		domain, err := d.domainMgr.AddDomain(req.Domain, req.AccountID)
		if err != nil {
			d.jsonError(w, err.Error(), http.StatusBadRequest)
			return
		}

		d.jsonResponse(w, domain)

	default:
		d.jsonError(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleDomainActions handles domain-specific actions
func (d *Dashboard) handleDomainActions(w http.ResponseWriter, r *http.Request) {
	// Extract domain from path (strings.Split always returns at least 1 element)
	path := strings.TrimPrefix(r.URL.Path, "/api/domains/")
	parts := strings.Split(path, "/")
	domain := parts[0]

	if d.domainMgr == nil {
		d.jsonError(w, "Domain management not available", http.StatusServiceUnavailable)
		return
	}

	switch r.Method {
	case http.MethodGet:
		// Get domain details
		customDomain, err := d.domainMgr.GetDomain(domain)
		if err != nil {
			d.jsonError(w, err.Error(), http.StatusNotFound)
			return
		}
		d.jsonResponse(w, customDomain)

	case http.MethodDelete:
		// Remove domain (RemoveDomain always returns nil)
		d.domainMgr.RemoveDomain(domain)
		w.WriteHeader(http.StatusNoContent)

	default:
		// Check for action in path
		if len(parts) > 1 {
			action := parts[1]
			switch action {
			case "dns":
				// Get DNS records
				// GetDNSRecords always returns nil error
				records, _ := d.domainMgr.GetDNSRecords(domain)
				d.jsonResponse(w, records)

			case "verify":
				// Verify domain
				err := d.domainMgr.VerifyDomain(domain, nil, nil)
				if err != nil {
					d.jsonError(w, err.Error(), http.StatusInternalServerError)
					return
				}
				d.jsonResponse(w, map[string]string{"status": "verified"})

			default:
				d.jsonError(w, "Unknown action", http.StatusBadRequest)
			}
			return
		}

		d.jsonError(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
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

	logs := d.server.GetRequestLogs(tunnelID, limit)
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
	result, err := d.server.ReplayRequest(logID)
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
table{width:100%%;border-collapse:collapse}
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
content:'';width:.5rem;height:.5rem;border-radius:50%%;
background:var(--ok);animation:pulse 2s ease-in-out infinite;
}
@keyframes pulse{
0%%,100%%{opacity:1;box-shadow:0 0 0 0 rgba(34,197,94,.4)}
50%%{opacity:.7;box-shadow:0 0 0 4px rgba(34,197,94,0)}
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

/* Empty state */
.empty{text-align:center;padding:2.5rem 1rem;color:var(--tx-2);font-size:.875rem}

/* Toast container */
.toasts{position:fixed;top:1rem;right:1rem;z-index:9999;display:flex;flex-direction:column;gap:.5rem;pointer-events:none}
.toast{
pointer-events:auto;display:flex;align-items:center;gap:.625rem;
padding:.625rem 1rem;border-radius:.5rem;font-size:.8125rem;font-weight:500;
box-shadow:0 4px 12px rgba(0,0,0,.25);min-width:14rem;max-width:22rem;
transform:translateX(110%%);opacity:0;transition:transform .3s ease,opacity .3s ease;
}
.toast.show{transform:translateX(0);opacity:1}
.toast.hide{transform:translateX(110%%);opacity:0}
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
padding:2rem;width:100%%;max-width:24rem;box-shadow:0 8px 32px rgba(0,0,0,.3);
}
.login-box h2{text-align:center;margin-bottom:.375rem;font-size:1.25rem}
.login-box .sub{text-align:center;color:var(--tx-2);font-size:.8125rem;margin-bottom:1.5rem}
.field{margin-bottom:1rem}
.field label{display:block;font-size:.8125rem;font-weight:500;color:var(--tx-2);margin-bottom:.375rem}
.field input{
width:100%%;padding:.5rem .75rem;background:var(--bg-0);color:var(--tx-0);
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
<div class="tab" data-tab="sessions">Sessions <span class="tab-badge" id="badgeSessions">0</span> <span class="kbd">S</span></div>
<div class="tab" data-tab="inspector">Inspector <span class="tab-badge" id="badgeInspector">0</span> <span class="kbd">I</span></div>
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
<table><thead><tr><th>ID</th><th>Account</th><th>Remote Address</th><th>Connected</th><th>Tunnels</th></tr></thead>
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
</div>
<button class="btn-ghost" id="refreshRequests">Refresh <span class="kbd">R</span></button>
</div>
<div class="tbl-wrap">
<table><thead><tr><th>Time</th><th>Method</th><th>Path</th><th>Status</th><th>Duration</th><th>Client IP</th><th>Actions</th></tr></thead>
<tbody id="tbodyRequests"></tbody></table>
</div>
<div class="empty" id="emptyRequests" style="display:none">No captured requests</div>
</div>
</div>

<!-- Login Overlay -->
<div class="overlay" id="loginOverlay">
<div class="login-box">
<h2>WireRift</h2>
<div class="sub">Enter your API token to authenticate</div>
<div class="field">
<label for="tokenInput">API Token</label>
<input type="password" id="tokenInput" placeholder="Enter your API token" autocomplete="off">
</div>
<button class="btn" id="loginBtn" style="width:100%%">Authenticate</button>
<div class="login-err" id="loginErr"></div>
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
var requestsCache = [];

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
    setTimeout(function(){ $('tokenInput').focus(); }, 100);
}
function hideLogin(){
    $('loginOverlay').classList.remove('show');
    $('app').style.display = 'block';
}
function logout(){
    try { sessionStorage.removeItem('wr_t'); } catch(e){}
    apiToken = '';
    if(statsInterval){ clearInterval(statsInterval); statsInterval = null; }
    if(reqInterval){ clearInterval(reqInterval); reqInterval = null; }
    if(uptimeTimer){ clearInterval(uptimeTimer); uptimeTimer = null; }
    if(animFrame){ cancelAnimationFrame(animFrame); animFrame = null; }
    showLogin();
}
function doLogin(){
    var val = $('tokenInput').value.trim();
    if(!val){ $('loginErr').textContent = 'Please enter a token'; return; }
    apiToken = val;
    $('loginErr').textContent = '';
    verifyAndLoad();
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
        toast('Authenticated successfully', 'ok');
    }).catch(function(e){
        try { sessionStorage.removeItem('wr_t'); } catch(ex){}
        $('loginErr').textContent = e.message === 'Unauthorized' ? 'Invalid token' : 'Connection failed';
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
        if(r.status === 401) throw new Error('Unauthorized');
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
function fmtUptime(sec){
    if(!sec || sec < 0) return '-';
    var d = Math.floor(sec / 86400);
    var h = Math.floor((sec %% 86400) / 3600);
    var m = Math.floor((sec %% 3600) / 60);
    var s = Math.floor(sec %% 60);
    if(d > 0) return d + 'd ' + h + 'h ' + m + 'm';
    if(h > 0) return h + 'h ' + m + 'm ' + s + 's';
    if(m > 0) return m + 'm ' + s + 's';
    return s + 's';
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
    var sig = items.map(function(t){ return t.id + t.status; }).join('|');
    if(tbody.getAttribute('data-sig') === sig) return;
    tbody.setAttribute('data-sig', sig);

    var frag = document.createDocumentFragment();
    for(var i = 0; i < items.length; i++){
        var t = items[i];
        var tr = document.createElement('tr');
        var c1 = document.createElement('td');
        var sp1 = document.createElement('span'); sp1.className = 'mono'; sp1.textContent = t.id || '-'; c1.appendChild(sp1);
        tr.appendChild(c1);
        var c2 = document.createElement('td'); c2.textContent = t.type || '-'; tr.appendChild(c2);
        var c3 = document.createElement('td');
        var sp3 = document.createElement('span'); sp3.className = 'mono';
        sp3.textContent = t.type === 'http' ? (t.url || '-') : 'Port ' + (t.port || '-');
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
        var c7 = document.createElement('td'); c7.textContent = fmtTimeDate(t.created_at); tr.appendChild(c7);
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

    var sig = items.map(function(s){ return s.id + s.tunnel_count; }).join('|');
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
        var c5 = document.createElement('td'); c5.textContent = s.tunnel_count || 0; tr.appendChild(c5);

        /* detail row */
        var detailTr = document.createElement('tr');
        detailTr.className = 'sess-detail-row';
        var detailTd = document.createElement('td');
        detailTd.colSpan = 5;
        detailTd.className = 'sess-detail-cell';
        var dl = document.createElement('dl');
        dl.className = 'sess-kv';
        addKV(dl, 'Session ID', s.id);
        addKV(dl, 'Account', s.account_id || 'dev');
        addKV(dl, 'Remote Address', s.remote_addr || '-');
        addKV(dl, 'Connected At', fmtTimeDate(s.connected_at));
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
    if(tbody.getAttribute('data-sig') === sig && !filter) return;
    tbody.setAttribute('data-sig', sig);

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
        var c5 = document.createElement('td'); c5.textContent = fmtDuration(r.duration_ms); tr.appendChild(c5);
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
function exportCurl(index){
    var r = requestsCache[index];
    if(!r){ toast('Request not found', 'er'); return; }
    var cmd = 'curl -X ' + (r.method || 'GET');
    if(r.req_headers){
        var hKeys = Object.keys(r.req_headers);
        for(var i = 0; i < hKeys.length; i++){
            cmd += " -H '" + hKeys[i] + ': ' + r.req_headers[hKeys[i]] + "'";
        }
    }
    if(r.req_body){
        var body = typeof r.req_body === 'string' ? r.req_body : JSON.stringify(r.req_body);
        cmd += " -d '" + body.replace(/'/g, "'" + '\\' + "'" + "'") + "'";
    }
    cmd += ' ' + (r.path || '/');
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
        toast('Refreshed', 'info');
    }
    if(key === 'T'){ e.preventDefault(); switchTab('tunnels'); }
    if(key === 'S'){ e.preventDefault(); switchTab('sessions'); }
    if(key === 'I'){ e.preventDefault(); switchTab('inspector'); }
}

/* -- Event Binding ------------------------------------------ */
function init(){
    initTheme();

    $('themeBtn').onclick = toggleTheme;
    $('authBtn').onclick = showLogin;
    $('loginBtn').onclick = doLogin;
    $('tokenInput').addEventListener('keydown', function(e){
        if(e.key === 'Enter') doLogin();
    });

    var tabEls = qsa('.tab');
    for(var i = 0; i < tabEls.length; i++){
        (function(el){
            el.onclick = function(){ switchTab(el.getAttribute('data-tab')); };
        })(tabEls[i]);
    }

    $('refreshTunnels').onclick = function(){ loadTunnels(); toast('Tunnels refreshed', 'info'); };
    $('refreshSessions').onclick = function(){ loadSessions(); toast('Sessions refreshed', 'info'); };
    $('refreshRequests').onclick = function(){ loadRequests(); toast('Inspector refreshed', 'info'); };

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
