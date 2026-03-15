package dashboard

import (
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"net/http"
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

	// Static files - fs.Sub on embedded FS always succeeds
	staticContent, _ := fs.Sub(staticFS, "static")
	fileServer := http.FileServer(http.FS(staticContent))
	mux.Handle("/static/", http.StripPrefix("/static/", fileServer))
	mux.HandleFunc("/", d.serveIndex)

	return mux
}

// authMiddleware checks for valid authentication.
func (d *Dashboard) authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Check for Bearer token
		auth := r.Header.Get("Authorization")
		if auth == "" {
			// Check for session cookie
			cookie, err := r.Cookie("wirerift_session")
			if err == nil && cookie.Value != "" {
				// Validate session token
				_, _, err := d.authManager.ValidateToken(cookie.Value)
				if err == nil {
					next(w, r)
					return
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

// serveIndex serves the main index.html
func (d *Dashboard) serveIndex(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(indexHTML))
}

// jsonResponse writes a JSON response
func (d *Dashboard) jsonResponse(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(data)
}

// jsonError writes a JSON error response
func (d *Dashboard) jsonError(w http.ResponseWriter, message string, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": message})
}

// Addr returns the dashboard address.
func (d *Dashboard) Addr() string {
	return fmt.Sprintf(":%d", d.port)
}

// indexHTML is the embedded dashboard HTML
var indexHTML = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>WireRift Dashboard</title>
    <style>
        :root {
            --bg-primary: #0f172a;
            --bg-secondary: #1e293b;
            --bg-tertiary: #334155;
            --text-primary: #f8fafc;
            --text-secondary: #94a3b8;
            --accent: #3b82f6;
            --accent-hover: #2563eb;
            --success: #22c55e;
            --warning: #f59e0b;
            --error: #ef4444;
            --border: #475569;
        }
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: var(--bg-primary);
            color: var(--text-primary);
            min-height: 100vh;
        }
        .container { max-width: 1400px; margin: 0 auto; padding: 2rem; }
        header {
            display: flex; justify-content: space-between; align-items: center;
            margin-bottom: 2rem; padding-bottom: 1rem; border-bottom: 1px solid var(--border);
        }
        h1 { font-size: 1.875rem; font-weight: 700; }
        h1 span { color: var(--accent); }
        .btn {
            background: var(--accent); color: white; border: none;
            padding: 0.75rem 1.5rem; border-radius: 0.5rem;
            cursor: pointer; font-size: 1rem; transition: background 0.2s;
        }
        .btn:hover { background: var(--accent-hover); }
        .btn-outline {
            background: transparent; border: 1px solid var(--border);
            color: var(--text-primary); padding: 0.5rem 1rem;
            border-radius: 0.375rem; cursor: pointer; font-size: 0.875rem;
        }
        .btn-outline:hover { background: var(--bg-tertiary); }
        .stats-grid {
            display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1.5rem; margin-bottom: 2rem;
        }
        .stat-card {
            background: var(--bg-secondary); border-radius: 0.75rem;
            padding: 1.5rem; border: 1px solid var(--border);
        }
        .stat-label { color: var(--text-secondary); font-size: 0.875rem; margin-bottom: 0.5rem; }
        .stat-value { font-size: 2rem; font-weight: 700; }
        .stat-value.success { color: var(--success); }
        .section {
            background: var(--bg-secondary); border-radius: 0.75rem;
            padding: 1.5rem; margin-bottom: 2rem; border: 1px solid var(--border);
        }
        .section-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 1rem; }
        .section h2 { font-size: 1.25rem; font-weight: 600; }
        table { width: 100%; border-collapse: collapse; }
        th, td { text-align: left; padding: 0.75rem 1rem; border-bottom: 1px solid var(--border); }
        th { color: var(--text-secondary); font-weight: 500; font-size: 0.875rem; }
        .status-badge {
            display: inline-block; padding: 0.25rem 0.75rem;
            border-radius: 9999px; font-size: 0.75rem; font-weight: 500;
        }
        .status-badge.active { background: rgba(34, 197, 94, 0.2); color: var(--success); }
        .overlay {
            display: none; position: fixed; inset: 0;
            background: rgba(0, 0, 0, 0.7); justify-content: center;
            align-items: center; z-index: 100;
        }
        .overlay.show { display: flex; }
        .form-box {
            background: var(--bg-secondary); padding: 2rem;
            border-radius: 1rem; width: 100%; max-width: 400px;
        }
        .form-box h2 { margin-bottom: 1.5rem; text-align: center; }
        .form-group { margin-bottom: 1rem; }
        .form-group label { display: block; margin-bottom: 0.5rem; color: var(--text-secondary); }
        .form-group input {
            width: 100%; padding: 0.75rem; background: var(--bg-primary);
            border: 1px solid var(--border); border-radius: 0.5rem;
            color: var(--text-primary); font-size: 1rem;
        }
        .form-group input:focus { outline: none; border-color: var(--accent); }
        .error-msg { color: var(--error); font-size: 0.875rem; margin-top: 0.5rem; text-align: center; }
        .empty-state { text-align: center; padding: 2rem; color: var(--text-secondary); }
        .mono { font-family: monospace; background: var(--bg-primary); padding: 0.25rem 0.5rem; border-radius: 0.25rem; }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>Wire<span>Rift</span></h1>
            <button class="btn" id="authBtn">Login</button>
        </header>
        <div class="stats-grid" id="statsGrid">
            <div class="stat-card"><div class="stat-label">Active Tunnels</div><div class="stat-value" id="tunnelCount">-</div></div>
            <div class="stat-card"><div class="stat-label">Active Sessions</div><div class="stat-value" id="sessionCount">-</div></div>
            <div class="stat-card"><div class="stat-label">Bytes In</div><div class="stat-value" id="bytesIn">-</div></div>
            <div class="stat-card"><div class="stat-label">Bytes Out</div><div class="stat-value" id="bytesOut">-</div></div>
        </div>
        <div class="section">
            <div class="section-header">
                <h2>Active Tunnels</h2>
                <button class="btn-outline" id="refreshTunnels">Refresh</button>
            </div>
            <table id="tunnelsTable">
                <thead><tr><th>ID</th><th>Type</th><th>URL / Port</th><th>Target</th><th>Protection</th><th>Status</th><th>Created</th></tr></thead>
                <tbody id="tunnelsBody"></tbody>
            </table>
            <div class="empty-state" id="tunnelsEmpty" style="display:none;">No active tunnels</div>
        </div>
        <div class="section">
            <div class="section-header">
                <h2>Connected Sessions</h2>
                <button class="btn-outline" id="refreshSessions">Refresh</button>
            </div>
            <table id="sessionsTable">
                <thead><tr><th>ID</th><th>Account</th><th>Remote Address</th><th>Connected</th><th>Tunnels</th></tr></thead>
                <tbody id="sessionsBody"></tbody>
            </table>
            <div class="empty-state" id="sessionsEmpty" style="display:none;">No connected sessions</div>
        </div>
    </div>
    <div class="overlay" id="loginOverlay">
        <div class="form-box">
            <h2>Authentication</h2>
            <div class="form-group">
                <label for="token">API Token</label>
                <input type="password" id="token" placeholder="Enter your API token">
            </div>
            <button class="btn" id="loginBtn">Authenticate</button>
            <div class="error-msg" id="loginError"></div>
        </div>
    </div>
    <script>
    (function() {
        let apiToken = '';
        const $ = id => document.getElementById(id);

        function showLogin() { $('loginOverlay').classList.add('show'); $('token').focus(); }
        function hideLogin() { $('loginOverlay').classList.remove('show'); }
        function logout() { sessionStorage.removeItem('wirerift_token'); apiToken = ''; location.reload(); }

        function login() {
            const token = $('token').value.trim();
            if (!token) { $('loginError').textContent = 'Please enter a token'; return; }
            apiToken = token;
            verifyAndLoad();
        }

        async function verifyAndLoad() {
            try {
                const r = await fetch('/api/stats', { headers: { 'Authorization': 'Bearer ' + apiToken } });
                if (r.ok) {
                    sessionStorage.setItem('wirerift_token', apiToken);
                    hideLogin();
                    $('authBtn').textContent = 'Logout';
                    $('authBtn').onclick = logout;
                    loadAll();
                    setInterval(loadAll, 5000);
                } else {
                    sessionStorage.removeItem('wirerift_token');
                    $('loginError').textContent = 'Invalid token';
                    showLogin();
                }
            } catch (e) { $('loginError').textContent = 'Connection failed'; showLogin(); }
        }

        async function apiFetch(path) {
            const r = await fetch(path, { headers: { 'Authorization': 'Bearer ' + apiToken } });
            if (!r.ok) throw new Error('API error');
            return r.json();
        }

        async function loadAll() { loadStats(); loadTunnels(); loadSessions(); }

        async function loadStats() {
            try {
                const s = await apiFetch('/api/stats');
                $('tunnelCount').textContent = s.active_tunnels || 0;
                $('sessionCount').textContent = s.active_sessions || 0;
                $('bytesIn').textContent = fmtBytes(s.bytes_in || 0);
                $('bytesOut').textContent = fmtBytes(s.bytes_out || 0);
            } catch (e) { console.error('Stats:', e); }
        }

        async function loadTunnels() {
            try {
                const tunnels = await apiFetch('/api/tunnels');
                const tbody = $('tunnelsBody');
                const empty = $('tunnelsEmpty');
                tbody.textContent = '';
                if (!tunnels || tunnels.length === 0) { empty.style.display = 'block'; return; }
                empty.style.display = 'none';
                tunnels.forEach(t => {
                    const tr = document.createElement('tr');
                    tr.appendChild(cell(t.id, 'code'));
                    tr.appendChild(cell(t.type));
                    tr.appendChild(cell(t.type === 'http' ? t.url : 'Port ' + t.port, 'mono'));
                    tr.appendChild(cell(t.target || 'localhost:' + t.local_port));
                    const badges = [];
                    if (t.allowed_ips && t.allowed_ips.length > 0) badges.push('IP');
                    if (t.has_pin) badges.push('PIN');
                    tr.appendChild(cell(badges.length > 0 ? badges.join(' + ') : '-'));
                    tr.appendChild(statusCell('Active', 'active'));
                    tr.appendChild(cell(fmtTime(t.created_at)));
                    tbody.appendChild(tr);
                });
            } catch (e) { console.error('Tunnels:', e); }
        }

        async function loadSessions() {
            try {
                const sessions = await apiFetch('/api/sessions');
                const tbody = $('sessionsBody');
                const empty = $('sessionsEmpty');
                tbody.textContent = '';
                if (!sessions || sessions.length === 0) { empty.style.display = 'block'; return; }
                empty.style.display = 'none';
                sessions.forEach(s => {
                    const tr = document.createElement('tr');
                    tr.appendChild(cell(s.id, 'code'));
                    tr.appendChild(cell(s.account_id || 'dev'));
                    tr.appendChild(cell(s.remote_addr || '-'));
                    tr.appendChild(cell(fmtTime(s.connected_at)));
                    tr.appendChild(cell(s.tunnel_count || 0));
                    tbody.appendChild(tr);
                });
            } catch (e) { console.error('Sessions:', e); }
        }

        function cell(text, cls) {
            const td = document.createElement('td');
            if (cls) { const el = document.createElement(cls); el.textContent = text; td.appendChild(el); }
            else { td.textContent = text; }
            return td;
        }

        function statusCell(text, status) {
            const td = document.createElement('td');
            const span = document.createElement('span');
            span.className = 'status-badge ' + status;
            span.textContent = text;
            td.appendChild(span);
            return td;
        }

        function fmtBytes(bytes) {
            if (bytes === 0) return '0 B';
            const k = 1024, sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
            const i = Math.floor(Math.log(bytes) / Math.log(k));
            return (bytes / Math.pow(k, i)).toFixed(1) + ' ' + sizes[i];
        }

        function fmtTime(t) { return t ? new Date(t).toLocaleString() : '-'; }

        // Event listeners
        $('authBtn').onclick = showLogin;
        $('loginBtn').onclick = login;
        $('refreshTunnels').onclick = loadTunnels;
        $('refreshSessions').onclick = loadSessions;
        $('token').addEventListener('keypress', e => { if (e.key === 'Enter') login(); });

        // Init
        const saved = sessionStorage.getItem('wirerift_token');
        if (saved) { apiToken = saved; verifyAndLoad(); } else { showLogin(); }
    })();
    </script>
</body>
</html>`
