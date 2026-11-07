package clientui

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

const cookieName = "wr_ui"

// NewKey returns a random launch key: whoever holds the address that carries it
// may use the interface.
func NewKey() (string, error) {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

type handler struct {
	m       *Manager
	key     string
	version string
	mux     *http.ServeMux
}

// NewHandler serves the interface. It is meant for a loopback listener, and
// still defends itself: every request must name a loopback host (DNS
// rebinding), carry the launch key as a cookie, and a change must come from
// this page (Origin and a custom header).
func NewHandler(m *Manager, key, version string) http.Handler {
	h := &handler{m: m, key: key, version: version, mux: http.NewServeMux()}
	h.mux.HandleFunc("/api/state", h.api(h.state))
	h.mux.HandleFunc("/api/connect", h.api(h.connect))
	h.mux.HandleFunc("/api/disconnect", h.api(h.disconnect))
	h.mux.HandleFunc("/api/forget", h.api(h.forget))
	h.mux.HandleFunc("/api/tunnels", h.api(h.tunnels))
	h.mux.HandleFunc("/api/tunnels/", h.api(h.tunnel))
	h.mux.HandleFunc("/api/traffic", h.api(h.traffic))
	h.mux.HandleFunc("/api/traffic/", h.api(h.exchange))
	h.mux.HandleFunc("/", h.index)
	return h
}

func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !loopbackHost(r.Host) {
		http.Error(w, "forbidden: use the loopback address", http.StatusForbidden)
		return
	}
	hd := w.Header()
	hd.Set("Cache-Control", "no-store")
	hd.Set("X-Content-Type-Options", "nosniff")
	hd.Set("X-Frame-Options", "DENY")
	hd.Set("Referrer-Policy", "no-referrer")
	h.mux.ServeHTTP(w, r)
}

func loopbackHost(hostport string) bool {
	host := hostport
	if hh, _, err := net.SplitHostPort(hostport); err == nil {
		host = hh
	}
	host = strings.Trim(host, "[]")
	return host == "127.0.0.1" || host == "::1" || strings.EqualFold(host, "localhost")
}

func (h *handler) authorized(r *http.Request) bool {
	c, err := r.Cookie(cookieName)
	return err == nil && subtle.ConstantTimeCompare([]byte(c.Value), []byte(h.key)) == 1
}

func (h *handler) index(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	if k := r.URL.Query().Get("k"); k != "" {
		if subtle.ConstantTimeCompare([]byte(k), []byte(h.key)) != 1 {
			http.Error(w, "wrong key: open the address printed by 'wirerift ui'", http.StatusForbidden)
			return
		}
		http.SetCookie(w, &http.Cookie{Name: cookieName, Value: h.key, Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode})
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	if !h.authorized(r) {
		http.Error(w, "open the address printed by 'wirerift ui' (it carries the key)", http.StatusForbidden)
		return
	}
	nonce, err := NewKey()
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'nonce-"+nonce+"'; style-src 'nonce-"+nonce+"'; style-src-attr 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
	page := strings.NewReplacer("{{NONCE}}", nonce, "{{VERSION}}", h.version).Replace(pageHTML)
	_, _ = w.Write([]byte(page))
}

// api wraps an API handler with the key, Origin and header checks.
func (h *handler) api(next func(http.ResponseWriter, *http.Request)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !h.authorized(r) {
			writeErr(w, http.StatusUnauthorized, "not signed in: open the address printed by 'wirerift ui'")
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			if r.Header.Get("X-WireRift-UI") != "1" {
				writeErr(w, http.StatusForbidden, "missing X-WireRift-UI header")
				return
			}
			if o := r.Header.Get("Origin"); o != "" {
				if u, err := url.Parse(o); err != nil || u.Host != r.Host {
					writeErr(w, http.StatusForbidden, "cross-origin request refused")
					return
				}
			}
		}
		next(w, r)
	}
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}

func readJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(v); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid request body")
		return false
	}
	return true
}

func methodIs(w http.ResponseWriter, r *http.Request, method string) bool {
	if r.Method != method {
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return false
	}
	return true
}

func (h *handler) state(w http.ResponseWriter, r *http.Request) {
	if methodIs(w, r, http.MethodGet) {
		writeJSON(w, http.StatusOK, h.m.State())
	}
}

func (h *handler) connect(w http.ResponseWriter, r *http.Request) {
	if !methodIs(w, r, http.MethodPost) {
		return
	}
	var req struct {
		Server   string `json:"server"`
		Token    string `json:"token"`
		Remember bool   `json:"remember"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	if err := h.m.Connect(req.Server, req.Token, req.Remember); err != nil {
		code := http.StatusBadGateway
		if errors.Is(err, ErrBusy) {
			code = http.StatusConflict
		}
		writeErr(w, code, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, h.m.State())
}

func (h *handler) disconnect(w http.ResponseWriter, r *http.Request) {
	if methodIs(w, r, http.MethodPost) {
		h.m.Disconnect()
		writeJSON(w, http.StatusOK, h.m.State())
	}
}

func (h *handler) forget(w http.ResponseWriter, r *http.Request) {
	if !methodIs(w, r, http.MethodPost) {
		return
	}
	if err := h.m.Forget(); err != nil {
		writeErr(w, http.StatusInternalServerError, "cannot delete the saved login: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, h.m.State())
}

func (h *handler) tunnels(w http.ResponseWriter, r *http.Request) {
	if !methodIs(w, r, http.MethodPost) {
		return
	}
	var spec TunnelSpec
	if !readJSON(w, r, &spec) {
		return
	}
	v, err := h.m.OpenTunnel(spec)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, v)
}

func (h *handler) tunnel(w http.ResponseWriter, r *http.Request) {
	if !methodIs(w, r, http.MethodDelete) {
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/api/tunnels/")
	if id == "" {
		writeErr(w, http.StatusNotFound, "not found")
		return
	}
	if err := h.m.CloseTunnel(id); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "closed"})
}

func (h *handler) traffic(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		since, _ := strconv.ParseUint(r.URL.Query().Get("since"), 10, 64)
		rows, last := h.m.Traffic(since)
		writeJSON(w, http.StatusOK, map[string]any{"rows": rows, "last": last})
	case http.MethodDelete:
		h.m.ClearTraffic()
		writeJSON(w, http.StatusOK, map[string]string{"status": "cleared"})
	default:
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

// exchange serves GET /api/traffic/{id} and POST /api/traffic/{id}/replay.
func (h *handler) exchange(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, "/api/traffic/")
	idStr, action, _ := strings.Cut(rest, "/")
	id, err := strconv.ParseUint(idStr, 10, 64)
	if err != nil {
		writeErr(w, http.StatusNotFound, "not found")
		return
	}
	switch {
	case action == "" && r.Method == http.MethodGet:
		d, ok := h.m.Detail(id)
		if !ok {
			writeErr(w, http.StatusNotFound, "exchange not found (the log keeps the last "+strconv.Itoa(trafficKeep)+")")
			return
		}
		writeJSON(w, http.StatusOK, d)
	case action == "replay" && r.Method == http.MethodPost:
		res, err := h.m.Replay(id)
		if err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, res)
	case action == "" || action == "replay":
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
	default:
		writeErr(w, http.StatusNotFound, "not found")
	}
}
