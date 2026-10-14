package server

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"mime"
	"net"
	"net/http"
	"sync"
	"time"
)

const (
	pinMaxFailures = 5
	pinLockout     = 5 * time.Minute
)

// pinGuard throttles PIN guessing per tunnel and client IP.
type pinGuard struct {
	mu       sync.Mutex
	failures map[string]*pinFailure
}

type pinFailure struct {
	count int
	until time.Time // locked until (zero = not locked)
	last  time.Time
}

func (g *pinGuard) locked(key string) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	f := g.failures[key]
	return f != nil && time.Now().Before(f.until)
}

// fail records a failed attempt and returns true once the key is locked.
func (g *pinGuard) fail(key string) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.failures == nil {
		g.failures = make(map[string]*pinFailure)
	}
	now := time.Now()
	if len(g.failures) > 10000 { // bound memory: drop stale entries
		for k, f := range g.failures {
			if now.Sub(f.last) > pinLockout {
				delete(g.failures, k)
			}
		}
	}
	f := g.failures[key]
	if f == nil || now.Sub(f.last) > pinLockout {
		f = &pinFailure{}
		g.failures[key] = f
	}
	f.count++
	f.last = now
	if f.count >= pinMaxFailures {
		f.until = now.Add(pinLockout)
		f.count = 0
	}
	return now.Before(f.until)
}

func (g *pinGuard) reset(key string) {
	g.mu.Lock()
	delete(g.failures, key)
	g.mu.Unlock()
}

// pinMAC computes an HMAC of the PIN for safe cookie storage using a server-level secret.
func (s *Server) pinMAC(pin, subdomain string) string {
	mac := hmac.New(sha256.New, s.pinSecret)
	mac.Write([]byte(subdomain + ":" + pin))
	return hex.EncodeToString(mac.Sum(nil))
}

// pinMatch performs constant-time comparison of a submitted PIN against the expected PIN.
func pinMatch(submitted, expected string) bool {
	return subtle.ConstantTimeCompare([]byte(submitted), []byte(expected)) == 1
}

// checkPIN validates PIN protection for a tunnel.
// Returns true if access is allowed, false if response was written (PIN page or error).
func (s *Server) checkPIN(w http.ResponseWriter, r *http.Request, pin, subdomain string) bool {
	cookieName := "wirerift_pin_" + subdomain
	ip := r.RemoteAddr
	if host, _, err := net.SplitHostPort(ip); err == nil {
		ip = host
	}
	guardKey := subdomain + "|" + ip
	if s.pinGuard.locked(guardKey) {
		w.Header().Set("Retry-After", "300")
		http.Error(w, "Too many invalid PIN attempts. Try again later.", http.StatusTooManyRequests)
		return false
	}
	expectedMAC := s.pinMAC(pin, subdomain)

	// Check PIN cookie (stores HMAC, not raw PIN)
	if cookie, err := r.Cookie(cookieName); err == nil {
		if subtle.ConstantTimeCompare([]byte(cookie.Value), []byte(expectedMAC)) == 1 {
			return true
		}
	}

	// Check X-WireRift-PIN header (for API/CLI access)
	if headerPIN := r.Header.Get("X-WireRift-PIN"); headerPIN != "" {
		if pinMatch(headerPIN, pin) {
			s.pinGuard.reset(guardKey)
			return true
		}
		s.pinGuard.fail(guardKey)
	}

	// setPINcookie sets a secure HMAC-based PIN cookie
	setPINcookie := func() {
		http.SetCookie(w, &http.Cookie{
			Name:     cookieName,
			Value:    expectedMAC,
			Path:     "/",
			MaxAge:   86400, // 24 hours
			HttpOnly: true,
			Secure:   r.TLS != nil,
			SameSite: http.SameSiteStrictMode,
		})
	}

	// Check ?pin= query parameter
	if queryPIN := r.URL.Query().Get("pin"); queryPIN != "" && !pinMatch(queryPIN, pin) {
		s.pinGuard.fail(guardKey)
	} else if queryPIN != "" {
		s.pinGuard.reset(guardKey)
		setPINcookie()
		// Redirect to clean URL (strip pin param)
		q := r.URL.Query()
		q.Del("pin")
		cleanURL := r.URL.Path
		if encoded := q.Encode(); encoded != "" {
			cleanURL += "?" + encoded
		}
		http.Redirect(w, r, cleanURL, http.StatusFound)
		return false
	}

	// Handle POST from PIN form
	if mt, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type")); r.Method == http.MethodPost && mt == "application/x-www-form-urlencoded" {
		r.ParseForm()
		if pinMatch(r.FormValue("pin"), pin) {
			s.pinGuard.reset(guardKey)
			setPINcookie()
			http.Redirect(w, r, r.URL.Path, http.StatusFound)
			return false
		}
		// Wrong PIN - show form again with error
		s.pinGuard.fail(guardKey)
		s.servePINPage(w, subdomain, true)
		return false
	}

	// Show PIN entry page
	s.servePINPage(w, subdomain, false)
	return false
}

// servePINPage serves the PIN entry HTML page.
func (s *Server) servePINPage(w http.ResponseWriter, _ string, showError bool) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusUnauthorized)

	errorHTML := ""
	if showError {
		errorHTML = `<p style="color:#ef4444;margin-bottom:16px;font-size:14px">Invalid PIN. Please try again.</p>`
	}

	fmt.Fprintf(w, `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>PIN Required - WireRift</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;background:#0f172a;color:#e2e8f0;display:flex;align-items:center;justify-content:center;min-height:100vh}
.card{background:#1e293b;border:1px solid #334155;border-radius:12px;padding:40px;max-width:400px;width:90%%;text-align:center}
.logo{font-size:24px;font-weight:700;margin-bottom:8px;color:#fff}
.sub{color:#94a3b8;font-size:14px;margin-bottom:24px}
form{display:flex;flex-direction:column;gap:12px}
input[type=password]{background:#0f172a;border:1px solid #475569;border-radius:8px;padding:12px 16px;color:#e2e8f0;font-size:16px;text-align:center;letter-spacing:8px;outline:none}
input[type=password]:focus{border-color:#6366f1}
button{background:#6366f1;color:#fff;border:none;border-radius:8px;padding:12px;font-size:16px;font-weight:600;cursor:pointer}
button:hover{background:#4f46e5}
.hint{color:#64748b;font-size:12px;margin-top:16px}
</style>
</head>
<body>
<div class="card">
<div class="logo">WireRift</div>
<p class="sub">This tunnel is PIN protected</p>
%s
<form method="POST">
<input type="password" name="pin" placeholder="Enter PIN" autocomplete="off" autofocus required maxlength="32">
<button type="submit">Unlock</button>
</form>
<p class="hint">You can also pass the PIN via header: X-WireRift-PIN</p>
</div>
</body>
</html>`, errorHTML)
}
