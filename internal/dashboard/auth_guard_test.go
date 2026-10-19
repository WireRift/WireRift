package dashboard

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/wirerift/wirerift/internal/auth"
)

func TestAuthLockoutAfterRepeatedBadTokens(t *testing.T) {
	mgr := auth.NewManager()
	d := New(Config{AuthManager: mgr})
	h := d.authMiddleware(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })

	do := func(ip, token string) int {
		r := httptest.NewRequest("GET", "/api/tunnels", nil)
		r.RemoteAddr = ip + ":1234"
		r.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		h(w, r)
		return w.Code
	}

	for i := 0; i < authMaxFailures; i++ {
		if code := do("203.0.113.5", "wrong"); code != http.StatusUnauthorized {
			t.Fatalf("attempt %d: code = %d, want 401", i, code)
		}
	}
	// Locked: even a valid token is refused until the lockout expires.
	if code := do("203.0.113.5", mgr.DevToken()); code != http.StatusTooManyRequests {
		t.Errorf("locked code = %d, want 429", code)
	}
	// Other IPs are unaffected, and success resets the counter.
	if code := do("198.51.100.1", mgr.DevToken()); code != http.StatusOK {
		t.Errorf("other IP code = %d, want 200", code)
	}
}

func TestAuthMissingCredentialsDoNotCountAsFailures(t *testing.T) {
	d := New(Config{AuthManager: auth.NewManager()})
	h := d.authMiddleware(func(w http.ResponseWriter, r *http.Request) {})
	for i := 0; i < authMaxFailures+5; i++ {
		r := httptest.NewRequest("GET", "/api/tunnels", nil)
		r.RemoteAddr = "203.0.113.7:1"
		w := httptest.NewRecorder()
		h(w, r)
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("code = %d, want 401 (never 429 without credentials)", w.Code)
		}
	}
}

// Unknown API paths (including endpoints that were removed, like /api/domains)
// answer 404 JSON instead of the web UI page.
func TestUnknownAPIPathsReturn404JSON(t *testing.T) {
	d := New(Config{AuthManager: auth.NewManager()})
	h := d.Handler()
	for _, path := range []string{"/api/domains", "/api/domains/x.example.com/verify", "/api/nonexistent"} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest("GET", path, nil))
		if w.Code != http.StatusNotFound || !strings.HasPrefix(w.Header().Get("Content-Type"), "application/json") {
			t.Errorf("%s: %d %q, want 404 JSON", path, w.Code, w.Header().Get("Content-Type"))
		}
	}
	// The UI itself and the real API are unaffected.
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", "/", nil))
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "<html") {
		t.Errorf("/ : %d", w.Code)
	}
	w = httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", "/api/tunnels", nil))
	if w.Code != http.StatusUnauthorized {
		t.Errorf("/api/tunnels without credentials: %d, want 401", w.Code)
	}
}
