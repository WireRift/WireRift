package server

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/wirerift/wirerift/internal/auth"
)

func TestMetricsAccessControl(t *testing.T) {
	mgr := auth.NewManager("secret-token")
	cfg := DefaultConfig()
	cfg.AuthManager = mgr
	s := New(cfg, nil)
	s.ready.Store(true)

	cases := []struct {
		name   string
		remote string
		header map[string]string
		want   int
	}{
		{"loopback peer", "127.0.0.1:1", nil, http.StatusOK},
		{"ipv6 loopback peer", "[::1]:1", nil, http.StatusOK},
		{"public peer without token", "203.0.113.9:1", nil, http.StatusUnauthorized},
		{"same-host proxy forwarding a visitor", "127.0.0.1:1", map[string]string{"X-Forwarded-For": "203.0.113.9"}, http.StatusUnauthorized},
		{"same-host proxy with Forwarded", "127.0.0.1:1", map[string]string{"Forwarded": "for=203.0.113.9"}, http.StatusUnauthorized},
		{"public peer with valid bearer", "203.0.113.9:1", map[string]string{"Authorization": "Bearer secret-token"}, http.StatusOK},
		{"public peer with lowercase scheme", "203.0.113.9:1", map[string]string{"Authorization": "bearer secret-token"}, http.StatusOK},
		{"public peer with wrong bearer", "203.0.113.9:1", map[string]string{"Authorization": "Bearer nope"}, http.StatusUnauthorized},
		{"public peer with empty bearer", "203.0.113.9:1", map[string]string{"Authorization": "Bearer "}, http.StatusUnauthorized},
		{"public peer with basic auth", "203.0.113.9:1", map[string]string{"Authorization": "Basic c2VjcmV0LXRva2Vu"}, http.StatusUnauthorized},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
			req.RemoteAddr = tc.remote
			for k, v := range tc.header {
				req.Header.Set(k, v)
			}
			rec := httptest.NewRecorder()
			s.handleHTTPRequest(rec, req)
			if rec.Code != tc.want {
				t.Fatalf("status = %d, want %d", rec.Code, tc.want)
			}
			if tc.want == http.StatusUnauthorized && rec.Header().Get("WWW-Authenticate") == "" {
				t.Error("401 without WWW-Authenticate")
			}
		})
	}

	// Health endpoints stay public.
	for _, path := range []string{"/healthz", "/health/ready"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.RemoteAddr = "203.0.113.9:1"
		rec := httptest.NewRecorder()
		s.handleHTTPRequest(rec, req)
		if rec.Code != http.StatusOK {
			t.Errorf("%s status = %d, want 200", path, rec.Code)
		}
	}
}

func TestEdgeRateConfig(t *testing.T) {
	if got := edgeRate(0, 100); got != 100 {
		t.Errorf("zero -> %v, want default", got)
	}
	if got := edgeRate(-3, 100); got != 100 {
		t.Errorf("negative -> %v, want default", got)
	}
	if got := edgeRate(500, 100); got != 500 {
		t.Errorf("500 -> %v", got)
	}

	cfg := DefaultConfig()
	cfg.EdgeRatePerIP = 1000
	cfg.EdgeRateBurst = 3
	s := New(cfg, nil)
	allowed := 0
	for i := 0; i < 10; i++ {
		if s.rateLimiter.Allow("198.51.100.1") {
			allowed++
		}
	}
	if allowed < 3 || allowed > 6 {
		t.Errorf("burst of 3 allowed %d of 10 immediate requests", allowed)
	}
}
