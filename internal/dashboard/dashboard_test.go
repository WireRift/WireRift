package dashboard

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/wirerift/wirerift/internal/auth"
	"github.com/wirerift/wirerift/internal/config"
	"github.com/wirerift/wirerift/internal/server"
)

func TestNew(t *testing.T) {
	d := New(Config{})
	if d == nil {
		t.Fatal("New returned nil")
	}
	if d.port != 4040 {
		t.Errorf("Default port = %d, want 4040", d.port)
	}
}

func TestNewWithCustomPort(t *testing.T) {
	d := New(Config{Port: 8080})
	if d.port != 8080 {
		t.Errorf("Port = %d, want 8080", d.port)
	}
}

func TestHandlerReturnsHandler(t *testing.T) {
	d := New(Config{})
	h := d.Handler()
	if h == nil {
		t.Error("Handler returned nil")
	}
}

func TestAuthMiddlewareRequiresAuth(t *testing.T) {
	authMgr := auth.NewManager()
	srv := server.New(server.DefaultConfig(), nil)

	d := New(Config{
		Server:      srv,
		AuthManager: authMgr,
	})

	handler := d.Handler()

	// Test without auth - should fail
	req := httptest.NewRequest("GET", "/api/tunnels", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("Status without auth = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

func TestAuthMiddlewareWithInvalidToken(t *testing.T) {
	authMgr := auth.NewManager()
	srv := server.New(server.DefaultConfig(), nil)

	d := New(Config{
		Server:      srv,
		AuthManager: authMgr,
	})

	handler := d.Handler()

	// Test with invalid token
	req := httptest.NewRequest("GET", "/api/tunnels", nil)
	req.Header.Set("Authorization", "Bearer invalid_token")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("Status with invalid token = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

func TestAddr(t *testing.T) {
	d := New(Config{Port: 3000})
	expected := ":3000"
	if d.Addr() != expected {
		t.Errorf("Addr() = %q, want %q", d.Addr(), expected)
	}
}

func TestHandleTunnelsNotAllowedMethod(t *testing.T) {
	authMgr := auth.NewManager()
	srv := server.New(server.DefaultConfig(), nil)
	domainMgr := config.NewDomainManager("test.dev")

	d := New(Config{
		Server:      srv,
		AuthManager: authMgr,
		DomainMgr:   domainMgr,
	})

	handler := d.Handler()

	// POST to /api/tunnels should fail
	req := httptest.NewRequest("POST", "/api/tunnels", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("Status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

func TestIndexHTML(t *testing.T) {
	d := New(Config{})
	req := httptest.NewRequest("GET", "/", nil)
	rec := httptest.NewRecorder()

	d.serveIndex(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("Status = %d, want %d", rec.Code, http.StatusOK)
	}

	contentType := rec.Header().Get("Content-Type")
	if contentType != "text/html; charset=utf-8" {
		t.Errorf("Content-Type = %q, want %q", contentType, "text/html; charset=utf-8")
	}
}

func TestAuthMiddlewareWithValidToken(t *testing.T) {
	authMgr := auth.NewManager()
	srv := server.New(server.DefaultConfig(), nil)

	d := New(Config{
		Server:      srv,
		AuthManager: authMgr,
	})

	handler := d.Handler()

	// Test with valid dev token
	req := httptest.NewRequest("GET", "/api/tunnels", nil)
	req.Header.Set("Authorization", "Bearer "+authMgr.DevToken())
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("Status with valid token = %d, want %d", rec.Code, http.StatusOK)
	}
}

func TestAuthMiddlewareWithSessionCookie(t *testing.T) {
	authMgr := auth.NewManager()
	srv := server.New(server.DefaultConfig(), nil)

	d := New(Config{
		Server:      srv,
		AuthManager: authMgr,
	})

	handler := d.Handler()

	// Test with session cookie using dev token
	req := httptest.NewRequest("GET", "/api/tunnels", nil)
	req.AddCookie(&http.Cookie{
		Name:  "wirerift_session",
		Value: authMgr.DevToken(),
	})
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("Status with session cookie = %d, want %d", rec.Code, http.StatusOK)
	}
}

func TestAuthMiddlewareWithInvalidAuthorizationHeader(t *testing.T) {
	authMgr := auth.NewManager()
	srv := server.New(server.DefaultConfig(), nil)

	d := New(Config{
		Server:      srv,
		AuthManager: authMgr,
	})

	handler := d.Handler()

	tests := []struct {
		name   string
		header string
	}{
		{"No Bearer prefix", "invalid_token"},
		{"Wrong prefix", "Basic dXNlcjpwYXNz"},
		{"Empty after Bearer", "Bearer "},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/api/tunnels", nil)
			req.Header.Set("Authorization", tt.header)
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			if rec.Code != http.StatusUnauthorized {
				t.Errorf("Status = %d, want %d", rec.Code, http.StatusUnauthorized)
			}
		})
	}
}

func TestHandleSessions(t *testing.T) {
	authMgr := auth.NewManager()
	srv := server.New(server.DefaultConfig(), nil)

	d := New(Config{
		Server:      srv,
		AuthManager: authMgr,
	})

	handler := d.Handler()

	// GET /api/sessions
	req := httptest.NewRequest("GET", "/api/sessions", nil)
	req.Header.Set("Authorization", "Bearer "+authMgr.DevToken())
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("Status = %d, want %d", rec.Code, http.StatusOK)
	}
}

func TestHandleStats(t *testing.T) {
	authMgr := auth.NewManager()
	srv := server.New(server.DefaultConfig(), nil)

	d := New(Config{
		Server:       srv,
		AuthManager:  authMgr,
		Port:         4040,
		HTTPSEnabled: true,
	})

	handler := d.Handler()

	// GET /api/stats
	req := httptest.NewRequest("GET", "/api/stats", nil)
	req.Header.Set("Authorization", "Bearer "+authMgr.DevToken())
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("Status = %d, want %d", rec.Code, http.StatusOK)
	}
}

func TestHandleDomainsGet(t *testing.T) {
	authMgr := auth.NewManager()
	srv := server.New(server.DefaultConfig(), nil)
	domainMgr := config.NewDomainManager("test.dev")

	d := New(Config{
		Server:      srv,
		AuthManager: authMgr,
		DomainMgr:   domainMgr,
	})

	handler := d.Handler()

	// GET /api/domains
	req := httptest.NewRequest("GET", "/api/domains", nil)
	req.Header.Set("Authorization", "Bearer "+authMgr.DevToken())
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("Status = %d, want %d", rec.Code, http.StatusOK)
	}
}

func TestHandleDomainsGetNilManager(t *testing.T) {
	authMgr := auth.NewManager()
	srv := server.New(server.DefaultConfig(), nil)

	d := New(Config{
		Server:      srv,
		AuthManager: authMgr,
		DomainMgr:   nil,
	})

	handler := d.Handler()

	// GET /api/domains with nil domain manager
	req := httptest.NewRequest("GET", "/api/domains", nil)
	req.Header.Set("Authorization", "Bearer "+authMgr.DevToken())
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("Status = %d, want %d", rec.Code, http.StatusOK)
	}
}

func TestHandleDomainsPostInvalidJSON(t *testing.T) {
	authMgr := auth.NewManager()
	srv := server.New(server.DefaultConfig(), nil)
	domainMgr := config.NewDomainManager("test.dev")

	d := New(Config{
		Server:      srv,
		AuthManager: authMgr,
		DomainMgr:   domainMgr,
	})

	handler := d.Handler()

	// POST /api/domains with invalid JSON
	req := httptest.NewRequest("POST", "/api/domains", nil)
	req.Header.Set("Authorization", "Bearer "+authMgr.DevToken())
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("Status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
}

func TestHandleDomainsPostNilManager(t *testing.T) {
	authMgr := auth.NewManager()
	srv := server.New(server.DefaultConfig(), nil)

	d := New(Config{
		Server:      srv,
		AuthManager: authMgr,
		DomainMgr:   nil,
	})

	handler := d.Handler()

	// POST /api/domains with nil domain manager (send valid JSON)
	body := strings.NewReader(`{"domain":"test.dev","account_id":"test"}`)
	req := httptest.NewRequest("POST", "/api/domains", body)
	req.Header.Set("Authorization", "Bearer "+authMgr.DevToken())
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("Status = %d, want %d", rec.Code, http.StatusServiceUnavailable)
	}
}

func TestHandleDomainsNotAllowedMethod(t *testing.T) {
	authMgr := auth.NewManager()
	srv := server.New(server.DefaultConfig(), nil)
	domainMgr := config.NewDomainManager("test.dev")

	d := New(Config{
		Server:      srv,
		AuthManager: authMgr,
		DomainMgr:   domainMgr,
	})

	handler := d.Handler()

	// DELETE /api/domains (not allowed at root level)
	req := httptest.NewRequest("DELETE", "/api/domains", nil)
	req.Header.Set("Authorization", "Bearer "+authMgr.DevToken())
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("Status = %d, want %d", rec.Code, http.StatusMethodNotAllowed)
	}
}

func TestJsonResponse(t *testing.T) {
	d := New(Config{})
	rec := httptest.NewRecorder()

	d.jsonResponse(rec, map[string]string{"test": "value"})

	if rec.Code != http.StatusOK {
		t.Errorf("Status = %d, want %d", rec.Code, http.StatusOK)
	}

	contentType := rec.Header().Get("Content-Type")
	if contentType != "application/json" {
		t.Errorf("Content-Type = %q, want %q", contentType, "application/json")
	}
}

func TestJsonError(t *testing.T) {
	d := New(Config{})
	rec := httptest.NewRecorder()

	d.jsonError(rec, "Test error", http.StatusBadRequest)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("Status = %d, want %d", rec.Code, http.StatusBadRequest)
	}

	contentType := rec.Header().Get("Content-Type")
	if contentType != "application/json" {
		t.Errorf("Content-Type = %q, want %q", contentType, "application/json")
	}
}

func TestHandleDomainActionsGet(t *testing.T) {
	authMgr := auth.NewManager()
	srv := server.New(server.DefaultConfig(), nil)
	domainMgr := config.NewDomainManager("test.dev")
	// Add a domain for testing
	domainMgr.AddDomain("example.test.dev", "test-account")

	d := New(Config{
		Server:      srv,
		AuthManager: authMgr,
		DomainMgr:   domainMgr,
	})

	handler := d.Handler()

	// GET /api/domains/example.test.dev
	req := httptest.NewRequest("GET", "/api/domains/example.test.dev", nil)
	req.Header.Set("Authorization", "Bearer "+authMgr.DevToken())
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("Status = %d, want %d", rec.Code, http.StatusOK)
	}
}

func TestHandleDomainActionsGetNotFound(t *testing.T) {
	authMgr := auth.NewManager()
	srv := server.New(server.DefaultConfig(), nil)
	domainMgr := config.NewDomainManager("test.dev")

	d := New(Config{
		Server:      srv,
		AuthManager: authMgr,
		DomainMgr:   domainMgr,
	})

	handler := d.Handler()

	// GET /api/domains/nonexistent.test.dev
	req := httptest.NewRequest("GET", "/api/domains/nonexistent.test.dev", nil)
	req.Header.Set("Authorization", "Bearer "+authMgr.DevToken())
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("Status = %d, want %d", rec.Code, http.StatusNotFound)
	}
}

func TestHandleDomainActionsDelete(t *testing.T) {
	authMgr := auth.NewManager()
	srv := server.New(server.DefaultConfig(), nil)
	domainMgr := config.NewDomainManager("test.dev")
	// Add a domain for testing
	domainMgr.AddDomain("todelete.test.dev", "test-account")

	d := New(Config{
		Server:      srv,
		AuthManager: authMgr,
		DomainMgr:   domainMgr,
	})

	handler := d.Handler()

	// DELETE /api/domains/todelete.test.dev
	req := httptest.NewRequest("DELETE", "/api/domains/todelete.test.dev", nil)
	req.Header.Set("Authorization", "Bearer "+authMgr.DevToken())
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Errorf("Status = %d, want %d", rec.Code, http.StatusNoContent)
	}
}

func TestHandleDomainActionsNilManager(t *testing.T) {
	authMgr := auth.NewManager()
	srv := server.New(server.DefaultConfig(), nil)

	d := New(Config{
		Server:      srv,
		AuthManager: authMgr,
		DomainMgr:   nil,
	})

	handler := d.Handler()

	// GET /api/domains/example.test.dev with nil domain manager
	req := httptest.NewRequest("GET", "/api/domains/example.test.dev", nil)
	req.Header.Set("Authorization", "Bearer "+authMgr.DevToken())
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("Status = %d, want %d", rec.Code, http.StatusServiceUnavailable)
	}
}

func TestHandleDomainActionsDNS(t *testing.T) {
	authMgr := auth.NewManager()
	srv := server.New(server.DefaultConfig(), nil)
	domainMgr := config.NewDomainManager("test.dev")
	domainMgr.AddDomain("test.example.test.dev", "test-account")

	d := New(Config{
		Server:      srv,
		AuthManager: authMgr,
		DomainMgr:   domainMgr,
	})

	handler := d.Handler()

	// GET /api/domains/test.example.test.dev/dns (POST to trigger action handler)
	req := httptest.NewRequest("POST", "/api/domains/test.example.test.dev/dns", nil)
	req.Header.Set("Authorization", "Bearer "+authMgr.DevToken())
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("Status = %d, want %d", rec.Code, http.StatusOK)
	}
}

func TestHandleDomainActionsVerify(t *testing.T) {
	authMgr := auth.NewManager()
	srv := server.New(server.DefaultConfig(), nil)
	domainMgr := config.NewDomainManager("test.dev")
	domainMgr.AddDomain("verify.test.dev", "test-account")

	d := New(Config{
		Server:      srv,
		AuthManager: authMgr,
		DomainMgr:   domainMgr,
	})

	handler := d.Handler()

	// POST /api/domains/verify.test.dev/verify
	req := httptest.NewRequest("POST", "/api/domains/verify.test.dev/verify", nil)
	req.Header.Set("Authorization", "Bearer "+authMgr.DevToken())
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("Status = %d, want %d", rec.Code, http.StatusOK)
	}
}

func TestHandleDomainActionsUnknownAction(t *testing.T) {
	authMgr := auth.NewManager()
	srv := server.New(server.DefaultConfig(), nil)
	domainMgr := config.NewDomainManager("test.dev")
	domainMgr.AddDomain("unknown.test.dev", "test-account")

	d := New(Config{
		Server:      srv,
		AuthManager: authMgr,
		DomainMgr:   domainMgr,
	})

	handler := d.Handler()

	// POST /api/domains/unknown.test.dev/unknown
	req := httptest.NewRequest("POST", "/api/domains/unknown.test.dev/unknown", nil)
	req.Header.Set("Authorization", "Bearer "+authMgr.DevToken())
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("Status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
}

func TestHandleDomainActionsMethodNotAllowed(t *testing.T) {
	authMgr := auth.NewManager()
	srv := server.New(server.DefaultConfig(), nil)
	domainMgr := config.NewDomainManager("test.dev")
	domainMgr.AddDomain("method.test.dev", "test-account")

	d := New(Config{
		Server:      srv,
		AuthManager: authMgr,
		DomainMgr:   domainMgr,
	})

	handler := d.Handler()

	// PUT /api/domains/method.test.dev (not allowed)
	req := httptest.NewRequest("PUT", "/api/domains/method.test.dev", nil)
	req.Header.Set("Authorization", "Bearer "+authMgr.DevToken())
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("Status = %d, want %d", rec.Code, http.StatusMethodNotAllowed)
	}
}

func TestServeIndex(t *testing.T) {
	d := New(Config{})
	req := httptest.NewRequest("GET", "/dashboard", nil)
	rec := httptest.NewRecorder()

	d.serveIndex(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("Status = %d, want %d", rec.Code, http.StatusOK)
	}

	contentType := rec.Header().Get("Content-Type")
	if contentType != "text/html; charset=utf-8" {
		t.Errorf("Content-Type = %q, want %q", contentType, "text/html; charset=utf-8")
	}

	// Should contain HTML
	body := rec.Body.String()
	if !strings.Contains(body, "<!DOCTYPE html>") {
		t.Error("Response should contain DOCTYPE html")
	}

	// Should have CSP nonce header
	csp := rec.Header().Get("Content-Security-Policy")
	if csp == "" {
		t.Error("Expected Content-Security-Policy header")
	}
	if !strings.Contains(csp, "script-src 'nonce-") {
		t.Errorf("CSP should contain nonce-based script-src, got: %s", csp)
	}

	// HTML should contain script tag with nonce attribute
	if !strings.Contains(body, `<script nonce="`) {
		t.Error("Script tag should have nonce attribute")
	}
}

func TestServeIndex_NonceUniqueness(t *testing.T) {
	d := New(Config{})

	// Two requests should get different nonces
	req1 := httptest.NewRequest("GET", "/", nil)
	rec1 := httptest.NewRecorder()
	d.serveIndex(rec1, req1)

	req2 := httptest.NewRequest("GET", "/", nil)
	rec2 := httptest.NewRecorder()
	d.serveIndex(rec2, req2)

	csp1 := rec1.Header().Get("Content-Security-Policy")
	csp2 := rec2.Header().Get("Content-Security-Policy")

	if csp1 == csp2 {
		t.Error("CSP nonces should be different for each request")
	}
}

func TestSecurityHeaders(t *testing.T) {
	d := New(Config{})
	handler := d.Handler()

	req := httptest.NewRequest("GET", "/api/stats", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Header().Get("X-Frame-Options") != "DENY" {
		t.Error("Expected X-Frame-Options: DENY")
	}
	if rec.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Error("Expected X-Content-Type-Options: nosniff")
	}
	if rec.Header().Get("Referrer-Policy") != "strict-origin-when-cross-origin" {
		t.Error("Expected Referrer-Policy header")
	}
}

func TestHandleDomainsPostSuccess(t *testing.T) {
	authMgr := auth.NewManager()
	srv := server.New(server.DefaultConfig(), nil)
	domainMgr := config.NewDomainManager("test.dev")

	// Create account first
	authMgr.CreateAccount("test@test.com", "Test Account")

	d := New(Config{
		Server:      srv,
		AuthManager: authMgr,
		DomainMgr:   domainMgr,
	})

	handler := d.Handler()

	// POST /api/domains with valid JSON
	body := strings.NewReader(`{"domain":"new.test.dev","account_id":"dev_account"}`)
	req := httptest.NewRequest("POST", "/api/domains", body)
	req.Header.Set("Authorization", "Bearer "+authMgr.DevToken())
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("Status = %d, want %d", rec.Code, http.StatusOK)
	}
}

// TestHandleTunnelsMethodNotAllowed tests tunnels endpoint with unsupported method
func TestHandleTunnelsMethodNotAllowed(t *testing.T) {
	authMgr := auth.NewManager()
	srv := server.New(server.DefaultConfig(), nil)

	d := New(Config{
		Server:      srv,
		AuthManager: authMgr,
	})

	handler := d.Handler()

	// POST /api/tunnels (not allowed)
	req := httptest.NewRequest("POST", "/api/tunnels", nil)
	req.Header.Set("Authorization", "Bearer "+authMgr.DevToken())
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("Status = %d, want %d", rec.Code, http.StatusMethodNotAllowed)
	}
}

// TestHandleSessionsMethodNotAllowed tests sessions endpoint with unsupported method
func TestHandleSessionsMethodNotAllowed(t *testing.T) {
	authMgr := auth.NewManager()
	srv := server.New(server.DefaultConfig(), nil)

	d := New(Config{
		Server:      srv,
		AuthManager: authMgr,
	})

	handler := d.Handler()

	// POST /api/sessions (not allowed)
	req := httptest.NewRequest("POST", "/api/sessions", nil)
	req.Header.Set("Authorization", "Bearer "+authMgr.DevToken())
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("Status = %d, want %d", rec.Code, http.StatusMethodNotAllowed)
	}
}

// TestHandleStatsWithData tests stats endpoint with actual server data
func TestHandleStatsWithData(t *testing.T) {
	authMgr := auth.NewManager()
	srv := server.New(server.DefaultConfig(), nil)

	d := New(Config{
		Server:      srv,
		AuthManager: authMgr,
	})

	handler := d.Handler()

	req := httptest.NewRequest("GET", "/api/stats", nil)
	req.Header.Set("Authorization", "Bearer "+authMgr.DevToken())
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("Status = %d, want %d", rec.Code, http.StatusOK)
	}

	// Parse response
	var stats map[string]interface{}
	if err := json.NewDecoder(rec.Body).Decode(&stats); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	// Should have uptime, active_tunnels, and active_sessions
	if _, ok := stats["uptime"]; !ok {
		t.Error("Response should contain uptime")
	}
	if _, ok := stats["active_tunnels"]; !ok {
		t.Error("Response should contain active_tunnels")
	}
	if _, ok := stats["active_sessions"]; !ok {
		t.Error("Response should contain active_sessions")
	}
}

// TestHandleStatsMethodNotAllowed tests stats endpoint with POST method
func TestHandleStatsMethodNotAllowed(t *testing.T) {
	authMgr := auth.NewManager()
	srv := server.New(server.DefaultConfig(), nil)

	d := New(Config{
		Server:      srv,
		AuthManager: authMgr,
	})

	handler := d.Handler()

	// POST should not be allowed
	req := httptest.NewRequest("POST", "/api/stats", nil)
	req.Header.Set("Authorization", "Bearer "+authMgr.DevToken())
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("Status = %d, want %d", rec.Code, http.StatusMethodNotAllowed)
	}
}

// TestHandleDomainActionsNoDomain tests domain actions with empty domain
func TestHandleDomainActionsNoDomain(t *testing.T) {
	authMgr := auth.NewManager()
	srv := server.New(server.DefaultConfig(), nil)
	domainMgr := config.NewDomainManager("test.dev")

	d := New(Config{
		Server:      srv,
		AuthManager: authMgr,
		DomainMgr:   domainMgr,
	})

	handler := d.Handler()

	// GET /api/domains/ (empty domain)
	req := httptest.NewRequest("GET", "/api/domains/", nil)
	req.Header.Set("Authorization", "Bearer "+authMgr.DevToken())
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	// Empty domain results in GetDomain("") which returns "not found" error → 404
	if rec.Code != http.StatusNotFound {
		t.Errorf("Status = %d, want %d", rec.Code, http.StatusNotFound)
	}
}

// TestHandleDomainActionsDeleteNotFound tests deleting non-existent domain
func TestHandleDomainActionsDeleteNotFound(t *testing.T) {
	authMgr := auth.NewManager()
	srv := server.New(server.DefaultConfig(), nil)
	domainMgr := config.NewDomainManager("test.dev")

	d := New(Config{
		Server:      srv,
		AuthManager: authMgr,
		DomainMgr:   domainMgr,
	})

	handler := d.Handler()

	// DELETE /api/domains/nonexistent.test.dev
	// RemoveDomain doesn't error for non-existent domains, returns 204
	req := httptest.NewRequest("DELETE", "/api/domains/nonexistent.test.dev", nil)
	req.Header.Set("Authorization", "Bearer "+authMgr.DevToken())
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Errorf("Status = %d, want %d", rec.Code, http.StatusNoContent)
	}
}

// TestHandleDomainsPostInvalidDomain tests POST /api/domains with an invalid domain name
func TestHandleDomainsPostInvalidDomain(t *testing.T) {
	authMgr := auth.NewManager()
	srv := server.New(server.DefaultConfig(), nil)
	domainMgr := config.NewDomainManager("test.dev")

	d := New(Config{
		Server:      srv,
		AuthManager: authMgr,
		DomainMgr:   domainMgr,
	})

	handler := d.Handler()

	// POST with empty domain (invalid)
	body := strings.NewReader(`{"domain":"","account_id":"test"}`)
	req := httptest.NewRequest("POST", "/api/domains", body)
	req.Header.Set("Authorization", "Bearer "+authMgr.DevToken())
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("Status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
}

// TestHandleDomainsPostDuplicateDomain tests POST /api/domains with a duplicate domain
func TestHandleDomainsPostDuplicateDomain(t *testing.T) {
	authMgr := auth.NewManager()
	srv := server.New(server.DefaultConfig(), nil)
	domainMgr := config.NewDomainManager("test.dev")

	// Add a domain first
	domainMgr.AddDomain("existing.test.dev", "test-account")

	d := New(Config{
		Server:      srv,
		AuthManager: authMgr,
		DomainMgr:   domainMgr,
	})

	handler := d.Handler()

	// POST with same domain name (should fail as duplicate)
	body := strings.NewReader(`{"domain":"existing.test.dev","account_id":"test"}`)
	req := httptest.NewRequest("POST", "/api/domains", body)
	req.Header.Set("Authorization", "Bearer "+authMgr.DevToken())
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("Status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
}

// TestHandleDomainActionsVerifyNonExistent tests verifying a domain that doesn't exist
func TestHandleDomainActionsVerifyNonExistent(t *testing.T) {
	authMgr := auth.NewManager()
	srv := server.New(server.DefaultConfig(), nil)
	domainMgr := config.NewDomainManager("test.dev")

	d := New(Config{
		Server:      srv,
		AuthManager: authMgr,
		DomainMgr:   domainMgr,
	})

	handler := d.Handler()

	// POST /api/domains/nonexistent.test.dev/verify (domain not added)
	req := httptest.NewRequest("POST", "/api/domains/nonexistent.test.dev/verify", nil)
	req.Header.Set("Authorization", "Bearer "+authMgr.DevToken())
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("Status = %d, want %d", rec.Code, http.StatusInternalServerError)
	}
}

// ─── /api/requests and /api/requests/{id}/replay tests ──────────

func TestHandleRequestsGet(t *testing.T) {
	authMgr := auth.NewManager()
	srv := server.New(server.DefaultConfig(), nil)

	d := New(Config{
		Server:      srv,
		AuthManager: authMgr,
	})

	handler := d.Handler()

	// GET /api/requests - should return empty list
	req := httptest.NewRequest("GET", "/api/requests", nil)
	req.Header.Set("Authorization", "Bearer "+authMgr.DevToken())
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("Status = %d, want %d", rec.Code, http.StatusOK)
	}

	contentType := rec.Header().Get("Content-Type")
	if contentType != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", contentType)
	}
}

func TestHandleRequestsGetWithLimit(t *testing.T) {
	authMgr := auth.NewManager()
	srv := server.New(server.DefaultConfig(), nil)

	d := New(Config{
		Server:      srv,
		AuthManager: authMgr,
	})

	handler := d.Handler()

	// GET /api/requests?limit=10
	req := httptest.NewRequest("GET", "/api/requests?limit=10", nil)
	req.Header.Set("Authorization", "Bearer "+authMgr.DevToken())
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("Status = %d, want %d", rec.Code, http.StatusOK)
	}
}

func TestHandleRequestsGetWithTunnelIDFilter(t *testing.T) {
	authMgr := auth.NewManager()
	srv := server.New(server.DefaultConfig(), nil)

	d := New(Config{
		Server:      srv,
		AuthManager: authMgr,
	})

	handler := d.Handler()

	// GET /api/requests?tunnel_id=tun-1
	req := httptest.NewRequest("GET", "/api/requests?tunnel_id=tun-1", nil)
	req.Header.Set("Authorization", "Bearer "+authMgr.DevToken())
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("Status = %d, want %d", rec.Code, http.StatusOK)
	}
}

func TestHandleRequestsGetWithInvalidLimit(t *testing.T) {
	authMgr := auth.NewManager()
	srv := server.New(server.DefaultConfig(), nil)

	d := New(Config{
		Server:      srv,
		AuthManager: authMgr,
	})

	handler := d.Handler()

	// GET /api/requests?limit=abc (invalid, should use default 50)
	req := httptest.NewRequest("GET", "/api/requests?limit=abc", nil)
	req.Header.Set("Authorization", "Bearer "+authMgr.DevToken())
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("Status = %d, want %d", rec.Code, http.StatusOK)
	}
}

func TestHandleRequestsMethodNotAllowed(t *testing.T) {
	authMgr := auth.NewManager()
	srv := server.New(server.DefaultConfig(), nil)

	d := New(Config{
		Server:      srv,
		AuthManager: authMgr,
	})

	handler := d.Handler()

	// POST to /api/requests should be method not allowed
	req := httptest.NewRequest("POST", "/api/requests", nil)
	req.Header.Set("Authorization", "Bearer "+authMgr.DevToken())
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("Status = %d, want %d", rec.Code, http.StatusMethodNotAllowed)
	}
}

func TestHandleRequestActionsReplayNotFound(t *testing.T) {
	authMgr := auth.NewManager()
	srv := server.New(server.DefaultConfig(), nil)

	d := New(Config{
		Server:      srv,
		AuthManager: authMgr,
	})

	handler := d.Handler()

	// POST /api/requests/nonexistent-id/replay
	req := httptest.NewRequest("POST", "/api/requests/nonexistent-id/replay", nil)
	req.Header.Set("Authorization", "Bearer "+authMgr.DevToken())
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("Status = %d, want %d", rec.Code, http.StatusBadRequest)
	}

	// Verify error message
	var resp map[string]string
	json.NewDecoder(rec.Body).Decode(&resp)
	if resp["error"] == "" {
		t.Error("Expected error message in response body")
	}
}

func TestHandleRequestActionsMethodNotAllowed(t *testing.T) {
	authMgr := auth.NewManager()
	srv := server.New(server.DefaultConfig(), nil)

	d := New(Config{
		Server:      srv,
		AuthManager: authMgr,
	})

	handler := d.Handler()

	// GET /api/requests/some-id/replay (should be POST only)
	req := httptest.NewRequest("GET", "/api/requests/some-id/replay", nil)
	req.Header.Set("Authorization", "Bearer "+authMgr.DevToken())
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("Status = %d, want %d", rec.Code, http.StatusMethodNotAllowed)
	}
}

func TestHandleRequestActionsInvalidPath(t *testing.T) {
	authMgr := auth.NewManager()
	srv := server.New(server.DefaultConfig(), nil)

	d := New(Config{
		Server:      srv,
		AuthManager: authMgr,
	})

	handler := d.Handler()

	// GET /api/requests/some-id (no /replay suffix)
	req := httptest.NewRequest("GET", "/api/requests/some-id", nil)
	req.Header.Set("Authorization", "Bearer "+authMgr.DevToken())
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("Status = %d, want %d", rec.Code, http.StatusNotFound)
	}
}

func TestHandleRequestActionsInvalidAction(t *testing.T) {
	authMgr := auth.NewManager()
	srv := server.New(server.DefaultConfig(), nil)

	d := New(Config{
		Server:      srv,
		AuthManager: authMgr,
	})

	handler := d.Handler()

	// POST /api/requests/some-id/notreplay (invalid action)
	req := httptest.NewRequest("POST", "/api/requests/some-id/notreplay", nil)
	req.Header.Set("Authorization", "Bearer "+authMgr.DevToken())
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("Status = %d, want %d", rec.Code, http.StatusNotFound)
	}
}

func TestHandleRequestsUnauthorized(t *testing.T) {
	authMgr := auth.NewManager()
	srv := server.New(server.DefaultConfig(), nil)

	d := New(Config{
		Server:      srv,
		AuthManager: authMgr,
	})

	handler := d.Handler()

	// GET /api/requests without auth
	req := httptest.NewRequest("GET", "/api/requests", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("Status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

func TestHandleRequestActionsReplayUnauthorized(t *testing.T) {
	authMgr := auth.NewManager()
	srv := server.New(server.DefaultConfig(), nil)

	d := New(Config{
		Server:      srv,
		AuthManager: authMgr,
	})

	handler := d.Handler()

	// POST /api/requests/some-id/replay without auth
	req := httptest.NewRequest("POST", "/api/requests/some-id/replay", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("Status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

// TestHandleRequestsGetWithLargeLimit tests the limit > 500 capping branch.
func TestHandleRequestsGetWithLargeLimit(t *testing.T) {
	authMgr := auth.NewManager()
	srv := server.New(server.DefaultConfig(), nil)

	d := New(Config{
		Server:      srv,
		AuthManager: authMgr,
	})

	handler := d.Handler()

	// GET /api/requests?limit=999 — should be capped to 500 internally
	req := httptest.NewRequest("GET", "/api/requests?limit=999", nil)
	req.Header.Set("Authorization", "Bearer "+authMgr.DevToken())
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("Status = %d, want %d", rec.Code, http.StatusOK)
	}
}

// TestHandleRequestsGetWithZeroLimit tests the limit=0 edge case (non-positive parsed value).
func TestHandleRequestsGetWithZeroLimit(t *testing.T) {
	authMgr := auth.NewManager()
	srv := server.New(server.DefaultConfig(), nil)

	d := New(Config{
		Server:      srv,
		AuthManager: authMgr,
	})

	handler := d.Handler()

	// GET /api/requests?limit=0 — parsed > 0 is false, so default 50 is used
	req := httptest.NewRequest("GET", "/api/requests?limit=0", nil)
	req.Header.Set("Authorization", "Bearer "+authMgr.DevToken())
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("Status = %d, want %d", rec.Code, http.StatusOK)
	}
}

// TestHandleRequestsGetWithNegativeLimit tests the limit=-5 edge case.
func TestHandleRequestsGetWithNegativeLimit(t *testing.T) {
	authMgr := auth.NewManager()
	srv := server.New(server.DefaultConfig(), nil)

	d := New(Config{
		Server:      srv,
		AuthManager: authMgr,
	})

	handler := d.Handler()

	// GET /api/requests?limit=-5 — parsed > 0 is false, so default 50 is used
	req := httptest.NewRequest("GET", "/api/requests?limit=-5", nil)
	req.Header.Set("Authorization", "Bearer "+authMgr.DevToken())
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("Status = %d, want %d", rec.Code, http.StatusOK)
	}
}

// TestHandleRequestActionsNoAction tests the missing action path (parts[1] absent).
func TestHandleRequestActionsNoAction(t *testing.T) {
	authMgr := auth.NewManager()
	srv := server.New(server.DefaultConfig(), nil)

	d := New(Config{
		Server:      srv,
		AuthManager: authMgr,
	})

	handler := d.Handler()

	// POST /api/requests/some-id — no /replay suffix, len(parts) < 2
	req := httptest.NewRequest("POST", "/api/requests/some-id", nil)
	req.Header.Set("Authorization", "Bearer "+authMgr.DevToken())
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("Status = %d, want %d", rec.Code, http.StatusNotFound)
	}
}
