package dashboard

import (
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
