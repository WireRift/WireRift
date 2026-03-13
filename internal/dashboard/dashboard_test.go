package dashboard

import (
	"net/http"
	"net/http/httptest"
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
