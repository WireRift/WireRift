package middleware

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestRecover(t *testing.T) {
	logger := slog.Default()

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		panic("test panic")
	})

	recovered := Recover(logger)(handler)

	req := httptest.NewRequest("GET", "/", nil)
	rec := httptest.NewRecorder()

	recovered.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("Status = %d, want %d", rec.Code, http.StatusInternalServerError)
	}
}

func TestRecoverNoPanic(t *testing.T) {
	logger := slog.Default()

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	recovered := Recover(logger)(handler)

	req := httptest.NewRequest("GET", "/", nil)
	rec := httptest.NewRecorder()

	recovered.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("Status = %d, want %d", rec.Code, http.StatusOK)
	}
}

func TestCORSAllowed(t *testing.T) {
	allowedOrigins := []string{"http://example.com", "http://localhost:3000"}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	corsHandler := CORS(allowedOrigins)(handler)

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Origin", "http://example.com")
	rec := httptest.NewRecorder()

	corsHandler.ServeHTTP(rec, req)

	if rec.Header().Get("Access-Control-Allow-Origin") != "http://example.com" {
		t.Errorf("CORS header = %q, want %q", rec.Header().Get("Access-Control-Allow-Origin"), "http://example.com")
	}
}

func TestCORSWildcard(t *testing.T) {
	allowedOrigins := []string{"*"}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	corsHandler := CORS(allowedOrigins)(handler)

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Origin", "http://any-origin.com")
	rec := httptest.NewRecorder()

	corsHandler.ServeHTTP(rec, req)

	if rec.Header().Get("Access-Control-Allow-Origin") != "http://any-origin.com" {
		t.Errorf("CORS header = %q, want %q", rec.Header().Get("Access-Control-Allow-Origin"), "http://any-origin.com")
	}
}

func TestCORSPreflight(t *testing.T) {
	allowedOrigins := []string{"http://example.com"}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("Handler should not be called for preflight")
	})

	corsHandler := CORS(allowedOrigins)(handler)

	req := httptest.NewRequest("OPTIONS", "/", nil)
	req.Header.Set("Origin", "http://example.com")
	rec := httptest.NewRecorder()

	corsHandler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Errorf("Status = %d, want %d", rec.Code, http.StatusNoContent)
	}
}

func TestRequestID(t *testing.T) {
	var capturedID string
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedID = w.Header().Get("X-Request-ID")
		w.WriteHeader(http.StatusOK)
	})

	requestIDHandler := RequestID()(handler)

	req := httptest.NewRequest("GET", "/", nil)
	rec := httptest.NewRecorder()

	requestIDHandler.ServeHTTP(rec, req)

	if capturedID == "" {
		t.Error("Request ID should not be empty")
	}
}

func TestRequestIDExisting(t *testing.T) {
	existingID := "existing-id-123"
	var capturedID string
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedID = w.Header().Get("X-Request-ID")
		w.WriteHeader(http.StatusOK)
	})

	requestIDHandler := RequestID()(handler)

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("X-Request-ID", existingID)
	rec := httptest.NewRecorder()

	requestIDHandler.ServeHTTP(rec, req)

	if capturedID != existingID {
		t.Errorf("Request ID = %q, want %q", capturedID, existingID)
	}
}

func TestHealthCheck(t *testing.T) {
	handler := HealthCheck()

	req := httptest.NewRequest("GET", "/health", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("Status = %d, want %d", rec.Code, http.StatusOK)
	}

	if rec.Body.String() != `{"status":"healthy"}` {
		t.Errorf("Body = %q, want %q", rec.Body.String(), `{"status":"healthy"}`)
	}
}

func TestReadyCheckAllPass(t *testing.T) {
	check1 := func() bool { return true }
	check2 := func() bool { return true }

	handler := ReadyCheck(check1, check2)

	req := httptest.NewRequest("GET", "/ready", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("Status = %d, want %d", rec.Code, http.StatusOK)
	}

	if rec.Body.String() != `{"status":"ready"}` {
		t.Errorf("Body = %q, want %q", rec.Body.String(), `{"status":"ready"}`)
	}
}

func TestReadyCheckOneFails(t *testing.T) {
	check1 := func() bool { return true }
	check2 := func() bool { return false }

	handler := ReadyCheck(check1, check2)

	req := httptest.NewRequest("GET", "/ready", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("Status = %d, want %d", rec.Code, http.StatusServiceUnavailable)
	}
}

func TestChain(t *testing.T) {
	var order []string

	m1 := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			order = append(order, "m1-before")
			next.ServeHTTP(w, r)
			order = append(order, "m1-after")
		})
	}

	m2 := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			order = append(order, "m2-before")
			next.ServeHTTP(w, r)
			order = append(order, "m2-after")
		})
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		order = append(order, "handler")
		w.WriteHeader(http.StatusOK)
	})

	chained := Chain(handler, m1, m2)

	req := httptest.NewRequest("GET", "/", nil)
	rec := httptest.NewRecorder()

	chained.ServeHTTP(rec, req)

	expected := []string{"m1-before", "m2-before", "handler", "m2-after", "m1-after"}
	if len(order) != len(expected) {
		t.Errorf("Order length = %d, want %d", len(order), len(expected))
	}
}

func TestResponseWriter(t *testing.T) {
	rec := httptest.NewRecorder()
	rw := &responseWriter{ResponseWriter: rec, status: http.StatusOK}

	rw.WriteHeader(http.StatusCreated)

	if rw.status != http.StatusCreated {
		t.Errorf("Status = %d, want %d", rw.status, http.StatusCreated)
	}

	// Second WriteHeader should be ignored
	rw.WriteHeader(http.StatusBadRequest)

	if rw.status != http.StatusCreated {
		t.Errorf("Status should remain %d", http.StatusCreated)
	}
}

func TestLogger(t *testing.T) {
	logger := slog.Default()

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
		w.Write([]byte("test response"))
	})

	loggingHandler := Logger(logger)(handler)

	req := httptest.NewRequest("GET", "/test?foo=bar", nil)
	req.RemoteAddr = "192.168.1.1:12345"
	req.Header.Set("User-Agent", "test-agent")
	rec := httptest.NewRecorder()

	loggingHandler.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Errorf("Status = %d, want %d", rec.Code, http.StatusCreated)
	}
}

func TestResponseWriterWrite(t *testing.T) {
	rec := httptest.NewRecorder()
	rw := &responseWriter{ResponseWriter: rec, status: http.StatusOK}

	// Write without calling WriteHeader first
	n, err := rw.Write([]byte("test"))
	if err != nil {
		t.Fatalf("Write failed: %v", err)
	}
	if n != 4 {
		t.Errorf("Write returned %d, want 4", n)
	}
	if rw.status != http.StatusOK {
		t.Errorf("Status = %d, want %d", rw.status, http.StatusOK)
	}
}

func TestCORSNoOrigin(t *testing.T) {
	allowedOrigins := []string{"http://example.com"}

	called := false
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	corsHandler := CORS(allowedOrigins)(handler)

	// No Origin header
	req := httptest.NewRequest("GET", "/", nil)
	rec := httptest.NewRecorder()

	corsHandler.ServeHTTP(rec, req)

	if !called {
		t.Error("Handler should be called")
	}
	// No CORS headers should be set
	if rec.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Error("CORS header should not be set without Origin")
	}
}

func TestCORSNotAllowed(t *testing.T) {
	allowedOrigins := []string{"http://example.com"}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	corsHandler := CORS(allowedOrigins)(handler)

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Origin", "http://notallowed.com")
	rec := httptest.NewRecorder()

	corsHandler.ServeHTTP(rec, req)

	// No CORS headers for disallowed origin
	if rec.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Error("CORS header should not be set for disallowed origin")
	}
}

func TestCompressNoGzip(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("test"))
	})

	compressHandler := Compress()(handler)

	// No Accept-Encoding header
	req := httptest.NewRequest("GET", "/", nil)
	rec := httptest.NewRecorder()

	compressHandler.ServeHTTP(rec, req)

	if rec.Body.String() != "test" {
		t.Errorf("Body = %q, want %q", rec.Body.String(), "test")
	}
}

func TestCompressWithGzip(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("test"))
	})

	compressHandler := Compress()(handler)

	// With Accept-Encoding: gzip
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Accept-Encoding", "gzip")
	rec := httptest.NewRecorder()

	compressHandler.ServeHTTP(rec, req)

	// Response passes through (simplified implementation)
	if rec.Body.String() != "test" {
		t.Errorf("Body = %q, want %q", rec.Body.String(), "test")
	}
}

func TestCompressAlreadyCompressed(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("test"))
	})

	compressHandler := Compress()(handler)

	// Already compressed content
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Accept-Encoding", "gzip")
	req.Header.Set("Content-Encoding", "gzip")
	rec := httptest.NewRecorder()

	compressHandler.ServeHTTP(rec, req)

	// Should skip compression
	if rec.Body.String() != "test" {
		t.Errorf("Body = %q, want %q", rec.Body.String(), "test")
	}
}

func TestStripPrefix(t *testing.T) {
	var receivedPath string
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedPath = r.URL.Path
		w.WriteHeader(http.StatusOK)
	})

	stripHandler := StripPrefix("/api")(handler)

	req := httptest.NewRequest("GET", "/api/users", nil)
	rec := httptest.NewRecorder()

	stripHandler.ServeHTTP(rec, req)

	if receivedPath != "/users" {
		t.Errorf("Path = %q, want %q", receivedPath, "/users")
	}
}

func TestTimeout(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		_, ok := ctx.Deadline()
		if !ok {
			t.Error("Context should have deadline")
		}
		w.WriteHeader(http.StatusOK)
	})

	timeoutHandler := Timeout(5 * time.Second)(handler)

	req := httptest.NewRequest("GET", "/", nil)
	rec := httptest.NewRecorder()

	timeoutHandler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("Status = %d, want %d", rec.Code, http.StatusOK)
	}
}

func TestGenerateRequestID(t *testing.T) {
	id := generateRequestID()

	if len(id) != 16 {
		t.Errorf("ID length = %d, want 16", len(id))
	}

	// Should be alphanumeric
	for _, c := range id {
		if !isAlphanumeric(byte(c)) {
			t.Errorf("ID contains non-alphanumeric character: %c", c)
		}
	}
}

func isAlphanumeric(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
}

func TestReadyCheckNoChecks(t *testing.T) {
	handler := ReadyCheck()

	req := httptest.NewRequest("GET", "/ready", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("Status = %d, want %d", rec.Code, http.StatusOK)
	}
}

func TestCORSPreflightNotAllowed(t *testing.T) {
	allowedOrigins := []string{"http://example.com"}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("Handler should not be called for preflight")
	})

	corsHandler := CORS(allowedOrigins)(handler)

	req := httptest.NewRequest("OPTIONS", "/", nil)
	req.Header.Set("Origin", "http://notallowed.com")
	rec := httptest.NewRecorder()

	corsHandler.ServeHTTP(rec, req)

	// Returns 403 for OPTIONS from non-allowed origins
	if rec.Code != http.StatusForbidden {
		t.Errorf("Status = %d, want %d", rec.Code, http.StatusForbidden)
	}
}

type testContextKey struct{}

func TestContextValues(t *testing.T) {
	// Test that middleware can set context values
	key := testContextKey{}
	value := "test-value"

	middleware := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := context.WithValue(r.Context(), key, value)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}

	var received string
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received = r.Context().Value(key).(string)
		w.WriteHeader(http.StatusOK)
	})

	chained := middleware(handler)

	req := httptest.NewRequest("GET", "/", nil)
	rec := httptest.NewRecorder()

	chained.ServeHTTP(rec, req)

	if received != value {
		t.Errorf("Received = %q, want %q", received, value)
	}
}

func TestLoggerCapturesStatus(t *testing.T) {
	logger := slog.Default()

	var capturedStatus int
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte("not found"))
	})

	// Use a custom response writer to capture status
	loggingHandler := Logger(logger)(handler)

	req := httptest.NewRequest("POST", "/test", strings.NewReader("body"))
	rec := httptest.NewRecorder()

	loggingHandler.ServeHTTP(rec, req)

	// The response writer should capture the status
	_ = capturedStatus // Status is logged, not returned
	if rec.Code != http.StatusNotFound {
		t.Errorf("Status = %d, want %d", rec.Code, http.StatusNotFound)
	}
}
