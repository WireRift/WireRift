package middleware

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"log/slog"
	"net/http"
	"strings"
	"time"
)

// Logger returns a middleware that logs HTTP requests.
func Logger(logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()

			// Wrap response writer to capture status
			wrapped := &responseWriter{ResponseWriter: w, status: http.StatusOK}

			next.ServeHTTP(wrapped, r)

			duration := time.Since(start)

			logger.Info("request",
				"method", r.Method,
				"path", r.URL.Path,
				"status", wrapped.status,
				"duration", duration.String(),
				"remote", r.RemoteAddr,
				"user-agent", r.UserAgent(),
			)
		})
	}
}

// responseWriter wraps http.ResponseWriter to capture status code
type responseWriter struct {
	http.ResponseWriter
	status  int
	written bool
}

func (w *responseWriter) WriteHeader(status int) {
	if !w.written {
		w.status = status
		w.written = true
		w.ResponseWriter.WriteHeader(status)
	}
}

func (w *responseWriter) Write(b []byte) (int, error) {
	if !w.written {
		w.WriteHeader(http.StatusOK)
	}
	return w.ResponseWriter.Write(b)
}

// Recover returns a middleware that recovers from panics.
func Recover(logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				if err := recover(); err != nil {
					logger.Error("panic recovered",
						"error", err,
						"path", r.URL.Path,
						"method", r.Method,
					)
					http.Error(w, "Internal Server Error", http.StatusInternalServerError)
				}
			}()
			next.ServeHTTP(w, r)
		})
	}
}

// CORS returns a middleware that adds CORS headers.
func CORS(allowedOrigins []string) func(http.Handler) http.Handler {
	origins := make(map[string]bool)
	for _, o := range allowedOrigins {
		origins[o] = true
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin := r.Header.Get("Origin")
			if origin == "" {
				next.ServeHTTP(w, r)
				return
			}

			// Check if origin is allowed
			allowed := false
			if origins["*"] {
				allowed = true
			} else if _, ok := origins[origin]; ok {
				allowed = true
			}

			if allowed {
				w.Header().Set("Access-Control-Allow-Origin", origin)
				w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
				w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
				w.Header().Set("Access-Control-Max-Age", "86400")
			}

			// Handle preflight - only respond to allowed origins
			if r.Method == http.MethodOptions {
				if !allowed {
					w.WriteHeader(http.StatusForbidden)
					return
				}
				w.WriteHeader(http.StatusNoContent)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// Compress returns a middleware that compresses responses.
// Note: This is a simplified version. For production, use proper compression.
func Compress() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Check if client accepts gzip
			if !strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
				next.ServeHTTP(w, r)
				return
			}

			// Skip for small responses or already compressed
			if r.Header.Get("Content-Encoding") != "" {
				next.ServeHTTP(w, r)
				return
			}

			// For now, just pass through - full gzip support would require
			// wrapping the response writer with gzip.Writer
			next.ServeHTTP(w, r)
		})
	}
}

// RequestID returns a middleware that adds a unique request ID.
func RequestID() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			id := r.Header.Get("X-Request-ID")
			if id == "" {
				id = generateRequestID()
			}
			w.Header().Set("X-Request-ID", id)
			next.ServeHTTP(w, r)
		})
	}
}

// generateRequestID generates a cryptographically random request ID.
func generateRequestID() string {
	b := make([]byte, 8)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// Chain chains multiple middlewares together.
func Chain(h http.Handler, middlewares ...func(http.Handler) http.Handler) http.Handler {
	for i := len(middlewares) - 1; i >= 0; i-- {
		h = middlewares[i](h)
	}
	return h
}

// HealthCheck returns a simple health check handler.
func HealthCheck() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"status":"healthy"}`))
	}
}

// ReadyCheck returns a readiness check handler.
func ReadyCheck(checks ...func() bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		for _, check := range checks {
			if !check() {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusServiceUnavailable)
				w.Write([]byte(`{"status":"not ready"}`))
				return
			}
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"status":"ready"}`))
	}
}

// StripPrefix returns a middleware that strips a URL prefix.
func StripPrefix(prefix string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.StripPrefix(prefix, next)
	}
}

// Timeout returns a middleware that adds a timeout to requests.
func Timeout(timeout time.Duration) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx, cancel := context.WithTimeout(r.Context(), timeout)
			defer cancel()
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
