package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestPINLockoutAfterRepeatedFailures(t *testing.T) {
	s := &Server{pinSecret: []byte("secret")}

	attempt := func(pin string) int {
		r := httptest.NewRequest("GET", "/", nil)
		r.RemoteAddr = "203.0.113.9:4000"
		r.Header.Set("X-WireRift-PIN", pin)
		w := httptest.NewRecorder()
		s.checkPIN(w, r, "1234", "app")
		return w.Code
	}

	for i := 0; i < pinMaxFailures; i++ {
		if code := attempt("0000"); code != http.StatusUnauthorized {
			t.Fatalf("attempt %d: code = %d, want 401", i, code)
		}
	}
	// Locked out: even the correct PIN is refused until the lockout expires.
	if code := attempt("1234"); code != http.StatusTooManyRequests {
		t.Errorf("after lockout code = %d, want 429", code)
	}

	// A different client IP is unaffected.
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "198.51.100.7:4000"
	r.Header.Set("X-WireRift-PIN", "1234")
	if !s.checkPIN(httptest.NewRecorder(), r, "1234", "app") {
		t.Error("other IP should not be locked out")
	}
}

func TestPINFormAcceptsCharsetContentType(t *testing.T) {
	s := &Server{pinSecret: []byte("secret")}
	r := httptest.NewRequest("POST", "/", strings.NewReader("pin=1234"))
	r.RemoteAddr = "203.0.113.9:4000"
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8")
	w := httptest.NewRecorder()
	s.checkPIN(w, r, "1234", "app")
	if w.Code != http.StatusFound {
		t.Errorf("code = %d, want 302", w.Code)
	}
}

func TestRedactHeader(t *testing.T) {
	for _, k := range []string{"Authorization", "cookie", "Set-Cookie", "X-WireRift-PIN"} {
		if got := redactHeader(k, "secret"); got != "[redacted]" {
			t.Errorf("%s not redacted: %q", k, got)
		}
	}
	if got := redactHeader("Accept", "text/html"); got != "text/html" {
		t.Errorf("Accept altered: %q", got)
	}
}

// The post-PIN redirect must stay on this host: a request path starting with
// "//" or `/\` would otherwise redirect to another origin.
func TestPINRedirectStaysOnHost(t *testing.T) {
	for _, path := range []string{"//evil.example/x", `/\evil.example/x`, "///evil.example"} {
		s := &Server{pinSecret: []byte("secret")}
		req := httptest.NewRequest("GET", "http://sub.example.com/", nil)
		req.URL.Path = path
		req.URL.RawQuery = "pin=1234"
		rec := httptest.NewRecorder()

		if s.checkPIN(rec, req, "1234", "sub") {
			t.Fatalf("%q: expected the redirect response, got access granted", path)
		}
		loc := rec.Header().Get("Location")
		if !strings.HasPrefix(loc, "/") || strings.HasPrefix(loc, "//") || strings.HasPrefix(loc, `/\`) {
			t.Errorf("%q: Location = %q, want a same-host path", path, loc)
		}
	}
}

// A holder of a valid PIN cookie keeps access while their (shared) IP is locked
// out by someone else's bad guesses; a wrong PIN stays refused.
func TestPINValidCookieSurvivesLockout(t *testing.T) {
	s := &Server{pinSecret: []byte("secret")}
	const addr = "203.0.113.9:4000"

	for i := 0; i < pinMaxFailures; i++ {
		r := httptest.NewRequest("GET", "/", nil)
		r.RemoteAddr = addr
		r.Header.Set("X-WireRift-PIN", "0000")
		s.checkPIN(httptest.NewRecorder(), r, "1234", "app")
	}

	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = addr
	r.AddCookie(&http.Cookie{Name: "wirerift_pin_app", Value: s.pinMAC("1234", "app")})
	if !s.checkPIN(httptest.NewRecorder(), r, "1234", "app") {
		t.Error("valid cookie must be accepted during lockout")
	}

	r = httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = addr
	r.AddCookie(&http.Cookie{Name: "wirerift_pin_app", Value: "forged"})
	w := httptest.NewRecorder()
	if s.checkPIN(w, r, "1234", "app") || w.Code != http.StatusTooManyRequests {
		t.Errorf("forged cookie during lockout: code = %d, want 429 and denied", w.Code)
	}
}
