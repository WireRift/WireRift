package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestWriteEdgeErrorNegotiatesBrowsersAndClients(t *testing.T) {
	// API client / curl: identical to the plain http.Error body.
	r := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	writeEdgeError(w, r, http.StatusBadGateway, "Tunnel not found")
	if w.Code != 502 || w.Body.String() != "Tunnel not found\n" || !strings.HasPrefix(w.Header().Get("Content-Type"), "text/plain") {
		t.Errorf("plain: %d %q %q", w.Code, w.Body.String(), w.Header().Get("Content-Type"))
	}

	// Browser: a self-contained HTML page with the message and a hint.
	r = httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Accept", "text/html,application/xhtml+xml")
	w = httptest.NewRecorder()
	writeEdgeError(w, r, http.StatusBadGateway, "Tunnel not found")
	body := w.Body.String()
	if w.Code != 502 || !strings.HasPrefix(w.Header().Get("Content-Type"), "text/html") {
		t.Fatalf("html: %d %q", w.Code, w.Header().Get("Content-Type"))
	}
	for _, want := range []string{"Tunnel not found", "No tunnel is registered", "502 Bad Gateway"} {
		if !strings.Contains(body, want) {
			t.Errorf("page missing %q", want)
		}
	}
	if csp := w.Header().Get("Content-Security-Policy"); !strings.Contains(csp, "default-src 'none'") {
		t.Errorf("CSP = %q", csp)
	}
	if w.Header().Get("Cache-Control") != "no-store" {
		t.Error("error pages must not be cached")
	}

	// HEAD never gets a body page.
	r = httptest.NewRequest("HEAD", "/", nil)
	r.Header.Set("Accept", "text/html")
	w = httptest.NewRecorder()
	writeEdgeError(w, r, http.StatusBadGateway, "x")
	if strings.Contains(w.Header().Get("Content-Type"), "html") {
		t.Error("HEAD received an HTML page")
	}
}

func TestWriteEdgeErrorEscapesMessage(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Accept", "text/html")
	w := httptest.NewRecorder()
	writeEdgeError(w, r, http.StatusBadGateway, `<script>alert(1)</script>`)
	if strings.Contains(w.Body.String(), "<script>") {
		t.Error("message was not HTML-escaped")
	}
}

func TestDefaultHintCoversCommonErrors(t *testing.T) {
	for _, tc := range []struct {
		status int
		msg    string
		want   string
	}{
		{502, "Session not found", "disconnected"},
		{502, "boom", "tunnel client did not answer"},
		{413, "x", "larger than"},
		{429, "x", "Wait a moment"},
		{403, "x", "not allowed"},
	} {
		if got := defaultHint(tc.status, tc.msg); !strings.Contains(got, tc.want) {
			t.Errorf("defaultHint(%d,%q) = %q, want %q", tc.status, tc.msg, got, tc.want)
		}
	}
	if defaultHint(418, "teapot") != "" {
		t.Error("unknown status should have no hint")
	}
}
