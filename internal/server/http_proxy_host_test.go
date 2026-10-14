package server

// Regression tests for Host header emission in SerializeRequest. The tunnel
// wire request is re-serialized from a parsed http.Request, and net/http
// keeps the host out of r.Header — so without explicit emission the request
// forwarded to the client relay carried no Host at all. Real HTTP/1.1
// servers (RFC 9112 Section 3.2), including Go's own net/http server,
// reject such requests with 400, which broke tunneled WebSocket handshakes
// against Go-based local services. See test/integration/ws_host_test.go for
// the end-to-end case.

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func TestSerializeRequestEmitsHostHeader(t *testing.T) {
	req := &http.Request{
		Method: "GET",
		URL:    &url.URL{Path: "/path?q=1"},
		Proto:  "HTTP/1.1",
		Host:   "app.example.com:8443",
		Header: http.Header{"X-Custom": []string{"v"}},
	}

	data, err := SerializeRequest(req)
	if err != nil {
		t.Fatalf("SerializeRequest failed: %v", err)
	}
	s := string(data)

	if got := strings.Count(s, "\r\nHost: "); got != 1 {
		t.Fatalf("Host header count = %d, want exactly 1:\n%s", got, s)
	}
	if !strings.Contains(s, "\r\nHost: app.example.com:8443\r\n") {
		t.Errorf("serialized request missing verbatim Host with port:\n%s", s)
	}
}

func TestSerializeRequestOmitsHostWhenAbsent(t *testing.T) {
	// HTTP/1.0-style visitor without a Host header: r.Host is empty and no
	// Host line may be synthesized.
	req := &http.Request{
		Method: "GET",
		URL:    &url.URL{Path: "/"},
		Proto:  "HTTP/1.0",
		Host:   "",
		Header: http.Header{},
	}

	data, err := SerializeRequest(req)
	if err != nil {
		t.Fatalf("SerializeRequest failed: %v", err)
	}
	s := string(data)

	if strings.Contains(s, "\r\nHost:") {
		t.Errorf("Host header synthesized for Host-less request:\n%s", s)
	}
}
