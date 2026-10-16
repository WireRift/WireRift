package server

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSerializeRequestDedupesForwardedHeaders(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "192.168.1.1:5555"
	req.Host = "app.example.com"
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("X-Forwarded-Host", "evil.com")
	req.Header.Set("X-WireRift-PIN", "1234")

	data, err := SerializeRequest(req)
	if err != nil {
		t.Fatal(err)
	}
	s := string(data)
	if n := strings.Count(strings.ToLower(s), "x-forwarded-proto:"); n != 1 {
		t.Errorf("X-Forwarded-Proto appears %d times, want 1:\n%s", n, s)
	}
	if strings.Contains(s, "evil.com") {
		t.Errorf("client-supplied X-Forwarded-Host leaked:\n%s", s)
	}
	if !strings.Contains(s, "X-Forwarded-Proto: http\r\n") {
		t.Errorf("trusted X-Forwarded-Proto missing:\n%s", s)
	}
	if strings.Contains(strings.ToLower(s), "x-wirerift-pin") {
		t.Errorf("PIN credential forwarded to backend:\n%s", s)
	}
}

func TestSerializeRequestChunkedBodyKeepsContentLength(t *testing.T) {
	req := httptest.NewRequest("POST", "/", strings.NewReader("hello world"))
	req.ContentLength = -1 // unknown length, as for chunked requests
	req.Header.Set("Transfer-Encoding", "chunked")

	data, err := SerializeRequest(req)
	if err != nil {
		t.Fatal(err)
	}
	// Round-trip through the parser the client uses.
	parsed, err := http.ReadRequest(bufioReader(data))
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(parsed.Body)
	if string(body) != "hello world" {
		t.Errorf("body = %q, want %q", body, "hello world")
	}
}

func TestSerializeRequestTooLarge(t *testing.T) {
	req := httptest.NewRequest("POST", "/", io.LimitReader(zeroReader{}, maxRequestBodySize+10))
	if _, err := SerializeRequest(req); !errors.Is(err, ErrRequestTooLarge) {
		t.Errorf("err = %v, want ErrRequestTooLarge", err)
	}
}

type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 0
	}
	return len(p), nil
}

func bufioReader(b []byte) *bufio.Reader { return bufio.NewReader(bytes.NewReader(b)) }

func TestDeserializeResponseForHEAD(t *testing.T) {
	req := httptest.NewRequest("HEAD", "/", nil)
	data := []byte("HTTP/1.1 200 OK\r\nContent-Length: 1234\r\n\r\n")
	resp, err := DeserializeResponseFor(data, req)
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	if err := WriteResponse(w, resp); err != nil {
		t.Errorf("HEAD response body copy failed: %v", err)
	}
}

func TestPublicHTTPURL(t *testing.T) {
	cases := []struct {
		scheme string
		port   int
		want   string
	}{
		{"", 0, "http://app.example.com"},
		{"http", 80, "http://app.example.com"},
		{"http", 8080, "http://app.example.com:8080"},
		{"https", 443, "https://app.example.com"},
		{"https", 8443, "https://app.example.com:8443"},
		{"https", 0, "https://app.example.com"},
	}
	for _, c := range cases {
		cfg := DefaultConfig()
		cfg.Domain = "example.com"
		cfg.PublicScheme, cfg.PublicPort = c.scheme, c.port
		if got := New(cfg, nil).publicHTTPURL("app"); got != c.want {
			t.Errorf("scheme=%q port=%d: got %q, want %q", c.scheme, c.port, got, c.want)
		}
	}
}
