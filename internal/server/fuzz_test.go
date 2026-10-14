package server

import (
	"testing"
)

// FuzzDeserializeResponse fuzzes HTTP response deserialization.
// Run: go test -fuzz=FuzzDeserializeResponse -fuzztime=30s ./internal/server/
func FuzzDeserializeResponse(f *testing.F) {
	// Valid HTTP response
	f.Add([]byte("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello"))
	// Minimal response
	f.Add([]byte("HTTP/1.1 200 OK\r\n\r\n"))
	// Response with headers
	f.Add([]byte("HTTP/1.1 404 Not Found\r\nContent-Type: text/plain\r\nX-Custom: value\r\n\r\nnot found"))
	// Empty
	f.Add([]byte{})
	// Garbage
	f.Add([]byte("not a response"))
	// Truncated
	f.Add([]byte("HTTP/1.1 200"))
	// Huge status line
	f.Add([]byte("HTTP/1.1 999 " + string(make([]byte, 1000)) + "\r\n\r\n"))

	f.Fuzz(func(t *testing.T, data []byte) {
		resp, err := DeserializeResponse(data)
		if err != nil {
			return
		}
		if resp != nil && resp.Body != nil {
			resp.Body.Close()
		}
	})
}

// FuzzExtractSubdomain fuzzes subdomain extraction.
func FuzzExtractSubdomain(f *testing.F) {
	f.Add("myapp.wirerift.com", "wirerift.com")
	f.Add("myapp.wirerift.com:8080", "wirerift.com")
	f.Add("wirerift.com", "wirerift.com")
	f.Add("", "wirerift.com")
	f.Add("....", "wirerift.com")
	f.Add("a]b[c.wirerift.com", "wirerift.com")
	f.Add(string(make([]byte, 10000)), "wirerift.com")

	f.Fuzz(func(t *testing.T, host, domain string) {
		_ = extractSubdomain(host, domain) // Should not panic
	})
}

// FuzzIsIPAllowed fuzzes the IP whitelist checker.
func FuzzIsIPAllowed(f *testing.F) {
	f.Add("192.168.1.1", "192.168.1.0/24")
	f.Add("10.0.0.1", "10.0.0.1")
	f.Add("::1", "::1")
	f.Add("not-an-ip", "10.0.0.0/8")
	f.Add("", "")
	f.Add("[::1]", "::1")

	s := New(DefaultConfig(), nil)

	f.Fuzz(func(t *testing.T, clientIP, allowed string) {
		s.isIPAllowed(clientIP, []string{allowed}) // Should not panic
	})
}
