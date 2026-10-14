package server

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
)

// maxRequestBodySize bounds the request body buffered for tunneling.
const maxRequestBodySize = 32 * 1024 * 1024

// ErrRequestTooLarge is returned when a request body exceeds maxRequestBodySize.
var ErrRequestTooLarge = errors.New("request body too large")

// skipForwardHeader reports headers that must not be copied verbatim from the
// visitor: the proxy re-emits trusted values (forwarding headers), the framing
// is recomputed from the buffered body, and the PIN is a credential for this
// server that must not leak to the local app.
func skipForwardHeader(key string) bool {
	switch http.CanonicalHeaderKey(key) {
	case "X-Forwarded-For", "X-Forwarded-Proto", "X-Forwarded-Host",
		"Content-Length", "Transfer-Encoding", "X-Wirerift-Pin":
		return true
	}
	return false
}

// SerializeRequest serializes an HTTP request for tunneling.
func SerializeRequest(r *http.Request) ([]byte, error) {
	// Buffer the body first so the framing headers match what is sent.
	var body []byte
	if r.Body != nil {
		var err error
		body, err = io.ReadAll(io.LimitReader(r.Body, maxRequestBodySize+1))
		if err != nil {
			return nil, err
		}
		if len(body) > maxRequestBodySize {
			return nil, ErrRequestTooLarge
		}
	}

	var buf bytes.Buffer

	// Write request line
	buf.WriteString(r.Method)
	buf.WriteByte(' ')
	buf.WriteString(r.URL.String())
	buf.WriteByte(' ')
	buf.WriteString(r.Proto)
	buf.WriteString("\r\n")

	// Write headers
	for key, values := range r.Header {
		if skipForwardHeader(key) {
			continue
		}
		for _, value := range values {
			buf.WriteString(key)
			buf.WriteString(": ")
			buf.WriteString(value)
			buf.WriteString("\r\n")
		}
	}

	// Add forwarding headers (exactly one of each, never client-supplied
	// duplicates that a backend could read first).
	clientIP := r.RemoteAddr
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		clientIP = host
	}
	buf.WriteString("X-Forwarded-For: ")
	if existing := r.Header.Get("X-Forwarded-For"); existing != "" {
		buf.WriteString(existing + ", " + clientIP)
	} else {
		buf.WriteString(clientIP)
	}
	buf.WriteString("\r\n")
	buf.WriteString("X-Forwarded-Proto: ")
	if r.TLS != nil {
		buf.WriteString("https")
	} else {
		buf.WriteString("http")
	}
	buf.WriteString("\r\n")
	buf.WriteString("X-Forwarded-Host: ")
	buf.WriteString(r.Host)
	buf.WriteString("\r\n")

	// Body framing: chunked/unknown-length bodies were decoded by net/http,
	// so always declare the real length.
	if len(body) > 0 || r.ContentLength != 0 {
		buf.WriteString("Content-Length: " + strconv.Itoa(len(body)) + "\r\n")
	}

	// End headers
	buf.WriteString("\r\n")
	buf.Write(body)

	return buf.Bytes(), nil
}

// DeserializeResponse deserializes an HTTP response from tunneling.
func DeserializeResponse(data []byte) (*http.Response, error) {
	reader := bufio.NewReader(bytes.NewReader(data))
	resp, err := http.ReadResponse(reader, nil)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

// WriteResponse writes an HTTP response to the client.
func WriteResponse(w http.ResponseWriter, resp *http.Response) error {
	// Copy headers
	for key, values := range resp.Header {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}

	// Write status code
	w.WriteHeader(resp.StatusCode)

	// Copy body
	if resp.Body != nil {
		_, err := io.Copy(w, resp.Body)
		resp.Body.Close()
		return err
	}

	return nil
}

// IsWebSocketRequest checks if a request is a WebSocket upgrade per RFC 6455.
func IsWebSocketRequest(r *http.Request) bool {
	if !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
		return false
	}
	// Connection header must contain "upgrade" (RFC 6455 Section 4.2.1)
	for _, v := range strings.Split(r.Header.Get("Connection"), ",") {
		if strings.EqualFold(strings.TrimSpace(v), "upgrade") {
			return true
		}
	}
	return false
}
