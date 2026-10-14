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

	// RFC 9112 Section 3.2: an HTTP/1.1 request on the wire must carry a
	// Host header. net/http removes Host from r.Header, so the loop above
	// never emits it; without this line the tunneled request reaches the
	// local service with an empty Host (or none), which strict servers —
	// including Go's own net/http server — reject with 400, breaking the
	// WebSocket relay and any Host-based routing on the local app.
	if r.Host != "" {
		buf.WriteString("Host: ")
		buf.WriteString(r.Host)
		buf.WriteString("\r\n")
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
	return DeserializeResponseFor(data, nil)
}

// DeserializeResponseFor deserializes a response to req. Passing the request
// matters for HEAD: its response carries Content-Length but no body, which
// would otherwise surface as an unexpected EOF while copying the body.
func DeserializeResponseFor(data []byte, req *http.Request) (*http.Response, error) {
	reader := bufio.NewReader(bytes.NewReader(data))
	resp, err := http.ReadResponse(reader, req)
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

	// Copy body. When the length is not declared (chunked, close-delimited,
	// SSE) flush after every chunk so data reaches the visitor immediately.
	if resp.Body != nil {
		defer resp.Body.Close()
		flusher, _ := w.(http.Flusher)
		if flusher == nil || (resp.ContentLength >= 0 && !isEventStream(resp)) {
			_, err := io.Copy(w, resp.Body)
			return err
		}
		buf := make([]byte, 32*1024)
		for {
			n, rerr := resp.Body.Read(buf)
			if n > 0 {
				if _, werr := w.Write(buf[:n]); werr != nil {
					return werr
				}
				flusher.Flush()
			}
			if rerr == io.EOF {
				return nil
			}
			if rerr != nil {
				return rerr
			}
		}
	}

	return nil
}

func isEventStream(resp *http.Response) bool {
	return strings.HasPrefix(resp.Header.Get("Content-Type"), "text/event-stream")
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
