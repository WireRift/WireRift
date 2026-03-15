package server

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// HTTPProxy handles HTTP request proxying through tunnels.
type HTTPProxy struct {
	server   *Server
	pool     sync.Pool // buffer pool
	timeout  time.Duration
}

// NewHTTPProxy creates a new HTTP proxy.
func NewHTTPProxy(server *Server, timeout time.Duration) *HTTPProxy {
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	return &HTTPProxy{
		server:  server,
		timeout: timeout,
		pool: sync.Pool{
			New: func() any {
				b := make([]byte, 32*1024) // 32 KB buffers
				return &b
			},
		},
	}
}

// ProxyRequest proxies an HTTP request through a tunnel.
func (p *HTTPProxy) ProxyRequest(w http.ResponseWriter, r *http.Request, tunnel *Tunnel, session *Session) error {
	stream, err := session.Mux.OpenStream()
	if err != nil {
		return fmt.Errorf("open stream: %w", err)
	}
	defer stream.Close()

	openFrame, _ := StreamOpenForHTTP(tunnel.ID, stream.ID(), r.RemoteAddr)
	if err := session.Mux.GetFrameWriter().Write(openFrame); err != nil {
		return fmt.Errorf("send stream open: %w", err)
	}

	reqData, err := SerializeRequest(r)
	if err != nil {
		return fmt.Errorf("serialize request: %w", err)
	}
	if _, err := stream.Write(reqData); err != nil {
		return fmt.Errorf("write request: %w", err)
	}

	respData, err := io.ReadAll(io.LimitReader(stream, 64*1024*1024))
	if err != nil {
		return fmt.Errorf("read response: %w", err)
	}

	resp, err := DeserializeResponse(respData)
	if err != nil {
		return fmt.Errorf("deserialize response: %w", err)
	}
	defer resp.Body.Close()

	return WriteResponse(w, resp)
}

// HTTPRequest represents a serialized HTTP request for tunneling.
type HTTPRequest struct {
	Method     string
	URL        string
	Proto      string
	Headers    map[string][]string
	Body       []byte
	RemoteAddr string
}

// HTTPResponse represents a serialized HTTP response from tunneling.
type HTTPResponse struct {
	StatusCode int
	Proto      string
	Headers    map[string][]string
	Body       []byte
}

// SerializeRequest serializes an HTTP request for tunneling.
func SerializeRequest(r *http.Request) ([]byte, error) {
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
		for _, value := range values {
			buf.WriteString(key)
			buf.WriteString(": ")
			buf.WriteString(value)
			buf.WriteString("\r\n")
		}
	}

	// Add forwarding headers
	buf.WriteString("X-Forwarded-For: ")
	buf.WriteString(r.RemoteAddr)
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

	// End headers
	buf.WriteString("\r\n")

	// Write body (limit to 32 MB to prevent memory exhaustion)
	if r.Body != nil {
		body, err := io.ReadAll(io.LimitReader(r.Body, 32*1024*1024))
		if err != nil {
			return nil, err
		}
		buf.Write(body)
	}

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

// IsWebSocketRequest checks if a request is a WebSocket upgrade.
func IsWebSocketRequest(r *http.Request) bool {
	return strings.EqualFold(r.Header.Get("Upgrade"), "websocket")
}

// IsSSE checks if a request is Server-Sent Events.
func IsSSE(r *http.Request) bool {
	accept := r.Header.Get("Accept")
	return strings.Contains(accept, "text/event-stream")
}

// shouldCloseConnection determines if the connection should be closed.
func shouldCloseConnection(r *http.Request, resp *http.Response) bool {
	// WebSocket should not close
	if IsWebSocketRequest(r) {
		return false
	}

	// Check Connection header
	if strings.EqualFold(r.Header.Get("Connection"), "close") {
		return true
	}
	if resp != nil && strings.EqualFold(resp.Header.Get("Connection"), "close") {
		return true
	}

	// HTTP/1.0 defaults to close
	if r.ProtoMajor < 1 || (r.ProtoMajor == 1 && r.ProtoMinor == 0) {
		return true
	}

	return false
}
