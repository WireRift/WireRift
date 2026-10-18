package server

import (
	"bufio"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// hostHasTunnel reports whether host maps to a registered HTTP tunnel.
func (s *Server) hostHasTunnel(host string) bool {
	sub := extractSubdomain(host, s.config.Domain)
	if sub == "" {
		return false
	}
	_, ok := s.getTunnelBySubdomain(sub)
	return ok
}

// handleHTTPRequest handles incoming HTTP requests.
func (s *Server) handleHTTPRequest(w http.ResponseWriter, r *http.Request) {
	// Health check endpoint. A tunnel's own /healthz (and its PIN/auth/IP
	// checks) must not be shadowed, so only answer for hosts without a tunnel.
	if r.URL.Path == "/healthz" && !s.hostHasTunnel(r.Host) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"status":"ok"}`))
		return
	}

	// Serve ACME HTTP-01 challenges before any other processing
	if strings.HasPrefix(r.URL.Path, "/.well-known/acme-challenge/") && s.config.ACMEChallengeHandler != nil {
		s.config.ACMEChallengeHandler(w, r)
		return
	}

	// Add request ID for tracing
	if r.Header.Get("X-Request-ID") == "" {
		b := make([]byte, 8)
		rand.Read(b)
		r.Header.Set("X-Request-ID", hex.EncodeToString(b))
	}
	w.Header().Set("X-Request-ID", r.Header.Get("X-Request-ID"))

	// Rate limit by client IP
	clientIP := r.RemoteAddr
	if host, _, err := net.SplitHostPort(clientIP); err == nil {
		clientIP = host
	}
	if !s.rateLimiter.Allow(clientIP) {
		writeEdgeError(w, r, http.StatusTooManyRequests, "Rate limit exceeded")
		return
	}

	// Extract subdomain from Host header
	host := r.Host
	subdomain := extractSubdomain(host, s.config.Domain)
	if subdomain == "" {
		writeEdgeError(w, r, http.StatusBadRequest, "Invalid host")
		return
	}

	// Look up tunnel
	tunnel, ok := s.getTunnelBySubdomain(subdomain)
	if !ok {
		writeEdgeError(w, r, http.StatusBadGateway, "Tunnel not found")
		return
	}

	// Check IP whitelist
	tunnel.mu.RLock()
	allowedIPs := tunnel.AllowedIPs
	pin := tunnel.PIN
	tunnelAuth := tunnel.Auth
	customHeaders := tunnel.Headers
	inspect := tunnel.Inspect
	tunnel.mu.RUnlock()

	if len(allowedIPs) > 0 {
		if !s.isIPAllowed(clientIP, allowedIPs) {
			writeEdgeError(w, r, http.StatusForbidden, "Forbidden: your IP is not whitelisted")
			return
		}
	}

	// Check Basic Auth
	if tunnelAuth != nil && tunnelAuth.Type == "basic" {
		if !s.checkBasicAuth(w, r, tunnelAuth.Username, tunnelAuth.Password) {
			return
		}
	}

	// Check PIN protection
	if pin != "" {
		if !s.checkPIN(w, r, pin, subdomain) {
			return
		}
	}

	// Get session
	session, ok := s.getSession(tunnel.SessionID)
	if !ok {
		writeEdgeError(w, r, http.StatusBadGateway, "Session not found")
		return
	}

	// Track request start for inspector
	var reqStart time.Time
	if inspect {
		reqStart = time.Now()
	}

	// Wrap response writer to capture status/headers for inspection and custom headers
	wrapped := &inspectResponseWriter{
		ResponseWriter: w,
		customHeaders:  customHeaders,
		statusCode:     200,
	}

	// Forward request through tunnel
	s.forwardHTTPRequest(wrapped, r, session, tunnel)

	// Log request for inspection
	if inspect {
		s.logRequest(tunnel, r, wrapped, clientIP, reqStart)
	}
}

// forwardHTTPRequest forwards an HTTP request through the tunnel.
func (s *Server) forwardHTTPRequest(w http.ResponseWriter, r *http.Request, session *Session, tunnel *Tunnel) {
	if IsWebSocketRequest(r) {
		s.forwardWebSocket(w, r, session, tunnel)
		return
	}

	// 1. Open a new mux stream
	stream, err := session.Mux.OpenStream()
	if err != nil {
		writeEdgeError(w, r, http.StatusBadGateway, "Failed to open stream")
		return
	}
	defer stream.Close()

	// 2. Send STREAM_OPEN frame with metadata
	openFrame, _ := StreamOpenForHTTP(tunnel.ID, stream.ID(), r.RemoteAddr)
	if err := session.Mux.GetFrameWriter().Write(openFrame); err != nil {
		writeEdgeError(w, r, http.StatusBadGateway, "Failed to send stream open")
		return
	}

	// 3. Serialize the HTTP request and write through the stream
	reqData, err := SerializeRequest(r)
	if err != nil {
		if errors.Is(err, ErrRequestTooLarge) {
			writeEdgeError(w, r, http.StatusRequestEntityTooLarge, "Request body too large")
			return
		}
		writeEdgeError(w, r, http.StatusInternalServerError, "Failed to serialize request")
		return
	}
	if _, err := stream.Write(reqData); err != nil {
		writeEdgeError(w, r, http.StatusBadGateway, "Failed to write request to stream")
		return
	}

	s.bytesIn.Add(int64(len(reqData)))

	// 4. Stop waiting if the visitor goes away, so a slow or hung local app
	// cannot pin this goroutine and its stream.
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-r.Context().Done():
			_ = stream.Reset()
		case <-done:
		}
	}()

	// 5. Parse the response head from the stream and stream the body back as it
	// arrives (no full buffering), so large downloads, SSE and long polling work.
	headTimer := time.AfterFunc(responseHeadTimeout, func() { _ = stream.Reset() })
	cr := &countingReader{r: stream, n: &s.bytesOut}
	br := bufio.NewReader(cr)
	resp, err := http.ReadResponse(br, r)
	headTimer.Stop()
	if err != nil {
		if cr.err != nil && cr.err != io.EOF {
			writeEdgeError(w, r, http.StatusBadGateway, "Failed to read response from stream")
			return
		}
		writeEdgeError(w, r, http.StatusBadGateway, "Failed to deserialize response")
		return
	}
	defer resp.Body.Close()

	// 6. Write the response back to the edge HTTP client
	if err := WriteResponse(w, resp); err != nil && resp.ContentLength < 0 {
		// The length is not declared, so a silent early end would look like a
		// complete chunked/close-delimited body. Abort the connection instead.
		panic(http.ErrAbortHandler)
	}
}

// responseHeadTimeout bounds how long the local app may take to start responding.
const responseHeadTimeout = 2 * time.Minute

// countingReader adds the bytes read to a shared counter.
type countingReader struct {
	r   io.Reader
	n   *atomic.Int64
	err error // last read error (only touched by the single reading goroutine)
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n.Add(int64(n))
	if err != nil {
		c.err = err
	}
	return n, err
}

// forwardWebSocket handles WebSocket upgrade requests by hijacking the connection
// and performing bidirectional copy between the client and the tunnel stream.
func (s *Server) forwardWebSocket(w http.ResponseWriter, r *http.Request, session *Session, tunnel *Tunnel) {
	// Hijack the HTTP connection to get raw TCP access
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		writeEdgeError(w, r, http.StatusInternalServerError, "WebSocket not supported")
		return
	}

	// Open a mux stream
	stream, err := session.Mux.OpenStream()
	if err != nil {
		writeEdgeError(w, r, http.StatusBadGateway, "Failed to open stream")
		return
	}
	defer stream.Close()

	// Send STREAM_OPEN
	openFrame, _ := StreamOpenForHTTP(tunnel.ID, stream.ID(), r.RemoteAddr)
	if err := session.Mux.GetFrameWriter().Write(openFrame); err != nil {
		writeEdgeError(w, r, http.StatusBadGateway, "Failed to send stream open")
		return
	}

	// Serialize and send the upgrade request
	reqData, err := SerializeRequest(r)
	if err != nil {
		if errors.Is(err, ErrRequestTooLarge) {
			writeEdgeError(w, r, http.StatusRequestEntityTooLarge, "Request body too large")
			return
		}
		writeEdgeError(w, r, http.StatusInternalServerError, "Failed to serialize request")
		return
	}
	if _, err := stream.Write(reqData); err != nil {
		writeEdgeError(w, r, http.StatusBadGateway, "Failed to write request")
		return
	}

	// Hijack the connection
	conn, bufrw, err := hijacker.Hijack()
	if err != nil {
		return
	}
	defer conn.Close()

	// Bidirectional copy between hijacked conn and stream
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		io.Copy(conn, stream)
		conn.Close()
	}()
	go func() {
		defer wg.Done()
		// First flush any buffered data
		if bufrw.Reader.Buffered() > 0 {
			buffered := make([]byte, bufrw.Reader.Buffered())
			_, _ = bufrw.Read(buffered)
			_, _ = stream.Write(buffered)
		}
		io.Copy(stream, conn)
		stream.Close()
	}()
	wg.Wait()
}

// extractSubdomain extracts the subdomain from a host.
func extractSubdomain(host, domain string) string {
	// Remove port if present
	for i := len(host) - 1; i >= 0; i-- {
		if host[i] == ':' {
			host = host[:i]
			break
		}
	}

	// DNS is case-insensitive
	host = strings.ToLower(host)

	// Check if host ends with domain
	suffix := "." + strings.ToLower(domain)
	if len(host) <= len(suffix) {
		return ""
	}
	if host[len(host)-len(suffix):] != suffix {
		return ""
	}

	return host[:len(host)-len(suffix)]
}

// isIPAllowed checks if the given client IP is in the allowed list.
// Supports exact IP match and CIDR notation.
func (s *Server) isIPAllowed(clientIP string, allowedIPs []string) bool {
	// Strip brackets from IPv6
	clientIP = strings.TrimPrefix(clientIP, "[")
	clientIP = strings.TrimSuffix(clientIP, "]")

	parsedClient := net.ParseIP(clientIP)

	for _, allowed := range allowedIPs {
		// Try CIDR match
		if strings.Contains(allowed, "/") {
			_, cidr, err := net.ParseCIDR(allowed)
			if err == nil && parsedClient != nil && cidr.Contains(parsedClient) {
				return true
			}
			continue
		}

		// Exact IP match
		allowedIP := net.ParseIP(allowed)
		if allowedIP != nil && parsedClient != nil && allowedIP.Equal(parsedClient) {
			return true
		}

		// String match fallback (e.g. unresolvable formats)
		if clientIP == allowed {
			return true
		}
	}
	return false
}

// checkBasicAuth validates HTTP Basic Authentication on a tunnel.
func (s *Server) checkBasicAuth(w http.ResponseWriter, r *http.Request, username, password string) bool {
	u, p, ok := r.BasicAuth()
	if !ok || subtle.ConstantTimeCompare([]byte(u), []byte(username)) != 1 ||
		subtle.ConstantTimeCompare([]byte(p), []byte(password)) != 1 {
		w.Header().Set("WWW-Authenticate", `Basic realm="WireRift Tunnel"`)
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return false
	}
	return true
}
