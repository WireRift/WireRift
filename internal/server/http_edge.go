package server

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
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
		http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
		return
	}

	// Extract subdomain from Host header
	host := r.Host
	subdomain := extractSubdomain(host, s.config.Domain)
	if subdomain == "" {
		http.Error(w, "Invalid host", http.StatusBadRequest)
		return
	}

	// Look up tunnel
	tunnel, ok := s.getTunnelBySubdomain(subdomain)
	if !ok {
		http.Error(w, "Tunnel not found", http.StatusBadGateway)
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
			http.Error(w, "Forbidden: your IP is not whitelisted", http.StatusForbidden)
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
		http.Error(w, "Session not found", http.StatusBadGateway)
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
		http.Error(w, "Failed to open stream", http.StatusBadGateway)
		return
	}
	defer stream.Close()

	// 2. Send STREAM_OPEN frame with metadata
	openFrame, _ := StreamOpenForHTTP(tunnel.ID, stream.ID(), r.RemoteAddr)
	if err := session.Mux.GetFrameWriter().Write(openFrame); err != nil {
		http.Error(w, "Failed to send stream open", http.StatusBadGateway)
		return
	}

	// 3. Serialize the HTTP request and write through the stream
	reqData, err := SerializeRequest(r)
	if err != nil {
		if errors.Is(err, ErrRequestTooLarge) {
			http.Error(w, "Request body too large", http.StatusRequestEntityTooLarge)
			return
		}
		http.Error(w, "Failed to serialize request", http.StatusInternalServerError)
		return
	}
	if _, err := stream.Write(reqData); err != nil {
		http.Error(w, "Failed to write request to stream", http.StatusBadGateway)
		return
	}

	// 4. Read response data from the stream (limit to 64 MB to prevent memory exhaustion)
	respData, err := io.ReadAll(io.LimitReader(stream, 64*1024*1024))
	if err != nil {
		http.Error(w, "Failed to read response from stream", http.StatusBadGateway)
		return
	}

	// 5. Deserialize the response
	resp, err := DeserializeResponse(respData)
	if err != nil {
		http.Error(w, "Failed to deserialize response", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// Track bytes
	s.bytesIn.Add(int64(len(reqData)))
	s.bytesOut.Add(int64(len(respData)))

	// 6. Write the response back to the edge HTTP client
	WriteResponse(w, resp)
}

// forwardWebSocket handles WebSocket upgrade requests by hijacking the connection
// and performing bidirectional copy between the client and the tunnel stream.
func (s *Server) forwardWebSocket(w http.ResponseWriter, r *http.Request, session *Session, tunnel *Tunnel) {
	// Hijack the HTTP connection to get raw TCP access
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "WebSocket not supported", http.StatusInternalServerError)
		return
	}

	// Open a mux stream
	stream, err := session.Mux.OpenStream()
	if err != nil {
		http.Error(w, "Failed to open stream", http.StatusBadGateway)
		return
	}
	defer stream.Close()

	// Send STREAM_OPEN
	openFrame, _ := StreamOpenForHTTP(tunnel.ID, stream.ID(), r.RemoteAddr)
	if err := session.Mux.GetFrameWriter().Write(openFrame); err != nil {
		http.Error(w, "Failed to send stream open", http.StatusBadGateway)
		return
	}

	// Serialize and send the upgrade request
	reqData, err := SerializeRequest(r)
	if err != nil {
		if errors.Is(err, ErrRequestTooLarge) {
			http.Error(w, "Request body too large", http.StatusRequestEntityTooLarge)
			return
		}
		http.Error(w, "Failed to serialize request", http.StatusInternalServerError)
		return
	}
	if _, err := stream.Write(reqData); err != nil {
		http.Error(w, "Failed to write request", http.StatusBadGateway)
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
			bufrw.Read(buffered)
			stream.Write(buffered)
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
