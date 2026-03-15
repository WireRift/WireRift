package server

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/wirerift/wirerift/internal/auth"
	"github.com/wirerift/wirerift/internal/mux"
	"github.com/wirerift/wirerift/internal/proto"
	"github.com/wirerift/wirerift/internal/ratelimit"
	"github.com/wirerift/wirerift/internal/utils"
)

// Errors returned by server operations.
var (
	ErrServerClosed       = errors.New("server is closed")
	ErrTunnelNotFound     = errors.New("tunnel not found")
	ErrSessionNotFound    = errors.New("session not found")
	ErrUnauthorized       = errors.New("unauthorized")
	ErrSubdomainTaken     = errors.New("subdomain is already taken")
	ErrPortUnavailable    = errors.New("port is unavailable")
	ErrMaxTunnelsExceeded = errors.New("maximum tunnels exceeded")
)

// Config holds server configuration.
type Config struct {
	// Domain is the base domain for tunnels (e.g., "wirerift.dev")
	Domain string

	// ControlAddr is the address for the control plane listener.
	ControlAddr string

	// HTTPAddr is the address for HTTP edge listener.
	HTTPAddr string

	// HTTPSAddr is the address for HTTPS edge listener.
	HTTPSAddr string

	// TCPAddrRange is the range for TCP tunnel ports (e.g., "20000-29999").
	TCPAddrRange string

	// DashboardAddr is the address for the dashboard API.
	DashboardAddr string

	// TLSConfig is the TLS configuration for the control plane.
	TLSConfig *tls.Config

	// HeartbeatInterval is the interval for heartbeat checks.
	HeartbeatInterval time.Duration

	// SessionTimeout is the timeout for inactive sessions.
	SessionTimeout time.Duration

	// MaxTunnelsPerSession is the maximum tunnels per session.
	MaxTunnelsPerSession int

	// AuthManager is the authentication manager.
	AuthManager *auth.Manager
}

// DefaultConfig returns the default server configuration.
func DefaultConfig() Config {
	return Config{
		Domain:               "wirerift.dev",
		ControlAddr:          ":4443",
		HTTPAddr:             ":80",
		HTTPSAddr:            ":443",
		TCPAddrRange:         "20000-29999",
		DashboardAddr:        ":4040",
		HeartbeatInterval:    30 * time.Second,
		SessionTimeout:       60 * time.Second,
		MaxTunnelsPerSession: 10,
	}
}

// Server is the tunnel server.
type Server struct {
	config      Config
	logger      *slog.Logger
	authManager *auth.Manager

	// Listeners
	controlListener net.Listener
	httpListener    net.Listener
	httpsListener   net.Listener

	// State
	sessions sync.Map // map[string]*Session
	tunnels  sync.Map // map[string]*Tunnel (by subdomain or port)

	// Rate limiting
	rateLimiter *ratelimit.Manager

	// Port allocation
	tcpPortStart int
	tcpPortEnd   int
	tcpPorts     sync.Map // map[int]bool (allocated ports)
	nextPort     atomic.Int32

	// Lifecycle
	ctx       context.Context
	cancel    context.CancelFunc
	wg        sync.WaitGroup
	startTime time.Time
}

// Session represents a client session.
type Session struct {
	ID         string
	AccountID  string
	Mux        *mux.Mux
	Tunnels    map[string]*Tunnel
	CreatedAt  time.Time
	LastSeen   time.Time
	RemoteAddr net.Addr
	mu         sync.RWMutex
}

// Tunnel represents an active tunnel.
type Tunnel struct {
	ID        string
	Type      proto.TunnelType
	SessionID string
	Subdomain string // for HTTP tunnels
	Port      int    // for TCP tunnels
	PublicURL string
	LocalAddr string
	CreatedAt time.Time
	mu        sync.RWMutex
}

// New creates a new server.
func New(config Config, logger *slog.Logger) *Server {
	if logger == nil {
		logger = slog.Default()
	}

	ctx, cancel := context.WithCancel(context.Background())

	s := &Server{
		config:       config,
		logger:       logger,
		ctx:          ctx,
		cancel:       cancel,
		tcpPortStart: 20000,
		tcpPortEnd:   29999,
		rateLimiter:  ratelimit.NewManager(100, 50), // 100 req/s, burst 50
	}

	s.nextPort.Store(int32(s.tcpPortStart))

	if config.AuthManager != nil {
		s.authManager = config.AuthManager
	} else {
		s.authManager = auth.NewManager()
	}

	return s
}

// Start starts the server.
func (s *Server) Start() error {
	s.startTime = time.Now()

	// Start control plane listener
	if err := s.startControlListener(); err != nil {
		return fmt.Errorf("start control listener: %w", err)
	}

	// Start HTTP edge listener
	if err := s.startHTTPListener(); err != nil {
		return fmt.Errorf("start HTTP listener: %w", err)
	}

	// Start HTTPS edge listener if TLS is configured
	if s.config.TLSConfig != nil {
		if err := s.startHTTPSListener(); err != nil {
			s.logger.Warn("HTTPS listener not started", "error", err)
		}
	}

	// Start session cleanup goroutine
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		s.startSessionCleanup()
	}()

	// Start rate limiter eviction goroutine
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		s.startRateLimiterEviction()
	}()

	s.logger.Info("server started",
		"control", s.config.ControlAddr,
		"http", s.config.HTTPAddr,
	)

	return nil
}

// Stop stops the server.
func (s *Server) Stop() error {
	s.cancel()

	// Close listeners
	if s.controlListener != nil {
		s.controlListener.Close()
	}
	if s.httpListener != nil {
		s.httpListener.Close()
	}
	if s.httpsListener != nil {
		s.httpsListener.Close()
	}

	// Close all sessions
	s.sessions.Range(func(key, value any) bool {
		if session, ok := value.(*Session); ok {
			session.Mux.Close()
		}
		return true
	})

	s.wg.Wait()

	s.logger.Info("server stopped")
	return nil
}

// startControlListener starts the control plane listener.
func (s *Server) startControlListener() error {
	var err error
	s.controlListener, err = net.Listen("tcp", s.config.ControlAddr)
	if err != nil {
		return err
	}

	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		s.acceptControlConnections()
	}()

	return nil
}

// acceptControlConnections accepts incoming control connections.
func (s *Server) acceptControlConnections() {
	for {
		conn, err := s.controlListener.Accept()
		if err != nil {
			select {
			case <-s.ctx.Done():
				return
			default:
			}
			// If listener was closed, stop accepting
			return
		}

		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.handleControlConnection(conn)
		}()
	}
}

// generateSubdomain generates a random subdomain string using unbiased random.
func generateSubdomain() string {
	const charset = "abcdefghijklmnopqrstuvwxyz0123456789"
	const maxByte = byte(256 - (256 % len(charset))) // reject biased bytes
	b := make([]byte, 8)
	buf := make([]byte, 12) // extra for rejections
	filled := 0
	for filled < 8 {
		rand.Read(buf)
		for _, v := range buf {
			if v < maxByte {
				b[filled] = charset[v%byte(len(charset))]
				filled++
				if filled == 8 {
					break
				}
			}
		}
	}
	return string(b)
}

// handleControlConnection handles a control plane connection.
func (s *Server) handleControlConnection(conn net.Conn) {
	defer conn.Close()

	remoteAddr := conn.RemoteAddr()
	s.logger.Debug("control connection", "remote", remoteAddr)

	// Read magic bytes
	if err := proto.ReadMagic(conn); err != nil {
		s.logger.Warn("invalid magic", "remote", remoteAddr, "error", err)
		return
	}

	// Create mux
	m := mux.New(conn, mux.DefaultConfig())
	go m.Run()

	// Authenticate
	session, err := s.handleAuth(m, remoteAddr)
	if err != nil {
		s.logger.Warn("auth failed", "remote", remoteAddr, "error", err)
		m.Close()
		return
	}
	defer s.removeSession(session.ID)

	s.logger.Info("session started", "id", session.ID, "remote", remoteAddr)

	// Handle tunnel requests until disconnect
	s.handleTunnelRequests(m, session)

	s.logger.Info("session ended", "id", session.ID)
}

// handleAuth authenticates a client connection.
func (s *Server) handleAuth(m *mux.Mux, remoteAddr net.Addr) (*Session, error) {
	// Wait for auth frame with timeout
	select {
	case frame := <-m.ControlFrame():
		if frame.Type != proto.FrameAuthReq {
			return nil, fmt.Errorf("expected AUTH_REQ, got %v", frame.Type)
		}

		var authReq proto.AuthRequest
		if err := proto.DecodeJSONPayload(frame, &authReq); err != nil {
			return nil, fmt.Errorf("decode auth request: %w", err)
		}

		// Validate token
		_, account, err := s.authManager.ValidateToken(authReq.Token)
		if err != nil {
			// Send failure response
			resp := &proto.AuthResponse{OK: false, Error: err.Error()}
			respFrame, _ := proto.EncodeJSONPayload(proto.FrameAuthRes, 0, resp)
			m.GetFrameWriter().Write(respFrame)
			return nil, fmt.Errorf("invalid token: %w", err)
		}

		// Create session
		sessionID := fmt.Sprintf("sess_%s", generateSubdomain())
		session := &Session{
			ID:         sessionID,
			AccountID:  account.ID,
			Mux:        m,
			Tunnels:    make(map[string]*Tunnel),
			CreatedAt:  time.Now(),
			LastSeen:   time.Now(),
			RemoteAddr: remoteAddr,
		}
		s.sessions.Store(sessionID, session)

		// Send success response
		maxTunnels := s.config.MaxTunnelsPerSession
		resp := &proto.AuthResponse{
			OK:         true,
			SessionID:  sessionID,
			MaxTunnels: maxTunnels,
		}
		respFrame, _ := proto.EncodeJSONPayload(proto.FrameAuthRes, 0, resp)
		m.GetFrameWriter().Write(respFrame)

		return session, nil

	case <-time.After(10 * time.Second):
		return nil, fmt.Errorf("auth timeout")

	case <-s.ctx.Done():
		return nil, fmt.Errorf("server shutting down")
	}
}

// handleTunnelRequests processes tunnel requests from a session.
func (s *Server) handleTunnelRequests(m *mux.Mux, session *Session) {
	for {
		select {
		case frame := <-m.ControlFrame():
			// Update LastSeen on any control frame activity
			session.mu.Lock()
			session.LastSeen = time.Now()
			session.mu.Unlock()

			switch frame.Type {
			case proto.FrameTunnelReq:
				s.handleTunnelRequest(m, session, frame)
			case proto.FrameTunnelClose:
				s.handleTunnelClose(session, frame)
			}

		case <-m.Done():
			return

		case <-s.ctx.Done():
			return
		}
	}
}

// handleTunnelRequest processes a tunnel creation request.
func (s *Server) handleTunnelRequest(m *mux.Mux, session *Session, frame *proto.Frame) {
	var req proto.TunnelRequest
	if err := proto.DecodeJSONPayload(frame, &req); err != nil {
		resp := &proto.TunnelResponse{OK: false, Error: "invalid request"}
		respFrame, _ := proto.EncodeJSONPayload(proto.FrameTunnelRes, 0, resp)
		m.GetFrameWriter().Write(respFrame)
		return
	}

	// Rate limit tunnel creation by session ID
	if !s.rateLimiter.Allow("tunnel:" + session.ID) {
		resp := &proto.TunnelResponse{OK: false, Error: "rate limit exceeded"}
		respFrame, _ := proto.EncodeJSONPayload(proto.FrameTunnelRes, 0, resp)
		m.GetFrameWriter().Write(respFrame)
		return
	}

	session.mu.Lock()
	if len(session.Tunnels) >= s.config.MaxTunnelsPerSession {
		session.mu.Unlock()
		resp := &proto.TunnelResponse{OK: false, Error: "max tunnels exceeded"}
		respFrame, _ := proto.EncodeJSONPayload(proto.FrameTunnelRes, 0, resp)
		m.GetFrameWriter().Write(respFrame)
		return
	}
	session.mu.Unlock()

	tunnelID := fmt.Sprintf("tun_%s", generateSubdomain())

	switch req.Type {
	case proto.TunnelTypeHTTP:
		subdomain := req.Subdomain
		if subdomain == "" {
			subdomain = generateSubdomain()
		}

		// Validate subdomain
		if !utils.IsValidSubdomain(subdomain) {
			resp := &proto.TunnelResponse{OK: false, Error: "invalid subdomain"}
			respFrame, _ := proto.EncodeJSONPayload(proto.FrameTunnelRes, 0, resp)
			m.GetFrameWriter().Write(respFrame)
			return
		}

		// Check if subdomain is taken
		if _, loaded := s.tunnels.LoadOrStore(subdomain, &Tunnel{}); loaded {
			resp := &proto.TunnelResponse{OK: false, Error: "subdomain already taken"}
			respFrame, _ := proto.EncodeJSONPayload(proto.FrameTunnelRes, 0, resp)
			m.GetFrameWriter().Write(respFrame)
			return
		}

		tunnel := &Tunnel{
			ID:        tunnelID,
			Type:      proto.TunnelTypeHTTP,
			SessionID: session.ID,
			Subdomain: subdomain,
			PublicURL: fmt.Sprintf("http://%s.%s", subdomain, s.config.Domain),
			LocalAddr: req.LocalAddr,
			CreatedAt: time.Now(),
		}
		s.tunnels.Store(subdomain, tunnel)

		session.mu.Lock()
		session.Tunnels[tunnelID] = tunnel
		session.mu.Unlock()

		resp := &proto.TunnelResponse{
			OK:        true,
			TunnelID:  tunnelID,
			Type:      proto.TunnelTypeHTTP,
			PublicURL: tunnel.PublicURL,
		}
		respFrame, _ := proto.EncodeJSONPayload(proto.FrameTunnelRes, 0, resp)
		m.GetFrameWriter().Write(respFrame)

		s.logger.Info("tunnel created", "id", tunnelID, "type", "http", "subdomain", subdomain)

	case proto.TunnelTypeTCP:
		port, err := s.allocatePort()
		if err != nil {
			resp := &proto.TunnelResponse{OK: false, Error: "no ports available"}
			respFrame, _ := proto.EncodeJSONPayload(proto.FrameTunnelRes, 0, resp)
			m.GetFrameWriter().Write(respFrame)
			return
		}

		tunnel := &Tunnel{
			ID:        tunnelID,
			Type:      proto.TunnelTypeTCP,
			SessionID: session.ID,
			Port:      port,
			PublicURL: fmt.Sprintf("tcp://%s:%d", s.config.Domain, port),
			LocalAddr: req.LocalAddr,
			CreatedAt: time.Now(),
		}

		portKey := fmt.Sprintf("tcp:%d", port)
		s.tunnels.Store(portKey, tunnel)

		session.mu.Lock()
		session.Tunnels[tunnelID] = tunnel
		session.mu.Unlock()

		// Start TCP listener for this tunnel
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.startTCPTunnelListener(port, tunnel, session)
		}()

		resp := &proto.TunnelResponse{
			OK:        true,
			TunnelID:  tunnelID,
			Type:      proto.TunnelTypeTCP,
			PublicURL: tunnel.PublicURL,
		}
		respFrame, _ := proto.EncodeJSONPayload(proto.FrameTunnelRes, 0, resp)
		m.GetFrameWriter().Write(respFrame)

		s.logger.Info("tunnel created", "id", tunnelID, "type", "tcp", "port", port)

	default:
		resp := &proto.TunnelResponse{OK: false, Error: "unsupported tunnel type"}
		respFrame, _ := proto.EncodeJSONPayload(proto.FrameTunnelRes, 0, resp)
		m.GetFrameWriter().Write(respFrame)
	}
}

// handleTunnelClose processes a tunnel close request.
func (s *Server) handleTunnelClose(session *Session, frame *proto.Frame) {
	var req proto.TunnelClose
	if err := proto.DecodeJSONPayload(frame, &req); err != nil {
		return
	}

	session.mu.Lock()
	tunnel, ok := session.Tunnels[req.TunnelID]
	if ok {
		delete(session.Tunnels, req.TunnelID)
	}
	session.mu.Unlock()

	if tunnel == nil {
		return
	}

	// Remove from global tunnels map
	switch tunnel.Type {
	case proto.TunnelTypeHTTP:
		s.tunnels.Delete(tunnel.Subdomain)
	case proto.TunnelTypeTCP:
		portKey := fmt.Sprintf("tcp:%d", tunnel.Port)
		s.tunnels.Delete(portKey)
		s.releasePort(tunnel.Port)
	}

	s.logger.Info("tunnel closed", "id", req.TunnelID)
}

// removeSession removes a session and cleans up all its tunnels.
func (s *Server) removeSession(sessionID string) {
	v, ok := s.sessions.LoadAndDelete(sessionID)
	if !ok {
		return
	}

	session := v.(*Session)
	session.mu.Lock()
	tunnels := make(map[string]*Tunnel)
	for k, v := range session.Tunnels {
		tunnels[k] = v
	}
	session.Tunnels = nil
	session.mu.Unlock()

	// Clean up all tunnels
	for _, tunnel := range tunnels {
		switch tunnel.Type {
		case proto.TunnelTypeHTTP:
			s.tunnels.Delete(tunnel.Subdomain)
		case proto.TunnelTypeTCP:
			portKey := fmt.Sprintf("tcp:%d", tunnel.Port)
			s.tunnels.Delete(portKey)
			s.releasePort(tunnel.Port)
		}
	}
}

// startTCPTunnelListener starts a TCP listener for a tunnel.
func (s *Server) startTCPTunnelListener(port int, tunnel *Tunnel, session *Session) {
	addr := fmt.Sprintf(":%d", port)
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		s.logger.Error("failed to start TCP tunnel listener", "port", port, "error", err)
		return
	}
	defer listener.Close()

	// Close listener when context or mux is done to unblock Accept
	go func() {
		select {
		case <-s.ctx.Done():
		case <-session.Mux.Done():
		}
		listener.Close()
	}()

	for {
		conn, err := listener.Accept()
		if err != nil {
			return
		}

		go func() {
			defer conn.Close()
			s.proxyTCPConnection(conn, tunnel, session)
		}()
	}
}

// proxyTCPConnection proxies a TCP connection through the mux.
func (s *Server) proxyTCPConnection(conn net.Conn, tunnel *Tunnel, session *Session) {
	// Open a stream through the mux
	stream, err := session.Mux.OpenStream()
	if err != nil {
		s.logger.Warn("failed to open stream for TCP proxy", "tunnel", tunnel.ID, "error", err)
		return
	}
	defer stream.Close()

	// Send STREAM_OPEN with TCP metadata
	openFrame, _ := StreamOpenForTCP(tunnel.ID, stream.ID(), conn.RemoteAddr().String())
	if err := session.Mux.GetFrameWriter().Write(openFrame); err != nil {
		return
	}

	// Bidirectional copy
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		io.Copy(stream, conn)
		stream.Close()
	}()
	go func() {
		defer wg.Done()
		io.Copy(conn, stream)
		conn.Close()
	}()
	wg.Wait()
}

// startHTTPListener starts the HTTP edge listener.
func (s *Server) startHTTPListener() error {
	var err error
	s.httpListener, err = net.Listen("tcp", s.config.HTTPAddr)
	if err != nil {
		return err
	}

	handler := http.HandlerFunc(s.handleHTTPRequest)
	server := &http.Server{Handler: handler}

	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		if err := server.Serve(s.httpListener); err != nil && err != http.ErrServerClosed {
			s.logger.Error("HTTP server error", "error", err)
		}
	}()

	return nil
}

// startHTTPSListener starts the HTTPS edge listener.
func (s *Server) startHTTPSListener() error {
	ln, err := net.Listen("tcp", s.config.HTTPSAddr)
	if err != nil {
		return err
	}
	tlsListener := tls.NewListener(ln, s.config.TLSConfig)
	s.httpsListener = tlsListener

	handler := http.HandlerFunc(s.handleHTTPRequest)
	server := &http.Server{Handler: handler}

	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		if err := server.Serve(tlsListener); err != nil && err != http.ErrServerClosed {
			s.logger.Error("HTTPS server error", "error", err)
		}
	}()

	return nil
}

// handleHTTPRequest handles incoming HTTP requests.
func (s *Server) handleHTTPRequest(w http.ResponseWriter, r *http.Request) {
	// Rate limit by client IP
	clientIP := r.RemoteAddr
	if idx := strings.LastIndex(clientIP, ":"); idx > 0 {
		clientIP = clientIP[:idx]
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

	// Get session
	session, ok := s.getSession(tunnel.SessionID)
	if !ok {
		http.Error(w, "Session not found", http.StatusBadGateway)
		return
	}

	// Forward request through tunnel
	s.forwardHTTPRequest(w, r, session, tunnel)
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

// getTunnelBySubdomain looks up a tunnel by subdomain.
func (s *Server) getTunnelBySubdomain(subdomain string) (*Tunnel, bool) {
	if v, ok := s.tunnels.Load(subdomain); ok {
		return v.(*Tunnel), true
	}
	return nil, false
}

// getSession looks up a session by ID.
func (s *Server) getSession(id string) (*Session, bool) {
	if v, ok := s.sessions.Load(id); ok {
		return v.(*Session), true
	}
	return nil, false
}

// allocatePort allocates a TCP port for a tunnel.
func (s *Server) allocatePort() (int, error) {
	portRange := s.tcpPortEnd - s.tcpPortStart + 1
	for i := 0; i < portRange; i++ {
		raw := int(s.nextPort.Add(1))
		// Wrap around using modulo to avoid race in store-back
		port := s.tcpPortStart + ((raw - s.tcpPortStart) % portRange)
		if port < s.tcpPortStart {
			port += portRange
		}

		if _, loaded := s.tcpPorts.LoadOrStore(port, true); !loaded {
			return port, nil
		}
	}
	return 0, ErrPortUnavailable
}

// releasePort releases a TCP port.
func (s *Server) releasePort(port int) {
	s.tcpPorts.Delete(port)
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

	// Check if host ends with domain
	suffix := "." + domain
	if len(host) <= len(suffix) {
		return ""
	}
	if host[len(host)-len(suffix):] != suffix {
		return ""
	}

	return host[:len(host)-len(suffix)]
}

// StartTime returns when the server was started.
func (s *Server) StartTime() time.Time {
	return s.startTime
}

// ControlAddr returns the control listener address (useful when using port 0).
func (s *Server) ControlAddr() string {
	if s.controlListener != nil {
		return s.controlListener.Addr().String()
	}
	return s.config.ControlAddr
}

// HTTPAddr returns the HTTP listener address (useful when using port 0).
func (s *Server) HTTPAddr() string {
	if s.httpListener != nil {
		return s.httpListener.Addr().String()
	}
	return s.config.HTTPAddr
}

// TunnelInfo represents tunnel information for API responses.
type TunnelInfo struct {
	ID        string    `json:"id"`
	Type      string    `json:"type"`
	URL       string    `json:"url,omitempty"`
	Port      int       `json:"port,omitempty"`
	Target    string    `json:"target"`
	LocalPort int       `json:"local_port,omitempty"`
	Status    string    `json:"status"`
	CreatedAt time.Time `json:"created_at"`
}

// SessionInfo represents session information for API responses.
type SessionInfo struct {
	ID          string    `json:"id"`
	AccountID   string    `json:"account_id"`
	RemoteAddr  string    `json:"remote_addr"`
	ConnectedAt time.Time `json:"connected_at"`
	TunnelCount int       `json:"tunnel_count"`
}

// ListTunnels returns a list of all active tunnels.
func (s *Server) ListTunnels() []TunnelInfo {
	var tunnels []TunnelInfo
	s.tunnels.Range(func(key, value any) bool {
		if t, ok := value.(*Tunnel); ok {
			t.mu.RLock()
			info := TunnelInfo{
				ID:        t.ID,
				Type:      string(t.Type),
				URL:       t.PublicURL,
				Port:      t.Port,
				Target:    t.LocalAddr,
				Status:    "active",
				CreatedAt: t.CreatedAt,
			}
			t.mu.RUnlock()
			tunnels = append(tunnels, info)
		}
		return true
	})
	return tunnels
}

// ListSessions returns a list of all connected sessions.
func (s *Server) ListSessions() []SessionInfo {
	var sessions []SessionInfo
	s.sessions.Range(func(key, value any) bool {
		if sess, ok := value.(*Session); ok {
			sess.mu.RLock()
			info := SessionInfo{
				ID:          sess.ID,
				AccountID:   sess.AccountID,
				RemoteAddr:  sess.RemoteAddr.String(),
				ConnectedAt: sess.CreatedAt,
				TunnelCount: len(sess.Tunnels),
			}
			sess.mu.RUnlock()
			sessions = append(sessions, info)
		}
		return true
	})
	return sessions
}

// Stats returns server statistics.
func (s *Server) Stats() map[string]interface{} {
	var tunnelCount, sessionCount int
	var bytesIn, bytesOut int64

	s.tunnels.Range(func(key, value any) bool {
		tunnelCount++
		return true
	})

	s.sessions.Range(func(key, value any) bool {
		sessionCount++
		return true
	})

	return map[string]interface{}{
		"active_tunnels":  tunnelCount,
		"active_sessions": sessionCount,
		"bytes_in":        bytesIn,
		"bytes_out":       bytesOut,
	}
}

// startSessionCleanup periodically checks for inactive sessions and removes them.
func (s *Server) startSessionCleanup() {
	ticker := time.NewTicker(s.config.SessionTimeout / 2)
	defer ticker.Stop()

	for {
		select {
		case <-s.ctx.Done():
			return
		case <-ticker.C:
			s.cleanupInactiveSessions()
		}
	}
}

// startRateLimiterEviction periodically evicts stale rate limiters to prevent memory leaks.
func (s *Server) startRateLimiterEviction() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-s.ctx.Done():
			return
		case <-ticker.C:
			evicted := s.rateLimiter.Evict(10 * time.Minute)
			if evicted > 0 {
				s.logger.Debug("evicted stale rate limiters", "count", evicted)
			}
		}
	}
}

// cleanupInactiveSessions removes sessions that have exceeded the session timeout.
func (s *Server) cleanupInactiveSessions() {
	now := time.Now()
	s.sessions.Range(func(key, value any) bool {
		session := value.(*Session)
		session.mu.RLock()
		lastSeen := session.LastSeen
		session.mu.RUnlock()

		if now.Sub(lastSeen) > s.config.SessionTimeout {
			s.logger.Info("session timed out", "id", session.ID)
			session.Mux.Close()
			s.removeSession(session.ID)
		}
		return true
	})
}
