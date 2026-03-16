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
	"strconv"
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
	ErrPortUnavailable = errors.New("port is unavailable")
)

// Config holds server configuration.
type Config struct {
	// Domain is the base domain for tunnels (e.g., "wirerift.com")
	Domain string

	// ControlAddr is the address for the control plane listener.
	ControlAddr string

	// HTTPAddr is the address for HTTP edge listener.
	HTTPAddr string

	// HTTPSAddr is the address for HTTPS edge listener.
	HTTPSAddr string

	// TCPAddrRange is the range for TCP tunnel ports (e.g., "20000-29999").
	TCPAddrRange string

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

	// ACMEChallengeHandler serves ACME HTTP-01 challenges on /.well-known/acme-challenge/
	ACMEChallengeHandler http.HandlerFunc
}

// DefaultConfig returns the default server configuration.
func DefaultConfig() Config {
	return Config{
		Domain:               "wirerift.com",
		ControlAddr:          ":4443",
		HTTPAddr:             ":80",
		HTTPSAddr:            ":443",
		TCPAddrRange:         "20000-29999",
		HeartbeatInterval:    30 * time.Second,
		SessionTimeout:       5 * time.Minute,
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

	// HTTP servers (for graceful shutdown)
	httpServer  *http.Server
	httpsServer *http.Server

	// PIN HMAC secret (generated at startup)
	pinSecret []byte

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

	// Traffic counters
	bytesIn  atomic.Int64
	bytesOut atomic.Int64

	// Traffic inspector
	requestLogs []RequestLog
	logMu       sync.RWMutex
	maxLogs     int

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
	ID         string
	Type       proto.TunnelType
	SessionID  string
	Subdomain  string // for HTTP tunnels
	Port       int    // for TCP tunnels
	PublicURL  string
	LocalAddr  string
	AllowedIPs []string          // IP whitelist (empty = allow all)
	PIN        string            // PIN protection (empty = no PIN)
	Auth       *proto.TunnelAuth // Basic auth (nil = no auth)
	Headers    map[string]string // Custom response headers
	Inspect    bool              // Traffic inspection enabled
	CreatedAt  time.Time
	mu         sync.RWMutex
}

// RequestLog represents a captured HTTP request/response for inspection.
type RequestLog struct {
	ID         string            `json:"id"`
	TunnelID   string            `json:"tunnel_id"`
	Method     string            `json:"method"`
	Path       string            `json:"path"`
	StatusCode int               `json:"status_code"`
	Duration   time.Duration     `json:"duration_ms"`
	ReqHeaders map[string]string `json:"req_headers"`
	ResHeaders map[string]string `json:"res_headers"`
	ReqBody    string            `json:"req_body,omitempty"`
	ResBody    string            `json:"res_body,omitempty"`
	ReqSize    int64             `json:"req_size"`
	ResSize    int64             `json:"res_size"`
	ClientIP   string            `json:"client_ip"`
	Timestamp  time.Time         `json:"timestamp"`
}

// New creates a new server.
func New(config Config, logger *slog.Logger) *Server {
	if logger == nil {
		logger = slog.Default()
	}

	ctx, cancel := context.WithCancel(context.Background())

	portStart, portEnd := 20000, 29999
	if config.TCPAddrRange != "" {
		if parts := strings.SplitN(config.TCPAddrRange, "-", 2); len(parts) == 2 {
			if ps, err := strconv.Atoi(strings.TrimSpace(parts[0])); err == nil {
				portStart = ps
			}
			if pe, err := strconv.Atoi(strings.TrimSpace(parts[1])); err == nil {
				portEnd = pe
			}
		}
	}

	pinSecret := make([]byte, 32)
	if _, err := rand.Read(pinSecret); err != nil {
		// crypto/rand.Read never fails on supported platforms, but handle defensively
		panic("crypto/rand.Read failed: " + err.Error())
	}

	s := &Server{
		config:       config,
		logger:       logger,
		ctx:          ctx,
		cancel:       cancel,
		tcpPortStart: portStart,
		tcpPortEnd:   portEnd,
		rateLimiter:  ratelimit.NewManager(100, 50),
		maxLogs:      500, // Keep last 500 requests for inspection
		pinSecret:    pinSecret,
	}

	// Store portStart-1 so first Add(1) yields portStart
	s.nextPort.Store(int32(s.tcpPortStart - 1))

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

	// Graceful shutdown of HTTP servers
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()

	if s.httpServer != nil {
		s.httpServer.Shutdown(shutdownCtx)
	}
	if s.httpsServer != nil {
		s.httpsServer.Shutdown(shutdownCtx)
	}

	// Close control listener
	if s.controlListener != nil {
		s.controlListener.Close()
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
// Also runs a heartbeat monitor to keep LastSeen updated from heartbeat ACKs.
func (s *Server) handleTunnelRequests(m *mux.Mux, session *Session) {
	// Heartbeat keepalive: periodically check mux's last heartbeat timestamp
	// and update session.LastSeen so the session cleanup doesn't kill active tunnels.
	heartbeatTicker := time.NewTicker(s.config.HeartbeatInterval / 2)
	defer heartbeatTicker.Stop()

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

		case <-heartbeatTicker.C:
			// Check if mux received a heartbeat recently
			lastHB := m.LastHeartbeat()
			if !lastHB.IsZero() {
				session.mu.Lock()
				if lastHB.After(session.LastSeen) {
					session.LastSeen = lastHB
				}
				session.mu.Unlock()
			}

		case <-m.Done():
			return

		case <-s.ctx.Done():
			return
		}
	}
}

// handleTunnelRequest processes a tunnel creation request.
// sendTunnelError sends a tunnel error response.
func sendTunnelError(m *mux.Mux, msg string) {
	resp := &proto.TunnelResponse{OK: false, Error: msg}
	respFrame, _ := proto.EncodeJSONPayload(proto.FrameTunnelRes, 0, resp)
	m.GetFrameWriter().Write(respFrame)
}

func (s *Server) handleTunnelRequest(m *mux.Mux, session *Session, frame *proto.Frame) {
	var req proto.TunnelRequest
	if err := proto.DecodeJSONPayload(frame, &req); err != nil {
		sendTunnelError(m, "invalid request")
		return
	}

	if !s.rateLimiter.Allow("tunnel:" + session.ID) {
		sendTunnelError(m, "rate limit exceeded")
		return
	}

	session.mu.Lock()
	if session.Tunnels == nil || len(session.Tunnels) >= s.config.MaxTunnelsPerSession {
		session.mu.Unlock()
		sendTunnelError(m, "max tunnels exceeded")
		return
	}
	session.mu.Unlock()

	tunnelID := "tun_" + generateSubdomain()

	switch req.Type {
	case proto.TunnelTypeHTTP:
		s.createHTTPTunnel(m, session, &req, tunnelID)
	case proto.TunnelTypeTCP:
		s.createTCPTunnel(m, session, &req, tunnelID)
	default:
		sendTunnelError(m, "unsupported tunnel type")
	}
}

// createHTTPTunnel handles HTTP tunnel creation.
func (s *Server) createHTTPTunnel(m *mux.Mux, session *Session, req *proto.TunnelRequest, tunnelID string) {
	subdomain := req.Subdomain
	if subdomain == "" {
		subdomain = generateSubdomain()
	}

	if !utils.IsValidSubdomain(subdomain) {
		sendTunnelError(m, "invalid subdomain")
		return
	}

	// Build the full tunnel before storing to avoid a race where another
	// goroutine reads an empty placeholder between LoadOrStore and Store.
	tunnel := &Tunnel{
		ID:         tunnelID,
		Type:       proto.TunnelTypeHTTP,
		SessionID:  session.ID,
		Subdomain:  subdomain,
		PublicURL:  "http://" + subdomain + "." + s.config.Domain,
		LocalAddr:  req.LocalAddr,
		AllowedIPs: req.AllowedIPs,
		PIN:        req.PIN,
		Auth:       req.Auth,
		Headers:    req.Headers,
		Inspect:    req.Inspect,
		CreatedAt:  time.Now(),
	}

	if _, loaded := s.tunnels.LoadOrStore(subdomain, tunnel); loaded {
		sendTunnelError(m, "subdomain already taken")
		return
	}

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
}

// createTCPTunnel handles TCP tunnel creation.
func (s *Server) createTCPTunnel(m *mux.Mux, session *Session, req *proto.TunnelRequest, tunnelID string) {
	port, err := s.allocatePort()
	if err != nil {
		sendTunnelError(m, "no ports available")
		return
	}

	tunnel := &Tunnel{
		ID:         tunnelID,
		Type:       proto.TunnelTypeTCP,
		SessionID:  session.ID,
		Port:       port,
		PublicURL:  "tcp://" + s.config.Domain + ":" + strconv.Itoa(port),
		LocalAddr:  req.LocalAddr,
		AllowedIPs: req.AllowedIPs,
		CreatedAt:  time.Now(),
	}

	portKey := "tcp:" + strconv.Itoa(port)
	s.tunnels.Store(portKey, tunnel)

	session.mu.Lock()
	session.Tunnels[tunnelID] = tunnel
	session.mu.Unlock()

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
}

// handleTunnelClose processes a tunnel close request.
func (s *Server) handleTunnelClose(session *Session, frame *proto.Frame) {
	var req proto.TunnelClose
	if err := proto.DecodeJSONPayload(frame, &req); err != nil {
		return
	}

	session.mu.Lock()
	if session.Tunnels == nil {
		session.mu.Unlock()
		return
	}
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
		portKey := "tcp:" + strconv.Itoa(tunnel.Port)
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
			portKey := "tcp:" + strconv.Itoa(tunnel.Port)
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
			defer func() {
				conn.Close()
				if r := recover(); r != nil {
					s.logger.Error("panic in TCP proxy", "tunnel", tunnel.ID, "error", r)
				}
			}()
			s.proxyTCPConnection(conn, tunnel, session)
		}()
	}
}

// proxyTCPConnection proxies a TCP connection through the mux.
func (s *Server) proxyTCPConnection(conn net.Conn, tunnel *Tunnel, session *Session) {
	// Check IP whitelist for TCP tunnels
	tunnel.mu.RLock()
	allowedIPs := tunnel.AllowedIPs
	tunnel.mu.RUnlock()

	if len(allowedIPs) > 0 {
		remoteAddr := conn.RemoteAddr().String()
		clientIP := remoteAddr
		if idx := strings.LastIndex(clientIP, ":"); idx > 0 {
			clientIP = clientIP[:idx]
		}
		if !s.isIPAllowed(clientIP, allowedIPs) {
			s.logger.Warn("TCP connection rejected by whitelist", "tunnel", tunnel.ID, "remote", remoteAddr)
			return
		}
	}

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

	// Bidirectional copy with bytes tracking
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		n, _ := io.Copy(stream, conn)
		s.bytesIn.Add(n)
		stream.Close()
	}()
	go func() {
		defer wg.Done()
		n, _ := io.Copy(conn, stream)
		s.bytesOut.Add(n)
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

	s.httpServer = &http.Server{
		Handler:           http.HandlerFunc(s.handleHTTPRequest),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}

	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		if err := s.httpServer.Serve(s.httpListener); err != nil && err != http.ErrServerClosed {
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

	s.httpsServer = &http.Server{
		Handler:           http.HandlerFunc(s.handleHTTPRequest),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}

	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		if err := s.httpsServer.Serve(tlsListener); err != nil && err != http.ErrServerClosed {
			s.logger.Error("HTTPS server error", "error", err)
		}
	}()

	return nil
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
	ID         string    `json:"id"`
	Type       string    `json:"type"`
	URL        string    `json:"url,omitempty"`
	Port       int       `json:"port,omitempty"`
	Target     string    `json:"target"`
	LocalPort  int       `json:"local_port,omitempty"`
	Status     string    `json:"status"`
	AllowedIPs []string  `json:"allowed_ips,omitempty"`
	HasPIN     bool      `json:"has_pin,omitempty"`
	HasAuth    bool      `json:"has_auth,omitempty"`
	Inspect    bool      `json:"inspect,omitempty"`
	CreatedAt  time.Time `json:"created_at"`
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
				ID:         t.ID,
				Type:       string(t.Type),
				URL:        t.PublicURL,
				Port:       t.Port,
				Target:     t.LocalAddr,
				Status:     "active",
				AllowedIPs: t.AllowedIPs,
				HasPIN:     t.PIN != "",
				HasAuth:    t.Auth != nil,
				Inspect:    t.Inspect,
				CreatedAt:  t.CreatedAt,
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
		"bytes_in":        s.bytesIn.Load(),
		"bytes_out":       s.bytesOut.Load(),
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
	s.runRateLimiterEviction(5 * time.Minute)
}

// runRateLimiterEviction runs the eviction loop with a configurable interval (testable).
func (s *Server) runRateLimiterEviction(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-s.ctx.Done():
			return
		case <-ticker.C:
			evicted := s.rateLimiter.Evict(interval * 2)
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
