package server

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/wirerift/wirerift/internal/mux"
	"github.com/wirerift/wirerift/internal/proto"
)

// Errors returned by server operations.
var (
	ErrServerClosed     = errors.New("server is closed")
	ErrTunnelNotFound   = errors.New("tunnel not found")
	ErrSessionNotFound  = errors.New("session not found")
	ErrUnauthorized     = errors.New("unauthorized")
	ErrSubdomainTaken   = errors.New("subdomain is already taken")
	ErrPortUnavailable  = errors.New("port is unavailable")
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
	config Config
	logger *slog.Logger

	// Listeners
	controlListener net.Listener
	httpListener    net.Listener
	httpsListener   net.Listener

	// State
	sessions sync.Map // map[string]*Session
	tunnels  sync.Map // map[string]*Tunnel (by subdomain or port)

	// Port allocation
	tcpPortStart int
	tcpPortEnd   int
	tcpPorts     sync.Map // map[int]bool (allocated ports)
	nextPort     atomic.Int32

	// Lifecycle
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
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
	Subdomain string    // for HTTP tunnels
	Port      int       // for TCP tunnels
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
		config:    config,
		logger:    logger,
		ctx:       ctx,
		cancel:    cancel,
		tcpPortStart: 20000,
		tcpPortEnd:   29999,
	}

	s.nextPort.Store(int32(s.tcpPortStart))

	return s
}

// Start starts the server.
func (s *Server) Start() error {
	// Start control plane listener
	if err := s.startControlListener(); err != nil {
		return fmt.Errorf("start control listener: %w", err)
	}

	// Start HTTP edge listener
	if err := s.startHTTPListener(); err != nil {
		return fmt.Errorf("start HTTP listener: %w", err)
	}

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
				s.logger.Error("accept control connection", "error", err)
				continue
			}
		}

		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.handleControlConnection(conn)
		}()
	}
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

	// Handle control frames
	go m.Run()

	for {
		select {
		case <-s.ctx.Done():
			return
		case <-m.Done():
			return
		}
	}
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

// handleHTTPRequest handles incoming HTTP requests.
func (s *Server) handleHTTPRequest(w http.ResponseWriter, r *http.Request) {
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
	// This is a simplified implementation
	// In the full implementation, we would:
	// 1. Create a new mux stream
	// 2. Send STREAM_OPEN with request metadata
	// 3. Send HTTP request as STREAM_DATA
	// 4. Read response from stream
	// 5. Write response to client

	http.Error(w, "Not implemented", http.StatusServiceUnavailable)
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
	for i := 0; i < s.tcpPortEnd-s.tcpPortStart; i++ {
		port := int(s.nextPort.Add(1))
		if port > s.tcpPortEnd {
			port = s.tcpPortStart
			s.nextPort.Store(int32(port))
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

// startTime tracks when the server was started
var startTime = time.Now()

// StartTime returns when the server was started.
func (s *Server) StartTime() time.Time {
	return startTime
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
	ID           string    `json:"id"`
	AccountID    string    `json:"account_id"`
	RemoteAddr   string    `json:"remote_addr"`
	ConnectedAt  time.Time `json:"connected_at"`
	TunnelCount  int       `json:"tunnel_count"`
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
