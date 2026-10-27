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

	// EdgeIdleTimeout bounds how long one read or write on a visitor connection
	// may stall (each successful operation restarts it), so streams of any
	// length work while stuck or trickling peers are dropped. Default 60s.
	EdgeIdleTimeout time.Duration

	// MaxBufferedBodyBytes caps request-body bytes buffered in memory across all
	// in-flight requests; beyond it new uploads get 503 until others finish.
	// Default DefaultMaxBufferedBodyBytes (256 MB).
	MaxBufferedBodyBytes int64

	// TCPBindHost is the interface TCP tunnel ports listen on ("" = all
	// interfaces). -dev sets it to loopback so nothing is reachable remotely.
	TCPBindHost string

	// PublicScheme ("http" or "https") and PublicPort shape the public URLs
	// handed to clients. Defaults: "http" and the scheme's standard port,
	// which is omitted from the URL.
	PublicScheme string
	PublicPort   int

	// TCPAddrRange is the range for TCP tunnel ports (e.g., "20000-29999").
	TCPAddrRange string

	// TLSConfig is the TLS configuration for the HTTPS edge.
	TLSConfig *tls.Config

	// ControlTLSConfig, when set, makes the control plane (:4443) serve TLS so
	// the auth token is not sent in cleartext. Clients use a tls:// address.
	ControlTLSConfig *tls.Config

	// HeartbeatInterval is the interval for heartbeat checks.
	HeartbeatInterval time.Duration

	// SessionTimeout is the timeout for inactive sessions.
	SessionTimeout time.Duration

	// HalfCloseTimeout is passed to each session's mux (mux.Config.HalfCloseTimeout).
	// Zero disables it.
	HalfCloseTimeout time.Duration

	// MaxTunnelsPerSession is the maximum tunnels per session.
	MaxTunnelsPerSession int

	// AuthManager is the authentication manager.
	AuthManager *auth.Manager

	// DomainSecret keys the DNS ownership proofs for custom domains. Persist it
	// (the server binary stores it in the cert dir) so the TXT records users
	// publish stay valid across restarts; nil means a random per-process secret.
	DomainSecret []byte

	// TXTResolver looks up TXT records for custom-domain verification
	// (default: the system resolver).
	TXTResolver TXTResolver

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
	pending pendingConns // control connections still unauthenticated

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
	pinGuard  pinGuard
	pinSecret []byte

	domainSecret []byte // keys custom-domain ownership proofs

	// State
	sessions sync.Map // map[string]*Session
	tunnels  sync.Map // map[string]*Tunnel (by subdomain or port)

	// Rate limiting
	rateLimiter *ratelimit.Manager
	authFails   *ratelimit.Manager // failed control-plane logins, per remote IP

	// acctMu serialises the session-count check with registering a session so
	// the per-account session limit cannot be overshot by parallel logins.
	acctMu sync.Mutex

	// Port allocation
	tcpPortStart int
	tcpPortEnd   int
	tcpPorts     sync.Map // map[int]bool (allocated ports)
	nextPort     atomic.Int32

	// Traffic counters
	bodyBudget *byteBudget // caps buffered request bodies (nil = unlimited)

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
	Account    *auth.Account // limits as of login; nil in tests that build sessions by hand
	Token      *auth.Token   // the credential the session logged in with
	Mux        *mux.Mux
	Tunnels    map[string]*Tunnel
	CreatedAt  time.Time
	LastSeen   time.Time
	RemoteAddr net.Addr
	mu         sync.RWMutex
}

// Tunnel represents an active tunnel.
type Tunnel struct {
	ID           string
	Type         proto.TunnelType
	SessionID    string
	AccountID    string // owner, copied from the session
	Subdomain    string // for HTTP tunnels
	CustomDomain string // optional extra host the tunnel is served on
	Port         int    // for TCP tunnels
	PublicURL    string
	LocalAddr    string
	AllowedIPs   []string          // IP whitelist (empty = allow all)
	PIN          string            // PIN protection (empty = no PIN)
	Auth         *proto.TunnelAuth // Basic auth (nil = no auth)
	Headers      map[string]string // Custom response headers
	Inspect      bool              // Traffic inspection enabled
	CreatedAt    time.Time
	mu           sync.RWMutex

	// ExpiresAt is when the server closes the tunnel on its own (zero = never).
	ExpiresAt time.Time
	expiry    *time.Timer

	// closed is closed when the tunnel is torn down (explicit close, expiry,
	// session end). Established connections watch it so that closing a tunnel
	// also cuts the visitors already connected to it.
	closed     chan struct{}
	closedOnce sync.Once

	listener net.Listener // public TCP listener (TCP tunnels), closed on shutdown
	stop     chan struct{}
	stopOnce sync.Once
}

// markClosed signals every established connection of this tunnel to stop.
func (t *Tunnel) markClosed() {
	t.closedOnce.Do(func() {
		if t.closed != nil {
			close(t.closed)
		}
	})
}

// watch runs the given close functions when the tunnel is torn down. Call the
// returned stop function when the connection ends on its own.
func (t *Tunnel) watch(closers ...func()) (stop func()) {
	done := make(chan struct{})
	go func() {
		select {
		case <-t.closed: // nil channel (tunnel built without one) never fires
			for _, c := range closers {
				c()
			}
		case <-done:
		}
	}()
	return func() { close(done) }
}

// cancelExpiry stops the tunnel's expiry timer, if any.
func (t *Tunnel) cancelExpiry() {
	t.mu.Lock()
	if t.expiry != nil {
		t.expiry.Stop()
	}
	t.mu.Unlock()
}

// shutdown stops the tunnel's public TCP listener, if any. It is idempotent
// and returns only after the listener is closed, so the port can be reused.
func (t *Tunnel) shutdown() {
	t.stopOnce.Do(func() {
		if t.stop != nil {
			close(t.stop)
		}
		t.mu.Lock()
		l := t.listener
		t.mu.Unlock()
		if l != nil {
			l.Close()
		}
	})
}

// addTunnel registers a tunnel on the session. It fails if the session was
// already removed (Tunnels == nil) or is at capacity, so a tunnel can never
// be registered on a dead session.
func (sess *Session) addTunnel(t *Tunnel, limit int) bool {
	sess.mu.Lock()
	defer sess.mu.Unlock()
	if sess.Tunnels == nil || len(sess.Tunnels) >= limit {
		return false
	}
	sess.Tunnels[t.ID] = t
	return true
}

// RequestLog represents a captured HTTP request/response for inspection.
type RequestLog struct {
	ID         string            `json:"id"`
	TunnelID   string            `json:"tunnel_id"`
	AccountID  string            `json:"account_id,omitempty"`
	Method     string            `json:"method"`
	Path       string            `json:"path"`
	Query      string            `json:"query,omitempty"`
	Host       string            `json:"host,omitempty"` // Host header the visitor used (custom domains replay on it)
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

	if config.EdgeIdleTimeout <= 0 {
		config.EdgeIdleTimeout = 60 * time.Second
	}
	if config.MaxBufferedBodyBytes <= 0 {
		config.MaxBufferedBodyBytes = DefaultMaxBufferedBodyBytes
	}

	domainSecret := config.DomainSecret
	if len(domainSecret) == 0 {
		domainSecret = NewDomainSecret()
	}

	s := &Server{
		domainSecret: domainSecret,
		config:       config,
		logger:       logger,
		ctx:          ctx,
		cancel:       cancel,
		tcpPortStart: portStart,
		tcpPortEnd:   portEnd,
		rateLimiter:  ratelimit.NewManager(100, 50),
		authFails:    ratelimit.NewManager(authFailRefill, authFailBurst),
		maxLogs:      500, // Keep last 500 requests for inspection
		pinSecret:    pinSecret,
		bodyBudget:   newByteBudget(config.MaxBufferedBodyBytes),
	}

	// Store portStart-1 so first Add(1) yields portStart
	s.nextPort.Store(int32(s.tcpPortStart - 1)) //nolint:gosec // port numbers are <= 65535

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

// goAwayGrace bounds how long Stop waits for GO_AWAY notices to be written.
const goAwayGrace = 2 * time.Second

// Stop stops the server.
func (s *Server) Stop() error {
	// Tell every client the stop is intentional before cancelling the context
	// (which makes the sessions close their connections on their own), but
	// never let a peer that stopped reading hold up the shutdown: the notice
	// gets goAwayGrace.
	var notified sync.WaitGroup
	s.sessions.Range(func(_, value any) bool {
		if session, ok := value.(*Session); ok {
			notified.Add(1)
			go func() {
				defer notified.Done()
				_ = session.Mux.SendGoAway("shutdown", "server is shutting down")
			}()
		}
		return true
	})
	sent := make(chan struct{})
	go func() { notified.Wait(); close(sent) }()
	select {
	case <-sent:
	case <-time.After(goAwayGrace):
	}

	s.cancel()

	// Graceful shutdown of HTTP servers
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()

	if s.httpServer != nil {
		_ = s.httpServer.Shutdown(shutdownCtx)
	}
	if s.httpsServer != nil {
		_ = s.httpsServer.Shutdown(shutdownCtx)
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
	if s.config.ControlTLSConfig != nil {
		s.controlListener = tls.NewListener(s.controlListener, s.config.ControlTLSConfig)
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

// controlAuthTimeout bounds how long a control connection may stay
// unauthenticated.
var controlAuthTimeout = 10 * time.Second

// handleControlConnection handles a control plane connection.
func (s *Server) handleControlConnection(conn net.Conn) {
	defer conn.Close()

	remoteAddr := conn.RemoteAddr()
	s.logger.Debug("control connection", "remote", remoteAddr)

	releasePending, ok := s.pending.acquire(remoteAddr)
	if !ok {
		s.logger.Warn("too many unauthenticated control connections", "remote", remoteAddr)
		return
	}
	defer releasePending()

	// An unauthenticated peer gets controlAuthTimeout to finish the TLS
	// handshake, the magic bytes and the auth frame; the deadline is lifted
	// once it has authenticated.
	_ = conn.SetReadDeadline(time.Now().Add(controlAuthTimeout))

	// Read magic bytes
	if err := proto.ReadMagic(conn); err != nil {
		s.logger.Warn("invalid magic", "remote", remoteAddr, "error", err)
		return
	}

	// Create mux
	muxCfg := mux.DefaultConfig()
	muxCfg.HalfCloseTimeout = s.config.HalfCloseTimeout
	m := mux.New(conn, muxCfg)
	m.SetMaxStreams(0) // no streams before authentication
	go func() { _ = m.Run() }()

	// Authenticate
	session, err := s.handleAuth(m, remoteAddr)
	if err != nil {
		s.logger.Warn("auth failed", "remote", remoteAddr, "error", err)
		m.Close()
		return
	}
	defer s.removeSession(session.ID)
	releasePending()
	_ = conn.SetReadDeadline(time.Time{})
	m.SetMaxStreams(muxCfg.MaxStreams)

	s.logger.Info("session started", "id", session.ID, "remote", remoteAddr)

	// Handle tunnel requests until disconnect
	s.handleTunnelRequests(m, session)

	s.logger.Info("session ended", "id", session.ID)
}

// handleAuth authenticates a client connection.
func (s *Server) handleAuth(m *mux.Mux, remoteAddr net.Addr) (*Session, error) {
	// Wait for auth frame with timeout
	authTimer := time.NewTimer(controlAuthTimeout)
	defer authTimer.Stop()

	select {
	case frame := <-m.ControlFrame():
		if frame.Type != proto.FrameAuthReq {
			return nil, fmt.Errorf("expected AUTH_REQ, got %v", frame.Type)
		}

		var authReq proto.AuthRequest
		if err := proto.DecodeJSONPayload(frame, &authReq); err != nil {
			return nil, fmt.Errorf("decode auth request: %w", err)
		}

		ip := remoteIP(remoteAddr)
		if s.authFails.Get(ip).Tokens() < 1 {
			resp := &proto.AuthResponse{OK: false, Error: "too many failed attempts, try again later", Retry: true}
			respFrame, _ := proto.EncodeJSONPayload(proto.FrameAuthRes, 0, resp)
			_ = m.GetFrameWriter().Write(respFrame)
			return nil, fmt.Errorf("auth throttled for %s", ip)
		}

		// Validate token
		tok, account, err := s.authManager.ValidateToken(authReq.Token)
		if err != nil {
			s.authFails.Allow(ip) // spend one credit; a run of failures empties the bucket
			// Send failure response
			resp := &proto.AuthResponse{OK: false, Error: err.Error()}
			respFrame, _ := proto.EncodeJSONPayload(proto.FrameAuthRes, 0, resp)
			_ = m.GetFrameWriter().Write(respFrame)
			return nil, fmt.Errorf("invalid token: %w", err)
		}

		// Create session
		sessionID := fmt.Sprintf("sess_%s", generateSubdomain())
		session := &Session{
			ID:         sessionID,
			AccountID:  account.ID,
			Account:    account,
			Token:      tok,
			Mux:        m,
			Tunnels:    make(map[string]*Tunnel),
			CreatedAt:  time.Now(),
			LastSeen:   time.Now(),
			RemoteAddr: remoteAddr,
		}
		if !s.registerSession(session, account.MaxSessions) {
			resp := &proto.AuthResponse{OK: false, Error: "session limit reached for this account", Retry: true}
			respFrame, _ := proto.EncodeJSONPayload(proto.FrameAuthRes, 0, resp)
			_ = m.GetFrameWriter().Write(respFrame)
			return nil, fmt.Errorf("account %s is at its session limit (%d)", account.ID, account.MaxSessions)
		}

		// Send success response
		maxTunnels := s.config.MaxTunnelsPerSession
		resp := &proto.AuthResponse{
			OK:         true,
			SessionID:  sessionID,
			MaxTunnels: maxTunnels,
		}
		respFrame, _ := proto.EncodeJSONPayload(proto.FrameAuthRes, 0, resp)
		_ = m.GetFrameWriter().Write(respFrame)

		return session, nil

	case <-authTimer.C:
		return nil, fmt.Errorf("auth timeout")

	case <-s.ctx.Done():
		return nil, fmt.Errorf("server shutting down")
	}
}

// Failed logins from one IP: a burst of authFailBurst, then one more every
// 1/authFailRefill seconds. An empty bucket refuses further attempts outright,
// so guessing tokens over the control port is slow and a correct token from a
// quiet IP is never delayed.
const (
	authFailBurst  = 10
	authFailRefill = 0.2
)

// remoteIP returns the host part of addr (or its whole string).
func remoteIP(addr net.Addr) string {
	if addr == nil {
		return ""
	}
	s := addr.String()
	if host, _, err := net.SplitHostPort(s); err == nil {
		return host
	}
	return s
}

// registerSession stores session unless its account already has maxSessions
// live sessions (0 = unlimited).
func (s *Server) registerSession(session *Session, maxSessions int) bool {
	s.acctMu.Lock()
	defer s.acctMu.Unlock()
	if maxSessions > 0 && s.accountSessionCount(session.AccountID) >= maxSessions {
		return false
	}
	s.sessions.Store(session.ID, session)
	return true
}

func (s *Server) accountSessionCount(accountID string) int {
	n := 0
	s.sessions.Range(func(_, v any) bool {
		if v.(*Session).AccountID == accountID {
			n++
		}
		return true
	})
	return n
}

// addTunnel registers a tunnel on its session and returns "" or the reason it
// was refused. The account limit is re-checked under acctMu so parallel
// requests from one account's sessions cannot all pass the early check in
// handleTunnelRequest and overshoot max_tunnels.
func (s *Server) addTunnel(session *Session, t *Tunnel) string {
	s.acctMu.Lock()
	defer s.acctMu.Unlock()
	if acct := session.Account; acct != nil && acct.MaxTunnels > 0 && s.accountTunnelCount(acct.ID) >= acct.MaxTunnels {
		return "account tunnel limit reached"
	}
	if !session.addTunnel(t, s.config.MaxTunnelsPerSession) {
		return "session closed"
	}
	return ""
}

// accountTunnelCount counts the tunnels of every live session of an account.
func (s *Server) accountTunnelCount(accountID string) int {
	n := 0
	s.sessions.Range(func(_, v any) bool {
		sess := v.(*Session)
		if sess.AccountID == accountID {
			sess.mu.RLock()
			n += len(sess.Tunnels)
			sess.mu.RUnlock()
		}
		return true
	})
	return n
}

// allowTunnelRequest applies the account's tunnel-creation rate. The limiter is
// keyed by account, so reconnecting does not hand out a fresh allowance. The
// bootstrap account keeps the server default.
func (s *Server) allowTunnelRequest(session *Session) bool {
	account := session.Account
	if account == nil {
		return s.rateLimiter.Allow("tunnel:" + session.ID)
	}
	key := "tunnel:" + account.ID
	if account.ID != auth.DevAccountID && account.RateLimit > 0 {
		return s.rateLimiter.AllowWith(key, float64(account.RateLimit), account.RateLimit)
	}
	return s.rateLimiter.Allow(key)
}

// CloseRevokedSessions ends every session whose token has been revoked, has
// expired or lost its account since the session logged in (typically after the
// token file was reloaded) and returns how many it closed.
func (s *Server) CloseRevokedSessions() int {
	var stale []*Session
	s.sessions.Range(func(_, v any) bool {
		if sess := v.(*Session); !s.authManager.StillValid(sess.Token) {
			stale = append(stale, sess)
		}
		return true
	})
	for _, sess := range stale {
		s.logger.Info("closing session: token is no longer valid", "session", sess.ID, "account", sess.AccountID)
		s.removeSession(sess.ID)
		_ = sess.Mux.Close()
	}
	return len(stale)
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

// maxTunnelTTLSeconds caps a requested tunnel lifetime (one year).
const maxTunnelTTLSeconds = 365 * 24 * 3600

// handleTunnelRequest processes a tunnel creation request.
// sendTunnelError sends a tunnel error response.
func sendTunnelError(m *mux.Mux, msg string) {
	resp := &proto.TunnelResponse{OK: false, Error: msg}
	respFrame, _ := proto.EncodeJSONPayload(proto.FrameTunnelRes, 0, resp)
	_ = m.GetFrameWriter().Write(respFrame)
}

func (s *Server) handleTunnelRequest(m *mux.Mux, session *Session, frame *proto.Frame) {
	var req proto.TunnelRequest
	if err := proto.DecodeJSONPayload(frame, &req); err != nil {
		sendTunnelError(m, "invalid request")
		return
	}

	if !s.allowTunnelRequest(session) {
		sendTunnelError(m, "rate limit exceeded")
		return
	}

	if acct := session.Account; acct != nil && acct.MaxTunnels > 0 && s.accountTunnelCount(acct.ID) >= acct.MaxTunnels {
		sendTunnelError(m, "account tunnel limit reached")
		return
	}

	session.mu.Lock()
	if session.Tunnels == nil || len(session.Tunnels) >= s.config.MaxTunnelsPerSession {
		session.mu.Unlock()
		sendTunnelError(m, "max tunnels exceeded")
		return
	}
	session.mu.Unlock()

	if req.TTLSeconds < 0 || req.TTLSeconds > maxTunnelTTLSeconds {
		sendTunnelError(m, "invalid ttl")
		return
	}

	if req.CustomDomain != "" && req.Type != proto.TunnelTypeHTTP {
		sendTunnelError(m, "custom domains are only supported for HTTP tunnels")
		return
	}

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

// validateTunnelAuth rejects an auth block the edge would not enforce, so a
// tunnel is never created unprotected by mistake.
func validateTunnelAuth(a *proto.TunnelAuth) error {
	if a == nil {
		return nil
	}
	if a.Type != "basic" {
		return fmt.Errorf("unsupported auth type %q", a.Type)
	}
	if a.Username == "" || a.Password == "" {
		return errors.New("basic auth needs a username and a password")
	}
	return nil
}

// createHTTPTunnel handles HTTP tunnel creation.
func (s *Server) createHTTPTunnel(m *mux.Mux, session *Session, req *proto.TunnelRequest, tunnelID string) {
	// Subdomains are case-insensitive on the wire; normalize so "MyApp" and
	// "myapp" are the same tunnel and the edge lookup (lowercased) finds it.
	subdomain := strings.ToLower(req.Subdomain)
	if subdomain == "" {
		subdomain = generateSubdomain()
	}

	if !utils.IsValidSubdomain(subdomain) {
		sendTunnelError(m, "invalid subdomain")
		return
	}
	if utils.IsReservedSubdomain(subdomain) {
		sendTunnelError(m, "subdomain is reserved")
		return
	}
	if err := validateTunnelAuth(req.Auth); err != nil {
		sendTunnelError(m, err.Error())
		return
	}

	customDomain, err := s.prepareCustomDomain(session, req.CustomDomain)
	if err != nil {
		sendTunnelError(m, err.Error())
		return
	}

	// Build the full tunnel before storing to avoid a race where another
	// goroutine reads an empty placeholder between LoadOrStore and Store.
	tunnel := &Tunnel{
		ID:           tunnelID,
		Type:         proto.TunnelTypeHTTP,
		SessionID:    session.ID,
		AccountID:    session.AccountID,
		Subdomain:    subdomain,
		CustomDomain: customDomain,
		PublicURL:    s.publicHTTPURL(subdomain),
		LocalAddr:    req.LocalAddr,
		AllowedIPs:   req.AllowedIPs,
		PIN:          req.PIN,
		Auth:         req.Auth,
		Headers:      req.Headers,
		Inspect:      req.Inspect,
		CreatedAt:    time.Now(),
		ExpiresAt:    expiryFor(req.TTLSeconds),
		closed:       make(chan struct{}),
	}

	if customDomain != "" {
		tunnel.PublicURL = s.publicURLForHost(customDomain)
	}

	if _, loaded := s.tunnels.LoadOrStore(subdomain, tunnel); loaded {
		sendTunnelError(m, "subdomain already taken")
		return
	}
	if customDomain != "" {
		if _, loaded := s.tunnels.LoadOrStore(customKeyPrefix+customDomain, tunnel); loaded {
			s.tunnels.Delete(subdomain)
			sendTunnelError(m, "custom domain already in use by another tunnel")
			return
		}
	}

	if refusal := s.addTunnel(session, tunnel); refusal != "" {
		s.tunnels.Delete(subdomain)
		if customDomain != "" {
			s.tunnels.Delete(customKeyPrefix + customDomain)
		}
		sendTunnelError(m, refusal)
		return
	}
	s.armExpiry(session, tunnel)

	resp := &proto.TunnelResponse{
		OK:        true,
		TunnelID:  tunnelID,
		Type:      proto.TunnelTypeHTTP,
		PublicURL: tunnel.PublicURL,
		ExpiresAt: expiresAtPtr(tunnel.ExpiresAt),
	}
	respFrame, _ := proto.EncodeJSONPayload(proto.FrameTunnelRes, 0, resp)
	_ = m.GetFrameWriter().Write(respFrame)

	s.logger.Info("tunnel created", "id", tunnelID, "type", "http", "subdomain", subdomain, "custom_domain", customDomain)
}

// createTCPTunnel handles TCP tunnel creation.
func (s *Server) createTCPTunnel(m *mux.Mux, session *Session, req *proto.TunnelRequest, tunnelID string) {
	// Bind before announcing success so a listen failure is reported.
	listener, port, err := s.listenTunnelPort()
	if err != nil {
		if errors.Is(err, ErrPortUnavailable) {
			sendTunnelError(m, "no ports available")
			return
		}
		s.logger.Error("failed to start TCP tunnel listener", "error", err)
		sendTunnelError(m, "failed to bind tunnel port")
		return
	}

	tunnel := &Tunnel{
		ID:         tunnelID,
		Type:       proto.TunnelTypeTCP,
		SessionID:  session.ID,
		AccountID:  session.AccountID,
		Port:       port,
		PublicURL:  "tcp://" + s.config.Domain + ":" + strconv.Itoa(port),
		LocalAddr:  req.LocalAddr,
		AllowedIPs: req.AllowedIPs,
		CreatedAt:  time.Now(),
		ExpiresAt:  expiryFor(req.TTLSeconds),
		closed:     make(chan struct{}),
	}
	tunnel.listener = listener
	tunnel.stop = make(chan struct{})

	portKey := "tcp:" + strconv.Itoa(port)
	s.tunnels.Store(portKey, tunnel)

	if refusal := s.addTunnel(session, tunnel); refusal != "" {
		s.tunnels.Delete(portKey)
		listener.Close()
		s.releasePort(port)
		sendTunnelError(m, refusal)
		return
	}

	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		s.serveTCPTunnelListener(listener, tunnel, session)
	}()

	s.armExpiry(session, tunnel)

	resp := &proto.TunnelResponse{
		OK:        true,
		TunnelID:  tunnelID,
		Type:      proto.TunnelTypeTCP,
		PublicURL: tunnel.PublicURL,
		ExpiresAt: expiresAtPtr(tunnel.ExpiresAt),
	}
	respFrame, _ := proto.EncodeJSONPayload(proto.FrameTunnelRes, 0, resp)
	_ = m.GetFrameWriter().Write(respFrame)

	s.logger.Info("tunnel created", "id", tunnelID, "type", "tcp", "port", port)
}

// maxTunnelBindAttempts bounds how many ports of the range are tried when some
// are taken by other programs (a busy range is common: it overlaps the OS's
// ephemeral ports).
const maxTunnelBindAttempts = 16

// listenTunnelPort reserves a free port of the range and listens on it. A port
// that cannot be bound is skipped, so one foreign listener does not fail the
// tunnel while the rest of the range is free.
func (s *Server) listenTunnelPort() (net.Listener, int, error) {
	var lastErr error
	for attempt := 0; attempt < maxTunnelBindAttempts; attempt++ {
		port, err := s.allocatePort()
		if err != nil {
			if lastErr != nil {
				return nil, 0, lastErr
			}
			return nil, 0, err
		}
		listener, err := net.Listen("tcp", s.tcpListenAddr(port))
		if err == nil {
			return listener, port, nil
		}
		s.releasePort(port)
		s.logger.Warn("tunnel port unavailable, trying the next one", "port", port, "error", err)
		lastErr = err
	}
	return nil, 0, lastErr
}

// handleTunnelClose processes a tunnel close request.
func (s *Server) handleTunnelClose(session *Session, frame *proto.Frame) {
	var req proto.TunnelClose
	if err := proto.DecodeJSONPayload(frame, &req); err != nil {
		return
	}
	s.closeTunnel(session, req.TunnelID, "closed")
}

// closeTunnel removes one tunnel from its session and from the public
// registries, stopping its listener and expiry timer. It reports whether the
// tunnel existed. It is the single teardown path for client close requests,
// time-limited tunnels that expire, and (via teardownTunnel) session removal.
func (s *Server) closeTunnel(session *Session, tunnelID, reason string) bool {
	session.mu.Lock()
	if session.Tunnels == nil {
		session.mu.Unlock()
		return false
	}
	tunnel, ok := session.Tunnels[tunnelID]
	if ok {
		delete(session.Tunnels, tunnelID)
	}
	session.mu.Unlock()
	if !ok {
		return false
	}

	s.teardownTunnel(tunnel)
	s.logger.Info("tunnel "+reason, "id", tunnelID)
	return true
}

// teardownTunnel releases everything a tunnel holds.
func (s *Server) teardownTunnel(tunnel *Tunnel) {
	tunnel.cancelExpiry()
	tunnel.markClosed()
	switch tunnel.Type {
	case proto.TunnelTypeHTTP:
		s.tunnels.Delete(tunnel.Subdomain)
		if tunnel.CustomDomain != "" {
			// Only release the name if it still points at this tunnel.
			s.tunnels.CompareAndDelete(customKeyPrefix+tunnel.CustomDomain, tunnel)
		}
	case proto.TunnelTypeTCP:
		s.tunnels.Delete("tcp:" + strconv.Itoa(tunnel.Port))
		tunnel.shutdown()
		s.releasePort(tunnel.Port)
	}
}

// expiryFor returns the expiry time for a TTL in seconds (zero = no expiry).
func expiryFor(ttlSeconds int) time.Time {
	if ttlSeconds <= 0 {
		return time.Time{}
	}
	return time.Now().Add(time.Duration(ttlSeconds) * time.Second)
}

func expiresAtPtr(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	return &t
}

// armExpiry schedules the automatic close of a time-limited tunnel.
func (s *Server) armExpiry(session *Session, tunnel *Tunnel) {
	if tunnel.ExpiresAt.IsZero() {
		return
	}
	id := tunnel.ID
	timer := time.AfterFunc(time.Until(tunnel.ExpiresAt), func() {
		s.closeTunnel(session, id, "expired")
	})
	tunnel.mu.Lock()
	tunnel.expiry = timer
	tunnel.mu.Unlock()

	// If the session was torn down between registration and here, its cleanup
	// found no timer to stop: don't let this one pin the session for the whole TTL.
	session.mu.RLock()
	_, alive := session.Tunnels[id]
	session.mu.RUnlock()
	if !alive {
		timer.Stop()
	}
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
		s.teardownTunnel(tunnel)
	}
}

// startTCPTunnelListener starts a TCP listener for a tunnel.
func (s *Server) startTCPTunnelListener(port int, tunnel *Tunnel, session *Session) {
	listener, err := net.Listen("tcp", s.tcpListenAddr(port))
	if err != nil {
		s.logger.Error("failed to start TCP tunnel listener", "port", port, "error", err)
		return
	}
	tunnel.mu.Lock()
	tunnel.listener = listener
	tunnel.mu.Unlock()
	s.serveTCPTunnelListener(listener, tunnel, session)
}

// serveTCPTunnelListener accepts visitors on an already-bound listener until
// the server, the session mux, or the tunnel itself shuts down.
func (s *Server) serveTCPTunnelListener(listener net.Listener, tunnel *Tunnel, session *Session) {
	defer listener.Close()

	// Close listener when context, mux or tunnel is done to unblock Accept
	go func() {
		select {
		case <-s.ctx.Done():
		case <-session.Mux.Done():
		case <-tunnel.stop: // nil (never fires) for tunnels without a stop channel
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
		if host, _, err := net.SplitHostPort(clientIP); err == nil {
			clientIP = host
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

	// Closing the tunnel (explicit close, TTL expiry, session end) must also cut
	// connections that are already established.
	stopWatch := tunnel.watch(func() { conn.Close() }, func() { _ = stream.Reset() })
	defer stopWatch()

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
		// No absolute Read/WriteTimeout: they would cut any response or upload
		// longer than the limit (SSE, large downloads). Progress is bounded by a
		// per-operation idle deadline instead (see Config.EdgeIdleTimeout).
		IdleTimeout:    120 * time.Second,
		MaxHeaderBytes: 1 << 20,
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
		// No absolute Read/WriteTimeout: they would cut any response or upload
		// longer than the limit (SSE, large downloads). Progress is bounded by a
		// per-operation idle deadline instead (see Config.EdgeIdleTimeout).
		IdleTimeout:    120 * time.Second,
		MaxHeaderBytes: 1 << 20,
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

// HTTPSAddr returns the HTTPS listener address (useful when using port 0).
func (s *Server) HTTPSAddr() string {
	if s.httpsListener != nil {
		return s.httpsListener.Addr().String()
	}
	return s.config.HTTPSAddr
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
	ID           string     `json:"id"`
	AccountID    string     `json:"account_id,omitempty"`
	Type         string     `json:"type"`
	URL          string     `json:"url,omitempty"`
	CustomDomain string     `json:"custom_domain,omitempty"`
	Port         int        `json:"port,omitempty"`
	Target       string     `json:"target"`
	LocalPort    int        `json:"local_port,omitempty"`
	Status       string     `json:"status"`
	AllowedIPs   []string   `json:"allowed_ips,omitempty"`
	HasPIN       bool       `json:"has_pin,omitempty"`
	HasAuth      bool       `json:"has_auth,omitempty"`
	Inspect      bool       `json:"inspect,omitempty"`
	CreatedAt    time.Time  `json:"created_at"`
	ExpiresAt    *time.Time `json:"expires_at,omitempty"`
}

// SessionInfo represents session information for API responses.
type SessionInfo struct {
	ID            string    `json:"id"`
	AccountID     string    `json:"account_id"`
	RemoteAddr    string    `json:"remote_addr"`
	ConnectedAt   time.Time `json:"connected_at"`
	LastSeen      time.Time `json:"last_seen"`
	LastHeartbeat time.Time `json:"last_heartbeat"`
	TunnelCount   int       `json:"tunnel_count"`
	Uptime        float64   `json:"uptime_seconds"`
}

// ListTunnels returns a list of all active tunnels.
func (s *Server) ListTunnels() []TunnelInfo {
	var tunnels []TunnelInfo
	s.tunnels.Range(func(key, value any) bool {
		if isAliasKey(key) {
			return true // a custom-domain alias of a tunnel that is listed under its own key
		}
		if t, ok := value.(*Tunnel); ok {
			t.mu.RLock()
			info := TunnelInfo{
				ID:           t.ID,
				AccountID:    t.AccountID,
				Type:         string(t.Type),
				URL:          t.PublicURL,
				Port:         t.Port,
				CustomDomain: t.CustomDomain,
				Target:       t.LocalAddr,
				Status:       "active",
				AllowedIPs:   t.AllowedIPs,
				HasPIN:       t.PIN != "",
				HasAuth:      t.Auth != nil,
				Inspect:      t.Inspect,
				CreatedAt:    t.CreatedAt,
				ExpiresAt:    expiresAtPtr(t.ExpiresAt),
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
			var lastHB time.Time
			if sess.Mux != nil {
				lastHB = sess.Mux.LastHeartbeat()
			}
			info := SessionInfo{
				ID:            sess.ID,
				AccountID:     sess.AccountID,
				RemoteAddr:    sess.RemoteAddr.String(),
				ConnectedAt:   sess.CreatedAt,
				LastSeen:      sess.LastSeen,
				LastHeartbeat: lastHB,
				TunnelCount:   len(sess.Tunnels),
				Uptime:        time.Since(sess.CreatedAt).Seconds(),
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
	return s.statsFor("")
}

// StatsFor is Stats limited to one account: its own tunnel and session counts
// and no server-wide traffic totals. An empty accountID means everything.
func (s *Server) StatsFor(accountID string) map[string]interface{} {
	return s.statsFor(accountID)
}

func (s *Server) statsFor(accountID string) map[string]interface{} {
	var tunnelCount, sessionCount int

	s.tunnels.Range(func(key, value any) bool {
		if isAliasKey(key) {
			return true
		}
		if t, ok := value.(*Tunnel); ok && accountID != "" && t.AccountID != accountID {
			return true
		}
		tunnelCount++
		return true
	})

	s.sessions.Range(func(key, value any) bool {
		if accountID == "" || value.(*Session).AccountID == accountID {
			sessionCount++
		}
		return true
	})

	if accountID != "" {
		return map[string]interface{}{"active_tunnels": tunnelCount, "active_sessions": sessionCount}
	}
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
			evicted := s.rateLimiter.Evict(interval*2) + s.authFails.Evict(interval*2)
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

// publicHTTPURL builds the public URL of an HTTP tunnel.
func (s *Server) publicHTTPURL(subdomain string) string {
	return s.publicURLForHost(subdomain + "." + s.config.Domain)
}

// publicURLForHost builds a tunnel URL for an arbitrary public host name.
func (s *Server) publicURLForHost(host string) string {
	scheme := s.config.PublicScheme
	if scheme == "" {
		scheme = "http"
	}
	port := s.config.PublicPort
	if port == 0 || (scheme == "http" && port == 80) || (scheme == "https" && port == 443) {
		return scheme + "://" + host
	}
	return scheme + "://" + net.JoinHostPort(host, strconv.Itoa(port))
}

// prepareCustomDomain validates a requested custom domain, makes sure nobody
// else is serving it, and verifies the DNS ownership proof. It returns "" when
// no custom domain was requested.
func (s *Server) prepareCustomDomain(session *Session, requested string) (string, error) {
	if requested == "" {
		return "", nil
	}
	domain, err := normalizeCustomDomain(requested, s.config.Domain)
	if err != nil {
		return "", err
	}
	// Prove ownership first: only the owner may learn whether the domain is
	// currently in use (otherwise any client could probe which custom domains
	// are live).
	if err := s.verifyCustomDomain(s.ctx, session.AccountID, domain); err != nil {
		return "", err
	}
	if _, taken := s.tunnels.Load(customKeyPrefix + domain); taken {
		return "", errors.New("custom domain already in use by another tunnel")
	}
	return domain, nil
}

// tcpListenAddr is the listen address of a TCP tunnel's public port.
func (s *Server) tcpListenAddr(port int) string {
	return net.JoinHostPort(s.config.TCPBindHost, strconv.Itoa(port))
}
