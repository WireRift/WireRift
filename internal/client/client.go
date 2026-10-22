package client

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/wirerift/wirerift/internal/mux"
	"github.com/wirerift/wirerift/internal/proto"
)

// Errors returned by client operations.
var (
	ErrNotConnected = errors.New("not connected to server")
	ErrAuthFailed   = errors.New("authentication failed")
	ErrTunnelFailed = errors.New("tunnel creation failed")
)

// Config holds client configuration.
type Config struct {
	// ServerAddr is the address of the tunnel server.
	ServerAddr string

	// Token is the authentication token.
	Token string

	// TLSConfig is the TLS configuration.
	TLSConfig *tls.Config

	// Reconnect enables automatic reconnection.
	Reconnect bool

	// ReconnectInterval is the initial reconnect interval.
	ReconnectInterval time.Duration

	// MaxReconnectInterval is the maximum reconnect interval.
	MaxReconnectInterval time.Duration

	// HeartbeatInterval is the interval for sending heartbeats.
	HeartbeatInterval time.Duration
}

// DefaultConfig returns the default client configuration.
func DefaultConfig() Config {
	return Config{
		ServerAddr:           "wirerift.com:4443",
		Reconnect:            true,
		ReconnectInterval:    1 * time.Second,
		MaxReconnectInterval: 30 * time.Second,
		HeartbeatInterval:    30 * time.Second,
	}
}

// Client is the tunnel client.
type Client struct {
	config Config
	logger *slog.Logger

	// Connection. connMu guards conn, mux and sessionID: reconnectLoop replaces
	// them while Close and the public accessors read them.
	connMu sync.RWMutex
	conn   net.Conn
	mux    *mux.Mux

	// Session state
	sessionID  string
	connected  atomic.Bool
	maxTunnels int

	// Tunnels
	tunnels sync.Map // map[string]*Tunnel

	// HTTP client for proxying (shared for connection reuse)
	httpClient *http.Client

	// Lifecycle
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// Tunnel represents an active tunnel.
type Tunnel struct {
	ID        string
	Type      proto.TunnelType
	PublicURL string
	LocalAddr string
	Subdomain string
	Port      int
	ExpiresAt time.Time // zero when the tunnel has no time limit
	client    *Client
	request   *proto.TunnelRequest // original creation request for reconnect
}

// New creates a new client.
func New(config Config, logger *slog.Logger) *Client {
	if logger == nil {
		logger = slog.Default()
	}

	ctx, cancel := context.WithCancel(context.Background())

	return &Client{
		config: config,
		logger: logger,
		ctx:    ctx,
		cancel: cancel,
		httpClient: &http.Client{
			// No overall Timeout: it would also cap body streaming and cut off
			// large downloads/SSE. Bound connect and time-to-first-byte instead.
			// Redirects are the visitor's to follow, not this relay's.
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
			Transport: &http.Transport{
				DialContext:           (&net.Dialer{Timeout: 10 * time.Second}).DialContext,
				ResponseHeaderTimeout: 30 * time.Second,
				MaxIdleConns:          100,
				MaxIdleConnsPerHost:   10,
				IdleConnTimeout:       90 * time.Second,
			},
		},
	}
}

// Connect connects to the tunnel server.
func (c *Client) Connect() error {
	if err := c.connect(); err != nil {
		return err
	}

	// Start stream handler (pass mux explicitly to avoid race on reconnect)
	currentMux := c.mux
	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		c.handleStreams(currentMux)
	}()

	// Start heartbeat (pass mux explicitly to avoid race on reconnect)
	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		c.heartbeatLoop(currentMux)
	}()

	// Start reconnect loop if enabled
	if c.config.Reconnect {
		c.wg.Add(1)
		go func() {
			defer c.wg.Done()
			c.reconnectLoop()
		}()
	}

	return nil
}

// TLSScheme prefixes a server address to request TLS on the control plane
// (e.g. "tls://tunnel.example.com:4443").
const TLSScheme = "tls://"

// dialServer connects to the control plane, using TLS when the address has the
// tls:// prefix or Config.TLSConfig is set. WIRERIFT_TLS_CA may name a PEM file
// with an extra CA to trust (for servers using a private certificate).
func (c *Client) dialServer() (net.Conn, error) {
	addr, useTLS := SplitServerAddr(c.config.ServerAddr)
	useTLS = useTLS || c.config.TLSConfig != nil
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	if !useTLS {
		return dialer.Dial("tcp", addr)
	}
	cfg, err := ControlTLSConfig(c.config.TLSConfig)
	if err != nil {
		return nil, err
	}
	return (&tls.Dialer{NetDialer: dialer, Config: cfg}).Dial("tcp", addr)
}

// SplitServerAddr strips an optional tls:// scheme from a server address and
// reports whether TLS was requested.
func SplitServerAddr(addr string) (hostPort string, useTLS bool) {
	if strings.HasPrefix(addr, TLSScheme) {
		return strings.TrimPrefix(addr, TLSScheme), true
	}
	return addr, false
}

// ControlTLSConfig returns the TLS configuration used to reach a TLS control
// plane: base (or secure defaults) plus the extra CA named by WIRERIFT_TLS_CA.
func ControlTLSConfig(base *tls.Config) (*tls.Config, error) {
	var cfg *tls.Config
	if base != nil {
		cfg = base.Clone()
	} else {
		cfg = &tls.Config{MinVersion: tls.VersionTLS12}
	}
	if caFile := os.Getenv("WIRERIFT_TLS_CA"); caFile != "" && cfg.RootCAs == nil {
		pem, err := os.ReadFile(caFile)
		if err != nil {
			return nil, fmt.Errorf("read WIRERIFT_TLS_CA: %w", err)
		}
		pool, err := x509.SystemCertPool()
		if err != nil || pool == nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("WIRERIFT_TLS_CA %s contains no certificates", caFile)
		}
		cfg.RootCAs = pool
	}
	return cfg, nil
}

// connect establishes the connection and authenticates.
func (c *Client) connect() error {
	// Dial server
	conn, err := c.dialServer()
	if err != nil {
		return fmt.Errorf("dial server: %w", err)
	}

	// Send magic bytes (4 bytes write to a just-opened TCP connection cannot fail)
	_ = proto.WriteMagic(conn)

	// Create mux and start run loop FIRST so it dispatches control frames
	m := mux.New(conn, mux.DefaultConfig())

	// Publish the new connection unless the client was closed meanwhile. Close
	// cancels the context before taking this lock, so either we see the
	// cancellation here, or Close sees (and closes) the connection published here.
	c.connMu.Lock()
	if c.ctx.Err() != nil {
		c.connMu.Unlock()
		m.Close()
		conn.Close()
		return fmt.Errorf("cancelled")
	}
	c.conn, c.mux = conn, m
	c.connMu.Unlock()

	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		_ = m.Run()
	}()

	// Authenticate
	if err := c.authenticate(); err != nil {
		m.Close() // Close mux first to stop mux.Run() goroutine
		conn.Close()
		return err
	}

	c.connected.Store(true)
	c.logger.Info("connected", "session", c.SessionID())

	return nil
}

// authenticate sends authentication request.
func (c *Client) authenticate() error {
	authReq := &proto.AuthRequest{
		Token:   c.config.Token,
		Version: "1.0.0",
	}

	// EncodeJSONPayload cannot fail for AuthRequest (only string fields)
	frame, _ := proto.EncodeJSONPayload(proto.FrameAuthReq, proto.ControlStreamID, authReq)

	m := c.currentMux()
	if err := m.GetFrameWriter().Write(frame); err != nil {
		return fmt.Errorf("send auth request: %w", err)
	}

	// Read response from control frame channel (dispatched by mux.Run)
	var respFrame *proto.Frame
	select {
	case f := <-m.ControlFrame():
		respFrame = f
	case <-m.Done():
		return fmt.Errorf("connection closed")
	case <-c.ctx.Done():
		return fmt.Errorf("cancelled")
	}

	if respFrame.Type != proto.FrameAuthRes {
		return fmt.Errorf("unexpected frame type: %v", respFrame.Type)
	}

	var authRes proto.AuthResponse
	if err := proto.DecodeJSONPayload(respFrame, &authRes); err != nil {
		return fmt.Errorf("decode auth response: %w", err)
	}

	if !authRes.OK {
		return fmt.Errorf("%w: %s", ErrAuthFailed, authRes.Error)
	}

	c.connMu.Lock()
	c.sessionID = authRes.SessionID
	c.connMu.Unlock()
	c.maxTunnels = authRes.MaxTunnels

	return nil
}

// Close closes the client.
func (c *Client) Close() error {
	c.cancel()

	c.connMu.RLock()
	m, conn := c.mux, c.conn
	c.connMu.RUnlock()
	if m != nil {
		m.Close()
	}
	if conn != nil {
		conn.Close()
	}

	c.wg.Wait()
	return nil
}

// HTTP opens an HTTP tunnel.
func (c *Client) HTTP(localAddr string, opts ...HTTPOption) (*Tunnel, error) {
	if !c.connected.Load() {
		return nil, ErrNotConnected
	}

	req := &proto.TunnelRequest{
		Type:      proto.TunnelTypeHTTP,
		LocalAddr: localAddr,
	}

	for _, opt := range opts {
		opt(req)
	}

	return c.openTunnel(req)
}

// TCP opens a TCP tunnel.
func (c *Client) TCP(localAddr string, port int, opts ...TCPOption) (*Tunnel, error) {
	if !c.connected.Load() {
		return nil, ErrNotConnected
	}

	req := &proto.TunnelRequest{
		Type:       proto.TunnelTypeTCP,
		LocalAddr:  localAddr,
		RemotePort: port,
	}
	for _, opt := range opts {
		opt(req)
	}

	return c.openTunnel(req)
}

// openTunnel sends a tunnel request.
func (c *Client) openTunnel(req *proto.TunnelRequest) (*Tunnel, error) {
	// EncodeJSONPayload cannot fail for TunnelRequest (simple JSON-serializable fields)
	frame, _ := proto.EncodeJSONPayload(proto.FrameTunnelReq, proto.ControlStreamID, req)

	m := c.currentMux()
	if err := m.GetFrameWriter().Write(frame); err != nil {
		return nil, fmt.Errorf("send tunnel request: %w", err)
	}

	// Read response from control frame channel (dispatched by mux.Run)
	var respFrame *proto.Frame
	select {
	case f := <-m.ControlFrame():
		respFrame = f
	case <-m.Done():
		return nil, fmt.Errorf("connection closed")
	case <-c.ctx.Done():
		return nil, fmt.Errorf("cancelled")
	}

	if respFrame.Type != proto.FrameTunnelRes {
		return nil, fmt.Errorf("unexpected frame type: %v", respFrame.Type)
	}

	var res proto.TunnelResponse
	if err := proto.DecodeJSONPayload(respFrame, &res); err != nil {
		return nil, fmt.Errorf("decode tunnel response: %w", err)
	}

	if !res.OK {
		return nil, fmt.Errorf("%w: %s", ErrTunnelFailed, res.Error)
	}

	// The server does not echo the assigned port in TunnelResponse; for TCP
	// tunnels it is only carried in PublicURL ("tcp://domain:port"). Consumers
	// (the CLI prints Tunnel.Port) need the assigned port.
	tunnel := &Tunnel{
		ID:        res.TunnelID,
		Type:      res.Type,
		PublicURL: res.PublicURL,
		LocalAddr: req.LocalAddr,
		Subdomain: req.Subdomain,
		Port:      assignedTCPPort(res.Type, res.PublicURL, req.RemotePort),
		client:    c,
		request:   req,
	}

	if res.ExpiresAt != nil {
		tunnel.ExpiresAt = *res.ExpiresAt
	}
	c.tunnels.Store(res.TunnelID, tunnel)

	c.logger.Info("tunnel opened", "id", res.TunnelID, "url", res.PublicURL)

	return tunnel, nil
}

// assignedTCPPort returns the server-assigned public port for a TCP tunnel.
// The assigned port is only carried in publicURL ("tcp://domain:port"), so it
// is parsed from there; on any parse failure (or a zero port) the requested
// remotePort is returned. For non-TCP tunnels the requested value is returned
// unchanged (HTTP tunnels have no public port).
func assignedTCPPort(tunnelType proto.TunnelType, publicURL string, remotePort int) int {
	if tunnelType != proto.TunnelTypeTCP {
		return remotePort
	}
	u, err := url.Parse(publicURL)
	if err != nil {
		return remotePort
	}
	p, err := strconv.Atoi(u.Port())
	if err != nil || p == 0 {
		return remotePort
	}
	return p
}

// CloseTunnel closes a tunnel.
func (c *Client) CloseTunnel(id string) error {
	m := c.currentMux()
	if m == nil {
		return ErrNotConnected
	}

	closeReq := &proto.TunnelClose{TunnelID: id}
	// EncodeJSONPayload cannot fail for TunnelClose (only string field)
	frame, _ := proto.EncodeJSONPayload(proto.FrameTunnelClose, proto.ControlStreamID, closeReq)

	if err := m.GetFrameWriter().Write(frame); err != nil {
		return err
	}

	c.tunnels.Delete(id)
	c.logger.Info("tunnel closed", "id", id)

	return nil
}

// SessionID returns the current session ID.
func (c *Client) SessionID() string {
	c.connMu.RLock()
	defer c.connMu.RUnlock()
	return c.sessionID
}

// currentMux returns the active mux (nil before the first connection).
func (c *Client) currentMux() *mux.Mux {
	c.connMu.RLock()
	defer c.connMu.RUnlock()
	return c.mux
}

// IsConnected returns true if connected.
func (c *Client) IsConnected() bool {
	return c.connected.Load()
}

// FrameWriter returns the frame writer (for internal use).
func (c *Client) FrameWriter() *proto.FrameWriter {
	m := c.currentMux()
	if m == nil {
		return nil
	}
	return m.GetFrameWriter()
}

// FrameReader returns the frame reader (for internal use).
func (c *Client) FrameReader() *proto.FrameReader {
	m := c.currentMux()
	if m == nil {
		return nil
	}
	return m.GetFrameReader()
}

// heartbeatLoop sends periodic heartbeats using the given mux.
// The mux is captured at start to avoid racing with reconnectLoop replacing c.mux.
func (c *Client) heartbeatLoop(m *mux.Mux) {
	ticker := time.NewTicker(c.config.HeartbeatInterval)
	defer ticker.Stop()
	started := time.Now()

	for {
		select {
		case <-c.ctx.Done():
			return
		case <-ticker.C:
			if !c.connected.Load() {
				continue
			}

			// Dead-peer detection: a half-open TCP connection never errors,
			// so give up after three intervals without any heartbeat ack and
			// let the reconnect loop take over.
			lastAlive := started
			if hb := m.LastHeartbeat(); hb.After(lastAlive) {
				lastAlive = hb
			}
			if time.Since(lastAlive) > 3*c.config.HeartbeatInterval {
				c.logger.Warn("no heartbeat ack from server, closing connection")
				m.Close()
				continue
			}

			frame := &proto.Frame{
				Version:  proto.Version,
				Type:     proto.FrameHeartbeat,
				StreamID: 0,
				Payload:  proto.HeartbeatPayload(),
			}

			if err := m.GetFrameWriter().Write(frame); err != nil {
				c.logger.Warn("heartbeat failed", "error", err)
			}
		case <-m.Done():
			c.connected.Store(false)
			c.logger.Warn("connection lost")
			return
		}
	}
}

// reconnectLoop handles automatic reconnection.
func (c *Client) reconnectLoop() {
	interval := c.config.ReconnectInterval

	for {
		select {
		case <-c.ctx.Done():
			return
		case <-c.mux.Done():
			if !c.config.Reconnect {
				return
			}

			c.connected.Store(false)

			// Ensure old mux and connection are fully closed before reconnecting.
			// This allows the old mux.Run() goroutine to exit cleanly.
			if c.mux != nil {
				c.mux.Close()
			}
			if c.conn != nil {
				c.conn.Close()
			}

			c.logger.Info("reconnecting", "interval", interval)

			timer := time.NewTimer(interval)
			select {
			case <-c.ctx.Done():
				timer.Stop()
				return
			case <-timer.C:
			}

			if err := c.connect(); err != nil {
				c.logger.Warn("reconnect failed", "error", err)
				interval = interval * 2
				if interval > c.config.MaxReconnectInterval {
					interval = c.config.MaxReconnectInterval
				}
				continue
			}

			// Re-create tunnels from previous session
			c.recreateTunnels()

			// Restart stream handler and heartbeat for new connection
			reconnectedMux := c.mux
			c.wg.Add(2)
			go func() {
				defer c.wg.Done()
				c.handleStreams(reconnectedMux)
			}()
			go func() {
				defer c.wg.Done()
				c.heartbeatLoop(reconnectedMux)
			}()

			interval = c.config.ReconnectInterval
			c.logger.Info("tunnel restored", "session", c.SessionID())
		}
	}
}

// tunnelRetryBase is the initial backoff between tunnel re-creation attempts.
var tunnelRetryBase = time.Second

// recreateTunnels re-creates all tunnels after a reconnect.
func (c *Client) recreateTunnels() {
	var oldTunnels []*Tunnel
	c.tunnels.Range(func(key, value any) bool {
		oldTunnels = append(oldTunnels, value.(*Tunnel))
		c.tunnels.Delete(key)
		return true
	})

	// A tunnel that could not be re-created stays registered so the next
	// reconnect tries again, instead of being lost for good (a client with an
	// empty tunnel map looks connected but serves nothing).
	m := c.mux
	keep := func(t *Tunnel) { c.tunnels.Store(t.ID, t) }

	for _, t := range oldTunnels {
		if t.request == nil {
			continue
		}
		request := *t.request
		// The server may still hold the previous session (and its subdomain or
		// port) for a moment, so retry with backoff before giving up.
		var newTunnel *Tunnel
		var err error
		expired, lost := false, false
		for attempt, delay := 0, tunnelRetryBase; attempt < 5; attempt, delay = attempt+1, delay*2 {
			// A time-limited tunnel keeps its ORIGINAL deadline across reconnects.
			// The remaining time is recomputed on every attempt (the retry sleeps
			// eat into it) and rounded DOWN, so no reconnect can extend the
			// deadline; once it has passed the tunnel is not revived.
			if !t.ExpiresAt.IsZero() {
				remaining := time.Until(t.ExpiresAt)
				if remaining < time.Second {
					expired = true
					break
				}
				request.TTLSeconds = int(remaining / time.Second)
			}
			if newTunnel, err = c.openTunnel(&request); err == nil {
				break
			}
			select {
			case <-m.Done():
				// The connection dropped again: retrying on a dead mux only burns
				// time. Leave it to the next reconnect.
				lost = true
			default:
			}
			if lost {
				break
			}
			c.logger.Warn("failed to re-create tunnel, will retry", "id", t.ID, "attempt", attempt+1, "error", err)
			select {
			case <-time.After(delay):
			case <-c.ctx.Done():
				return
			}
		}
		if expired {
			c.logger.Info("tunnel expired, not re-creating", "id", t.ID)
			continue
		}
		if lost {
			c.logger.Warn("connection lost while re-creating tunnel, will retry on next reconnect", "id", t.ID, "error", err)
			keep(t)
			continue
		}
		if err != nil {
			c.logger.Error("giving up re-creating tunnel for now, will retry on next reconnect", "id", t.ID, "error", err)
			keep(t)
			continue
		}
		c.logger.Info("tunnel re-created", "old_id", t.ID, "new_id", newTunnel.ID, "url", newTunnel.PublicURL)
	}
}

// HTTPOption is an option for HTTP tunnels.
type HTTPOption func(*proto.TunnelRequest)

// TCPOption is an option for TCP tunnels.
type TCPOption = HTTPOption

// WithTTL makes the server close the tunnel automatically after d (rounded up
// to whole seconds). It works for both HTTP and TCP tunnels.
func WithTTL(d time.Duration) HTTPOption {
	return func(req *proto.TunnelRequest) {
		if d < 0 {
			req.TTLSeconds = -1 // rejected by the server; never "no limit"
			return
		}
		req.TTLSeconds = int((d + time.Second - 1) / time.Second)
	}
}

// WithSubdomain sets the subdomain.
func WithSubdomain(subdomain string) HTTPOption {
	return func(req *proto.TunnelRequest) {
		req.Subdomain = subdomain
	}
}

// WithCustomDomain also serves the tunnel on a domain you own (e.g.
// app.example.com). The server verifies ownership through a DNS TXT record and
// reports the exact record to create when it is missing.
func WithCustomDomain(domain string) HTTPOption {
	return func(req *proto.TunnelRequest) {
		req.CustomDomain = domain
	}
}

// WithInspect enables traffic inspection.
func WithInspect() HTTPOption {
	return func(req *proto.TunnelRequest) {
		req.Inspect = true
	}
}

// WithAuth sets tunnel authentication.
func WithAuth(username, password string) HTTPOption {
	return func(req *proto.TunnelRequest) {
		req.Auth = &proto.TunnelAuth{
			Type:     "basic",
			Username: username,
			Password: password,
		}
	}
}

// WithHeaders sets custom headers.
func WithHeaders(headers map[string]string) HTTPOption {
	return func(req *proto.TunnelRequest) {
		req.Headers = headers
	}
}

// WithAllowedIPs sets the IP whitelist for the tunnel.
// Only requests from these IPs will be allowed. Supports CIDR notation.
func WithAllowedIPs(ips []string) HTTPOption {
	return func(req *proto.TunnelRequest) {
		req.AllowedIPs = ips
	}
}

// WithPIN sets PIN protection for the tunnel.
// Visitors must enter the PIN to access the tunnel.
func WithPIN(pin string) HTTPOption {
	return func(req *proto.TunnelRequest) {
		req.PIN = pin
	}
}

// Close closes the tunnel.
func (t *Tunnel) Close() error {
	return t.client.CloseTunnel(t.ID)
}

// handleStreams accepts incoming streams from the given mux and dispatches them.
// The mux is passed explicitly to avoid a race where reconnectLoop replaces c.mux
// while a previous handleStreams goroutine is still running on the old mux.
func (c *Client) handleStreams(m *mux.Mux) {
	for {
		stream, err := m.AcceptStream()
		if err != nil {
			return
		}
		go func() {
			defer func() {
				if r := recover(); r != nil {
					c.logger.Error("panic in stream handler", "error", r)
				}
			}()
			c.handleStream(stream)
		}()
	}
}

// handleStream routes a stream based on its protocol.
func (c *Client) handleStream(stream *mux.Stream) {
	defer stream.Close()
	protocol := stream.Protocol()

	switch protocol {
	case "http":
		c.handleHTTPStream(stream)
	case "tcp":
		c.handleTCPStream(stream)
	default:
		_ = stream.Reset()
	}
}

// handleHTTPStream handles an incoming HTTP stream by proxying to the local service.
func (c *Client) handleHTTPStream(stream *mux.Stream) {
	// Find the tunnel for this stream
	tunnel := c.findTunnelForStream(stream)
	if tunnel == nil {
		_ = stream.Reset()
		return
	}

	// Read HTTP request from stream
	reader := bufio.NewReader(stream)
	req, err := http.ReadRequest(reader)
	if err != nil {
		return
	}

	// WebSocket upgrades cannot pass through http.Client/resp.Write: a 101
	// Switching Protocols response carries a live bidirectional body that
	// blocks the response writer forever, so the visitor's handshake never
	// completes. Relay them as a raw pipe instead.
	if strings.EqualFold(req.Header.Get("Upgrade"), "websocket") {
		c.handleUpgradeStream(stream, req, tunnel)
		return
	}

	// Forward to local service
	req.URL.Scheme = "http"
	req.URL.Host = tunnel.LocalAddr
	req.RequestURI = ""

	resp, err := c.httpClient.Do(req)
	if err != nil {
		// The local app did not answer. The port is deliberately not shown:
		// the visitor is on the public internet.
		_, _ = stream.Write(localUnreachableResponse(strings.Contains(req.Header.Get("Accept"), "text/html") && req.Method != http.MethodHead))
		return
	}
	defer resp.Body.Close()

	// Write response back through stream
	_ = resp.Write(stream)
}

// handleUpgradeStream relays a WebSocket upgrade as a raw bidirectional pipe:
// the upgrade request is written verbatim to the local service and both
// directions are copied with per-direction closes, so the 101 handshake,
// frames, and EOF all propagate (mirrors the server-side proxyTCPConnection
// relay and handleTCPStream).
func (c *Client) handleUpgradeStream(stream *mux.Stream, req *http.Request, tunnel *Tunnel) {
	localConn, err := net.DialTimeout("tcp", tunnel.LocalAddr, 10*time.Second)
	if err != nil {
		stream.Close()
		return
	}
	defer localConn.Close()

	if err := req.Write(localConn); err != nil {
		stream.Close()
		return
	}

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		io.Copy(localConn, stream)
		localConn.Close()
	}()
	go func() {
		defer wg.Done()
		io.Copy(stream, localConn)
		stream.Close()
	}()
	wg.Wait()
}

// handleTCPStream handles an incoming TCP stream by proxying to the local service.
func (c *Client) handleTCPStream(stream *mux.Stream) {
	tunnel := c.findTunnelForStream(stream)
	if tunnel == nil {
		_ = stream.Reset()
		return
	}

	// Dial local service
	localConn, err := net.DialTimeout("tcp", tunnel.LocalAddr, 10*time.Second)
	if err != nil {
		stream.Close()
		return
	}
	defer localConn.Close()

	// Bidirectional copy
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		io.Copy(localConn, stream)
		// Remote finished sending: propagate EOF to the local service.
		if tc, ok := localConn.(*net.TCPConn); ok {
			_ = tc.CloseWrite()
		}
	}()
	go func() {
		defer wg.Done()
		io.Copy(stream, localConn)
		// Local service finished: half-close so the visitor sees EOF.
		stream.Close()
	}()
	wg.Wait()
}

// findTunnelForStream finds the tunnel associated with a stream.
func (c *Client) findTunnelForStream(stream *mux.Stream) *Tunnel {
	tunnelID := stream.TunnelID()
	if v, ok := c.tunnels.Load(tunnelID); ok {
		return v.(*Tunnel)
	}
	return nil
}

const unreachableText = "Local service unreachable: the tunnel is up, but nothing answered on the local port."

const unreachableHTML = `<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>502 Bad Gateway - WireRift</title>
<style>*{margin:0;padding:0;box-sizing:border-box}body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;background:#0f172a;color:#e2e8f0;display:flex;align-items:center;justify-content:center;min-height:100vh}.card{background:#1e293b;border:1px solid #334155;border-radius:12px;padding:40px;max-width:480px;width:90%}.code{font-size:14px;color:#818cf8;font-weight:600;margin-bottom:8px}h1{font-size:22px;margin-bottom:12px;color:#fff}p{color:#94a3b8;font-size:15px;line-height:1.5}.brand{margin-top:24px;font-size:12px;color:#64748b}</style></head>
<body><div class="card"><div class="code">502 Bad Gateway</div><h1>The local app is not responding</h1>
<p>The tunnel is working, but nothing answered on the local port. Start your app (or check that it listens on the port you exposed), then refresh this page.</p>
<div class="brand">WireRift</div></div></body></html>`

// localUnreachableResponse builds the raw HTTP 502 sent through the tunnel when
// the local service cannot be reached.
func localUnreachableResponse(html bool) []byte {
	body, ctype := unreachableText+"\n", "text/plain; charset=utf-8"
	if html {
		body, ctype = unreachableHTML, "text/html; charset=utf-8"
	}
	return []byte("HTTP/1.1 502 Bad Gateway\r\n" +
		"Content-Type: " + ctype + "\r\n" +
		"Content-Length: " + strconv.Itoa(len(body)) + "\r\n" +
		"Cache-Control: no-store\r\n" +
		"X-WireRift-Error: local-service-unreachable\r\n\r\n" + body)
}
