package client

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/wirerift/wirerift/internal/mux"
	"github.com/wirerift/wirerift/internal/proto"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	if cfg.ServerAddr == "" {
		t.Error("ServerAddr should not be empty")
	}
	if cfg.ReconnectInterval <= 0 {
		t.Error("ReconnectInterval should be positive")
	}
	if cfg.HeartbeatInterval <= 0 {
		t.Error("HeartbeatInterval should be positive")
	}
	if cfg.MaxReconnectInterval <= 0 {
		t.Error("MaxReconnectInterval should be positive")
	}
	if !cfg.Reconnect {
		t.Error("Reconnect should be true by default")
	}
}

func TestClientNew(t *testing.T) {
	cfg := DefaultConfig()
	c := New(cfg, nil)

	if c == nil {
		t.Fatal("New returned nil")
	}
	if c.config.ServerAddr != cfg.ServerAddr {
		t.Errorf("ServerAddr = %q, want %q", c.config.ServerAddr, cfg.ServerAddr)
	}
}

func TestClientNewWithLogger(t *testing.T) {
	logger := slog.Default()
	c := New(DefaultConfig(), logger)
	if c.logger != logger {
		t.Error("Logger not set correctly")
	}
}

func TestClientNewWithNilLogger(t *testing.T) {
	c := New(DefaultConfig(), nil)
	if c.logger == nil {
		t.Error("Logger should be set to default when nil is passed")
	}
}

func TestClientCloseWithoutConnect(t *testing.T) {
	c := New(DefaultConfig(), nil)
	if err := c.Close(); err != nil {
		t.Errorf("Close failed: %v", err)
	}
}

func TestCloseIdempotent(t *testing.T) {
	c := New(DefaultConfig(), nil)
	for i := 0; i < 3; i++ {
		if err := c.Close(); err != nil {
			t.Errorf("Close %d failed: %v", i+1, err)
		}
	}
}

func TestHTTPOptions(t *testing.T) {
	tests := []struct {
		name     string
		opt      HTTPOption
		validate func(*proto.TunnelRequest) bool
	}{
		{
			name: "WithSubdomain",
			opt:  WithSubdomain("myapp"),
			validate: func(req *proto.TunnelRequest) bool {
				return req.Subdomain == "myapp"
			},
		},
		{
			name: "WithInspect",
			opt:  WithInspect(),
			validate: func(req *proto.TunnelRequest) bool {
				return req.Inspect
			},
		},
		{
			name: "WithAuth",
			opt:  WithAuth("user", "pass"),
			validate: func(req *proto.TunnelRequest) bool {
				return req.Auth != nil && req.Auth.Username == "user" && req.Auth.Password == "pass" && req.Auth.Type == "basic"
			},
		},
		{
			name: "WithHeaders",
			opt:  WithHeaders(map[string]string{"X-Test": "value"}),
			validate: func(req *proto.TunnelRequest) bool {
				return req.Headers["X-Test"] == "value"
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &proto.TunnelRequest{}
			tt.opt(req)
			if !tt.validate(req) {
				t.Errorf("Validation failed for %s", tt.name)
			}
		})
	}
}

func TestIsConnected(t *testing.T) {
	c := New(DefaultConfig(), nil)
	if c.IsConnected() {
		t.Error("Should not be connected initially")
	}
}

func TestSessionID(t *testing.T) {
	c := New(DefaultConfig(), nil)
	if c.SessionID() != "" {
		t.Error("SessionID should be empty before connecting")
	}
}

func TestHTTPNotConnected(t *testing.T) {
	c := New(DefaultConfig(), nil)
	_, err := c.HTTP("localhost:3000")
	if err != ErrNotConnected {
		t.Errorf("Expected ErrNotConnected, got %v", err)
	}
}

func TestTCPNotConnected(t *testing.T) {
	c := New(DefaultConfig(), nil)
	_, err := c.TCP("localhost:3000", 8080)
	if err != ErrNotConnected {
		t.Errorf("Expected ErrNotConnected, got %v", err)
	}
}

func TestCloseTunnelNotConnected(t *testing.T) {
	c := New(DefaultConfig(), nil)
	err := c.CloseTunnel("test-id")
	if err != ErrNotConnected {
		t.Errorf("Expected ErrNotConnected, got %v", err)
	}
}

func TestTunnelGetters(t *testing.T) {
	tunnel := &Tunnel{
		ID:        "test-id",
		PublicURL: "https://test.wirerift.dev",
		LocalAddr: "localhost:3000",
	}
	if tunnel.GetPublicURL() != "https://test.wirerift.dev" {
		t.Errorf("GetPublicURL = %q, want %q", tunnel.GetPublicURL(), "https://test.wirerift.dev")
	}
	if tunnel.GetLocalAddr() != "localhost:3000" {
		t.Errorf("GetLocalAddr = %q, want %q", tunnel.GetLocalAddr(), "localhost:3000")
	}
}

func TestTunnelClose(t *testing.T) {
	c := New(DefaultConfig(), nil)
	tunnel := &Tunnel{ID: "test-tunnel", client: c}
	err := tunnel.Close()
	if err != ErrNotConnected {
		t.Errorf("Expected ErrNotConnected, got %v", err)
	}
}

func TestFrameWriterReaderBeforeConnect(t *testing.T) {
	c := New(DefaultConfig(), nil)
	if c.FrameWriter() != nil {
		t.Error("FrameWriter should be nil before connect")
	}
	if c.FrameReader() != nil {
		t.Error("FrameReader should be nil before connect")
	}
}

func TestClientErrors(t *testing.T) {
	if ErrClientClosed == nil {
		t.Error("ErrClientClosed should not be nil")
	}
	if ErrNotConnected == nil {
		t.Error("ErrNotConnected should not be nil")
	}
	if ErrAuthFailed == nil {
		t.Error("ErrAuthFailed should not be nil")
	}
	if ErrTunnelFailed == nil {
		t.Error("ErrTunnelFailed should not be nil")
	}
	if ErrReconnectFailed == nil {
		t.Error("ErrReconnectFailed should not be nil")
	}
}

// --- Mock server for full-flow connect tests ---
// The mock server uses a mux on the server side, matching the real server.
// This ensures control frames are dispatched properly through the mux protocol.

type mockServer struct {
	listener net.Listener
	addr     string
	token    string
	tunnels  map[string]*Tunnel
	mu       struct {
		sync.Mutex
		connCount int
	}
}

func newMockServer(t *testing.T) *mockServer {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to create listener: %v", err)
	}
	ms := &mockServer{
		listener: l,
		addr:     l.Addr().String(),
		token:    "test-token",
		tunnels:  make(map[string]*Tunnel),
	}
	go ms.serve()
	return ms
}

func (ms *mockServer) serve() {
	for {
		conn, err := ms.listener.Accept()
		if err != nil {
			return
		}
		ms.mu.Lock()
		ms.mu.connCount++
		ms.mu.Unlock()
		go ms.handleConn(conn)
	}
}

func (ms *mockServer) handleConn(conn net.Conn) {
	defer conn.Close()

	magic := make([]byte, 4)
	if _, err := io.ReadFull(conn, magic); err != nil {
		return
	}
	if magic[0] != 0x57 || magic[1] != 0x52 || magic[2] != 0x46 || magic[3] != 0x01 {
		return
	}

	// Use a mux on the server side so control frames are dispatched properly
	m := mux.New(conn, mux.DefaultConfig())
	go m.Run()

	for {
		select {
		case frame, ok := <-m.ControlFrame():
			if !ok {
				return
			}

			switch frame.Type {
			case proto.FrameAuthReq:
				ms.handleAuth(frame, m.GetFrameWriter())
			case proto.FrameTunnelReq:
				ms.handleTunnelRequest(frame, m.GetFrameWriter())
			case proto.FrameTunnelClose:
				// Just consume it
			}

		case <-m.Done():
			return
		}
	}
}

func (ms *mockServer) handleAuth(frame *proto.Frame, writer *proto.FrameWriter) {
	var authReq proto.AuthRequest
	if err := proto.DecodeJSONPayload(frame, &authReq); err != nil {
		return
	}

	authRes := &proto.AuthResponse{
		OK:         authReq.Token == ms.token,
		SessionID:  "test-session-123",
		MaxTunnels: 10,
	}
	if authReq.Token != ms.token {
		authRes.Error = "invalid token"
	}

	respFrame, _ := proto.EncodeJSONPayload(proto.FrameAuthRes, proto.ControlStreamID, authRes)
	writer.Write(respFrame)
}

func (ms *mockServer) handleTunnelRequest(frame *proto.Frame, writer *proto.FrameWriter) {
	var req proto.TunnelRequest
	if err := proto.DecodeJSONPayload(frame, &req); err != nil {
		return
	}

	res := &proto.TunnelResponse{
		OK:        true,
		TunnelID:  "tunnel-" + time.Now().Format("20060102150405"),
		Type:      req.Type,
		PublicURL: "https://test.wirerift.dev",
	}

	respFrame, _ := proto.EncodeJSONPayload(proto.FrameTunnelRes, proto.ControlStreamID, res)
	writer.Write(respFrame)
}

func (ms *mockServer) Close() {
	ms.listener.Close()
}

func (ms *mockServer) ConnectionCount() int {
	ms.mu.Lock()
	defer ms.mu.Unlock()
	return ms.mu.connCount
}

// --- Helper: create a connected client using net.Pipe ---

// makeConnectedClient creates a Client with an active mux backed by a net.Pipe.
// The mux.Run() loop is started so that control frames are dispatched.
// Returns the client, and the server-side mux for sending responses.
func makeConnectedClient(t *testing.T) (*Client, *mux.Mux) {
	t.Helper()
	c1, c2 := net.Pipe()

	cfg := Config{
		HeartbeatInterval:    100 * time.Millisecond,
		ReconnectInterval:    50 * time.Millisecond,
		MaxReconnectInterval: 200 * time.Millisecond,
	}
	c := New(cfg, slog.Default())
	c.conn = c1
	c.mux = mux.New(c1, mux.DefaultConfig())
	c.connected.Store(true)
	c.sessionID = "test-session"
	c.maxTunnels = 10
	go c.mux.Run()

	serverMux := mux.New(c2, mux.DefaultConfig())
	go serverMux.Run()

	return c, serverMux
}

// makeConnectedClientRaw creates a Client with an active mux backed by a net.Pipe.
// Returns the client and the raw server-side connection (not a mux).
// Used for tests that need direct control over the connection (e.g., close, drain).
func makeConnectedClientRaw(t *testing.T) (*Client, net.Conn) {
	t.Helper()
	c1, c2 := net.Pipe()

	cfg := Config{
		HeartbeatInterval:    100 * time.Millisecond,
		ReconnectInterval:    50 * time.Millisecond,
		MaxReconnectInterval: 200 * time.Millisecond,
	}
	c := New(cfg, slog.Default())
	c.conn = c1
	c.mux = mux.New(c1, mux.DefaultConfig())
	c.connected.Store(true)
	c.sessionID = "test-session"
	c.maxTunnels = 10

	return c, c2
}

// --- connect() tests ---

func TestConnectFailureDial(t *testing.T) {
	cfg := DefaultConfig()
	cfg.ServerAddr = "127.0.0.1:1"
	cfg.Reconnect = false
	c := New(cfg, nil)
	err := c.Connect()
	if err == nil {
		t.Fatal("Expected error for invalid address")
	}
	c.Close()
}

func TestConnectWithTLSDialFailure(t *testing.T) {
	cfg := DefaultConfig()
	cfg.ServerAddr = "127.0.0.1:1"
	cfg.TLSConfig = &tls.Config{InsecureSkipVerify: true}
	cfg.Reconnect = false
	c := New(cfg, nil)
	err := c.Connect()
	if err == nil {
		t.Fatal("Expected error for TLS dial to invalid address")
	}
	c.Close()
}

func TestConnectSuccess(t *testing.T) {
	server := newMockServer(t)
	defer server.Close()

	cfg := DefaultConfig()
	cfg.ServerAddr = server.addr
	cfg.Token = server.token
	cfg.Reconnect = false
	cfg.HeartbeatInterval = 100 * time.Millisecond

	c := New(cfg, nil)
	defer c.Close()

	err := c.Connect()
	if err != nil {
		t.Fatalf("Connect failed: %v", err)
	}
	if !c.IsConnected() {
		t.Error("Should be connected")
	}
	if c.SessionID() == "" {
		t.Error("SessionID should not be empty")
	}
	if c.FrameWriter() == nil {
		t.Error("FrameWriter should not be nil after connect")
	}
	if c.FrameReader() == nil {
		t.Error("FrameReader should not be nil after connect")
	}
}

func TestConnectWithReconnectEnabled(t *testing.T) {
	server := newMockServer(t)
	defer server.Close()

	cfg := DefaultConfig()
	cfg.ServerAddr = server.addr
	cfg.Token = server.token
	cfg.Reconnect = true
	cfg.HeartbeatInterval = 100 * time.Millisecond
	cfg.ReconnectInterval = 50 * time.Millisecond
	cfg.MaxReconnectInterval = 200 * time.Millisecond

	c := New(cfg, nil)
	err := c.Connect()
	if err != nil {
		t.Fatalf("Connect failed: %v", err)
	}
	if !c.IsConnected() {
		t.Error("Should be connected")
	}
	// Let heartbeat and reconnect goroutines run briefly
	time.Sleep(150 * time.Millisecond)
	c.Close()
}

func TestConnectAuthFailure(t *testing.T) {
	server := newMockServer(t)
	defer server.Close()

	cfg := DefaultConfig()
	cfg.ServerAddr = server.addr
	cfg.Token = "wrong-token"
	cfg.Reconnect = false
	c := New(cfg, nil)
	defer c.Close()

	err := c.Connect()
	if err == nil {
		t.Fatal("Expected error for invalid token")
	}
	if c.IsConnected() {
		t.Error("Should not be connected")
	}
}

// --- authenticate() tests using net.Pipe ---

func TestAuthenticateWriteError(t *testing.T) {
	c1, c2 := net.Pipe()
	c2.Close() // close the other end so writes fail

	cfg := Config{HeartbeatInterval: time.Second}
	c := New(cfg, slog.Default())
	c.conn = c1
	c.mux = mux.New(c1, mux.DefaultConfig())

	err := c.authenticate()
	if err == nil {
		t.Fatal("Expected error when writing to closed pipe")
	}
	c1.Close()
}

func TestAuthenticateReadError(t *testing.T) {
	c1, c2 := net.Pipe()

	cfg := Config{HeartbeatInterval: time.Second}
	c := New(cfg, slog.Default())
	c.conn = c1
	c.mux = mux.New(c1, mux.DefaultConfig())
	go c.mux.Run() // Start mux so it dispatches control frames

	// Server side: use a mux too, read the auth request then close
	serverMux := mux.New(c2, mux.DefaultConfig())
	go serverMux.Run()
	go func() {
		// Wait for control frame (the auth request), then close
		select {
		case <-serverMux.ControlFrame():
		case <-serverMux.Done():
		}
		// Close without sending response
		serverMux.Close()
	}()

	err := c.authenticate()
	if err == nil {
		t.Fatal("Expected error when reading response from closed conn")
	}
	c1.Close()
}

func TestAuthenticateDecodeError(t *testing.T) {
	c1, c2 := net.Pipe()

	cfg := Config{HeartbeatInterval: time.Second}
	c := New(cfg, slog.Default())
	c.conn = c1
	c.mux = mux.New(c1, mux.DefaultConfig())
	go c.mux.Run()

	// Server side: use a mux, read auth request, send auth response with invalid JSON
	serverMux := mux.New(c2, mux.DefaultConfig())
	go serverMux.Run()
	go func() {
		select {
		case <-serverMux.ControlFrame():
		case <-serverMux.Done():
			return
		}
		// Send auth response frame with invalid JSON payload
		badFrame := &proto.Frame{
			Version:  proto.Version,
			Type:     proto.FrameAuthRes,
			StreamID: 0,
			Payload:  []byte("not valid json{{{"),
		}
		serverMux.GetFrameWriter().Write(badFrame)
		// Keep mux alive to drain
		<-serverMux.Done()
	}()

	err := c.authenticate()
	if err == nil {
		t.Fatal("Expected error for bad JSON payload")
	}
	c1.Close()
	c2.Close()
}

func TestAuthenticateAuthFailed(t *testing.T) {
	c1, c2 := net.Pipe()

	cfg := Config{HeartbeatInterval: time.Second}
	c := New(cfg, slog.Default())
	c.conn = c1
	c.mux = mux.New(c1, mux.DefaultConfig())
	go c.mux.Run()

	serverMux := mux.New(c2, mux.DefaultConfig())
	go serverMux.Run()
	go func() {
		select {
		case <-serverMux.ControlFrame():
		case <-serverMux.Done():
			return
		}
		resp := &proto.AuthResponse{
			OK:    false,
			Error: "access denied",
		}
		respFrame, _ := proto.EncodeJSONPayload(proto.FrameAuthRes, proto.ControlStreamID, resp)
		serverMux.GetFrameWriter().Write(respFrame)
		<-serverMux.Done()
	}()

	err := c.authenticate()
	if err == nil {
		t.Fatal("Expected error for auth failure")
	}
	c1.Close()
	c2.Close()
}

func TestAuthenticateSuccess(t *testing.T) {
	c1, c2 := net.Pipe()

	cfg := Config{HeartbeatInterval: time.Second}
	c := New(cfg, slog.Default())
	c.conn = c1
	c.mux = mux.New(c1, mux.DefaultConfig())
	go c.mux.Run()

	serverMux := mux.New(c2, mux.DefaultConfig())
	go serverMux.Run()
	go func() {
		select {
		case <-serverMux.ControlFrame():
		case <-serverMux.Done():
			return
		}
		resp := &proto.AuthResponse{
			OK:         true,
			SessionID:  "session-abc",
			MaxTunnels: 5,
		}
		respFrame, _ := proto.EncodeJSONPayload(proto.FrameAuthRes, proto.ControlStreamID, resp)
		serverMux.GetFrameWriter().Write(respFrame)
		<-serverMux.Done()
	}()

	err := c.authenticate()
	if err != nil {
		t.Fatalf("Expected success, got %v", err)
	}
	if c.sessionID != "session-abc" {
		t.Errorf("sessionID = %q, want session-abc", c.sessionID)
	}
	if c.maxTunnels != 5 {
		t.Errorf("maxTunnels = %d, want 5", c.maxTunnels)
	}
	c1.Close()
	c2.Close()
}

// --- openTunnel() tests ---

func TestOpenTunnelSuccess(t *testing.T) {
	client, serverMux := makeConnectedClient(t)

	go func() {
		select {
		case frame, ok := <-serverMux.ControlFrame():
			if !ok {
				return
			}
			if frame.Type != proto.FrameTunnelReq {
				return
			}
			resp := &proto.TunnelResponse{
				OK:        true,
				TunnelID:  "tun-123",
				Type:      proto.TunnelTypeHTTP,
				PublicURL: "https://myapp.wirerift.dev",
			}
			respFrame, _ := proto.EncodeJSONPayload(proto.FrameTunnelRes, proto.ControlStreamID, resp)
			serverMux.GetFrameWriter().Write(respFrame)
		case <-serverMux.Done():
		}
		<-serverMux.Done()
	}()

	req := &proto.TunnelRequest{
		Type:      proto.TunnelTypeHTTP,
		LocalAddr: "localhost:3000",
		Subdomain: "myapp",
	}
	tunnel, err := client.openTunnel(req)
	if err != nil {
		t.Fatalf("openTunnel failed: %v", err)
	}
	if tunnel.ID != "tun-123" {
		t.Errorf("tunnel ID = %q, want tun-123", tunnel.ID)
	}
	if tunnel.PublicURL != "https://myapp.wirerift.dev" {
		t.Errorf("PublicURL = %q, want https://myapp.wirerift.dev", tunnel.PublicURL)
	}
	if tunnel.LocalAddr != "localhost:3000" {
		t.Errorf("LocalAddr = %q, want localhost:3000", tunnel.LocalAddr)
	}
	if tunnel.Subdomain != "myapp" {
		t.Errorf("Subdomain = %q, want myapp", tunnel.Subdomain)
	}

	// Verify tunnel is stored
	if _, ok := client.tunnels.Load("tun-123"); !ok {
		t.Error("tunnel should be stored in client.tunnels")
	}

	client.conn.Close()
}

func TestOpenTunnelWriteError(t *testing.T) {
	client, serverMux := makeConnectedClient(t)
	serverMux.Close() // close server mux so writes fail

	req := &proto.TunnelRequest{
		Type:      proto.TunnelTypeHTTP,
		LocalAddr: "localhost:3000",
	}
	_, err := client.openTunnel(req)
	if err == nil {
		t.Fatal("Expected error when writing to closed conn")
	}
	client.conn.Close()
}

func TestOpenTunnelReadError(t *testing.T) {
	client, serverMux := makeConnectedClient(t)

	go func() {
		// Wait for control frame then close without responding
		select {
		case <-serverMux.ControlFrame():
		case <-serverMux.Done():
		}
		serverMux.Close()
	}()

	req := &proto.TunnelRequest{
		Type:      proto.TunnelTypeHTTP,
		LocalAddr: "localhost:3000",
	}
	_, err := client.openTunnel(req)
	if err == nil {
		t.Fatal("Expected error when reading from closed conn")
	}
	client.conn.Close()
}

func TestOpenTunnelDecodeError(t *testing.T) {
	client, serverMux := makeConnectedClient(t)

	go func() {
		select {
		case <-serverMux.ControlFrame():
		case <-serverMux.Done():
			return
		}
		badFrame := &proto.Frame{
			Version:  proto.Version,
			Type:     proto.FrameTunnelRes,
			StreamID: 0,
			Payload:  []byte("invalid json{{{"),
		}
		serverMux.GetFrameWriter().Write(badFrame)
		<-serverMux.Done()
	}()

	req := &proto.TunnelRequest{
		Type:      proto.TunnelTypeHTTP,
		LocalAddr: "localhost:3000",
	}
	_, err := client.openTunnel(req)
	if err == nil {
		t.Fatal("Expected error for invalid JSON")
	}
	client.conn.Close()
}

func TestOpenTunnelFailed(t *testing.T) {
	client, serverMux := makeConnectedClient(t)

	go func() {
		select {
		case <-serverMux.ControlFrame():
		case <-serverMux.Done():
			return
		}
		resp := &proto.TunnelResponse{
			OK:    false,
			Error: "max tunnels reached",
		}
		respFrame, _ := proto.EncodeJSONPayload(proto.FrameTunnelRes, proto.ControlStreamID, resp)
		serverMux.GetFrameWriter().Write(respFrame)
		<-serverMux.Done()
	}()

	req := &proto.TunnelRequest{
		Type:      proto.TunnelTypeHTTP,
		LocalAddr: "localhost:3000",
	}
	_, err := client.openTunnel(req)
	if err == nil {
		t.Fatal("Expected error for failed tunnel")
	}
	client.conn.Close()
}

// --- HTTP() and TCP() with connected client ---

func TestHTTPSuccess(t *testing.T) {
	client, serverMux := makeConnectedClient(t)

	go func() {
		select {
		case frame, ok := <-serverMux.ControlFrame():
			if !ok {
				return
			}
			if frame.Type != proto.FrameTunnelReq {
				return
			}
			resp := &proto.TunnelResponse{
				OK:        true,
				TunnelID:  "http-tun-1",
				Type:      proto.TunnelTypeHTTP,
				PublicURL: "https://myapp.wirerift.dev",
			}
			respFrame, _ := proto.EncodeJSONPayload(proto.FrameTunnelRes, proto.ControlStreamID, resp)
			serverMux.GetFrameWriter().Write(respFrame)
		case <-serverMux.Done():
		}
		<-serverMux.Done()
	}()

	tunnel, err := client.HTTP("localhost:3000", WithSubdomain("myapp"), WithInspect())
	if err != nil {
		t.Fatalf("HTTP failed: %v", err)
	}
	if tunnel.ID != "http-tun-1" {
		t.Errorf("tunnel ID = %q, want http-tun-1", tunnel.ID)
	}
	client.conn.Close()
}

func TestTCPSuccess(t *testing.T) {
	client, serverMux := makeConnectedClient(t)

	go func() {
		select {
		case frame, ok := <-serverMux.ControlFrame():
			if !ok {
				return
			}
			if frame.Type != proto.FrameTunnelReq {
				return
			}
			resp := &proto.TunnelResponse{
				OK:       true,
				TunnelID: "tcp-tun-1",
				Type:     proto.TunnelTypeTCP,
			}
			respFrame, _ := proto.EncodeJSONPayload(proto.FrameTunnelRes, proto.ControlStreamID, resp)
			serverMux.GetFrameWriter().Write(respFrame)
		case <-serverMux.Done():
		}
		<-serverMux.Done()
	}()

	tunnel, err := client.TCP("localhost:5432", 5432)
	if err != nil {
		t.Fatalf("TCP failed: %v", err)
	}
	if tunnel.ID != "tcp-tun-1" {
		t.Errorf("tunnel ID = %q, want tcp-tun-1", tunnel.ID)
	}
	if tunnel.Port != 5432 {
		t.Errorf("Port = %d, want 5432", tunnel.Port)
	}
	client.conn.Close()
}

// --- CloseTunnel() tests ---

func TestCloseTunnelSuccess(t *testing.T) {
	client, serverMux := makeConnectedClient(t)

	// Store a tunnel to close
	client.tunnels.Store("tun-1", &Tunnel{ID: "tun-1", client: client})

	go func() {
		// Drain control frames
		for {
			select {
			case <-serverMux.ControlFrame():
			case <-serverMux.Done():
				return
			}
		}
	}()

	err := client.CloseTunnel("tun-1")
	if err != nil {
		t.Fatalf("CloseTunnel failed: %v", err)
	}

	// Verify tunnel is deleted
	if _, ok := client.tunnels.Load("tun-1"); ok {
		t.Error("tunnel should be deleted after close")
	}

	client.conn.Close()
}

func TestCloseTunnelWriteError(t *testing.T) {
	client, serverMux := makeConnectedClient(t)
	serverMux.Close() // close server mux so writes fail
	// Wait briefly for the close to propagate
	time.Sleep(10 * time.Millisecond)

	err := client.CloseTunnel("tun-1")
	if err == nil {
		t.Fatal("Expected error when writing to closed conn")
	}
	client.conn.Close()
}

// --- heartbeatLoop() tests ---

func TestHeartbeatLoopSendsHeartbeat(t *testing.T) {
	server := newMockServer(t)
	defer server.Close()

	cfg := DefaultConfig()
	cfg.ServerAddr = server.addr
	cfg.Token = server.token
	cfg.Reconnect = false
	cfg.HeartbeatInterval = 50 * time.Millisecond

	c := New(cfg, nil)
	err := c.Connect()
	if err != nil {
		t.Fatalf("Connect failed: %v", err)
	}

	// Wait for multiple heartbeats
	time.Sleep(200 * time.Millisecond)

	if !c.IsConnected() {
		t.Error("Should still be connected after heartbeats")
	}
	c.Close()
}

func TestHeartbeatLoopCtxDone(t *testing.T) {
	server := newMockServer(t)
	defer server.Close()

	cfg := DefaultConfig()
	cfg.ServerAddr = server.addr
	cfg.Token = server.token
	cfg.Reconnect = false
	cfg.HeartbeatInterval = 50 * time.Millisecond

	c := New(cfg, nil)
	err := c.Connect()
	if err != nil {
		t.Fatalf("Connect failed: %v", err)
	}

	// Cancel context to trigger heartbeat loop exit
	c.cancel()
	// Wait for goroutines
	time.Sleep(100 * time.Millisecond)
}

func TestHeartbeatLoopWriteError(t *testing.T) {
	client, serverConn := makeConnectedClientRaw(t)

	// Close server side after a brief delay so heartbeat write fails,
	// then close mux to end the loop since heartbeat failures only log warnings.
	go func() {
		time.Sleep(50 * time.Millisecond)
		serverConn.Close()
		// Wait for at least one heartbeat failure, then close mux to exit loop
		time.Sleep(150 * time.Millisecond)
		client.mux.Close()
	}()

	client.heartbeatLoop()
	client.conn.Close()
}

func TestHeartbeatLoopMuxDone(t *testing.T) {
	client, serverConn := makeConnectedClientRaw(t)

	// Close the mux to trigger Done()
	go func() {
		time.Sleep(50 * time.Millisecond)
		client.mux.Close()
	}()

	client.heartbeatLoop()

	// After mux done, connected should be false
	if client.connected.Load() {
		t.Error("connected should be false after mux done")
	}
	serverConn.Close()
}

func TestHeartbeatLoopNotConnected(t *testing.T) {
	// Test the continue branch when not connected
	client, serverConn := makeConnectedClientRaw(t)
	client.connected.Store(false) // set not connected

	go func() {
		// Let a couple of heartbeat ticks pass (at 100ms interval), then cancel ctx
		time.Sleep(250 * time.Millisecond)
		client.cancel()
	}()

	// Drain server side
	go io.Copy(io.Discard, serverConn)

	client.heartbeatLoop()
	serverConn.Close()
	client.conn.Close()
}

// --- reconnectLoop() tests ---

func TestReconnectLoopCtxDone(t *testing.T) {
	client, serverConn := makeConnectedClientRaw(t)
	client.config.Reconnect = true

	// Cancel context immediately
	client.cancel()

	client.reconnectLoop()
	serverConn.Close()
	client.conn.Close()
}

func TestReconnectLoopReconnectDisabled(t *testing.T) {
	client, serverConn := makeConnectedClientRaw(t)
	client.config.Reconnect = false

	// Close mux to trigger Done
	go func() {
		time.Sleep(20 * time.Millisecond)
		client.mux.Close()
	}()

	client.reconnectLoop()
	serverConn.Close()
}

func TestReconnectLoopFailureWithBackoff(t *testing.T) {
	client, serverConn := makeConnectedClientRaw(t)
	client.config.Reconnect = true
	client.config.ServerAddr = "127.0.0.1:1" // will fail to reconnect
	client.config.ReconnectInterval = 20 * time.Millisecond
	client.config.MaxReconnectInterval = 50 * time.Millisecond

	// Close mux to trigger reconnect
	client.mux.Close()

	// Let it attempt a couple reconnects then cancel
	go func() {
		time.Sleep(200 * time.Millisecond)
		client.cancel()
	}()

	client.reconnectLoop()
	serverConn.Close()
}

func TestReconnectLoopCtxDoneDuringWait(t *testing.T) {
	client, serverConn := makeConnectedClientRaw(t)
	client.config.Reconnect = true
	client.config.ServerAddr = "127.0.0.1:1"
	client.config.ReconnectInterval = 5 * time.Second // long interval

	// Close mux to trigger reconnect
	client.mux.Close()

	// Cancel context while waiting for reconnect interval
	go func() {
		time.Sleep(50 * time.Millisecond)
		client.cancel()
	}()

	client.reconnectLoop()
	serverConn.Close()
}

func TestReconnectLoopSuccess(t *testing.T) {
	// Start a mock server that the client can reconnect to
	server := newMockServer(t)
	defer server.Close()

	client, serverConn := makeConnectedClientRaw(t)
	client.config.Reconnect = true
	client.config.ServerAddr = server.addr
	client.config.Token = server.token
	client.config.ReconnectInterval = 20 * time.Millisecond
	client.config.MaxReconnectInterval = 100 * time.Millisecond

	// Close mux to trigger reconnect
	client.mux.Close()

	// Let reconnect succeed, then cancel to stop the loop
	go func() {
		time.Sleep(300 * time.Millisecond)
		client.cancel()
	}()

	client.reconnectLoop()
	serverConn.Close()
}

// --- Full integration: Connect with reconnect, then connection loss ---

func TestConnectionLossTriggersReconnect(t *testing.T) {
	server := newMockServer(t)

	cfg := DefaultConfig()
	cfg.ServerAddr = server.addr
	cfg.Token = server.token
	cfg.Reconnect = false
	cfg.HeartbeatInterval = 100 * time.Millisecond

	c := New(cfg, nil)
	err := c.Connect()
	if err != nil {
		t.Fatalf("Connect failed: %v", err)
	}

	// Close server to cause connection loss
	server.Close()
	time.Sleep(200 * time.Millisecond)
	c.Close()
}

// --- Tunnel.Close via client ---

func TestTunnelCloseViaClient(t *testing.T) {
	client, serverMux := makeConnectedClient(t)

	go func() {
		for {
			select {
			case <-serverMux.ControlFrame():
			case <-serverMux.Done():
				return
			}
		}
	}()

	tunnel := &Tunnel{
		ID:     "tun-42",
		client: client,
	}
	client.tunnels.Store("tun-42", tunnel)

	err := tunnel.Close()
	if err != nil {
		t.Fatalf("tunnel.Close failed: %v", err)
	}

	if _, ok := client.tunnels.Load("tun-42"); ok {
		t.Error("tunnel should be deleted")
	}

	client.conn.Close()
}

// --- connect() WriteMagic error ---

func TestConnectWriteMagicError(t *testing.T) {
	// Test WriteMagic error path by creating a server that sends RST.
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	go func() {
		conn, err := l.Accept()
		if err != nil {
			return
		}
		// Set linger to 0 and close to send RST
		if tc, ok := conn.(*net.TCPConn); ok {
			tc.SetLinger(0)
		}
		conn.Close()
	}()

	cfg := DefaultConfig()
	cfg.ServerAddr = l.Addr().String()
	cfg.Reconnect = false

	c := New(cfg, nil)
	connectErr := c.connect()
	if connectErr == nil {
		t.Log("WriteMagic did not fail immediately (buffered)")
	}
	c.Close()
}

// --- connect() authenticate error (via mock server that sends wrong response) ---

func TestConnectAuthenticateError(t *testing.T) {
	// Server that accepts but sends wrong auth response
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	go func() {
		conn, err := l.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		// Read magic
		magic := make([]byte, 4)
		io.ReadFull(conn, magic)

		// Use a mux on the server side so the client mux dispatches correctly
		serverMux := mux.New(conn, mux.DefaultConfig())
		go serverMux.Run()

		// Wait for auth request
		select {
		case <-serverMux.ControlFrame():
		case <-serverMux.Done():
			return
		}

		// Send auth failure
		resp := &proto.AuthResponse{OK: false, Error: "bad token"}
		respFrame, _ := proto.EncodeJSONPayload(proto.FrameAuthRes, proto.ControlStreamID, resp)
		serverMux.GetFrameWriter().Write(respFrame)

		<-serverMux.Done()
	}()

	cfg := DefaultConfig()
	cfg.ServerAddr = l.Addr().String()
	cfg.Token = "bad-token"
	cfg.Reconnect = false

	c := New(cfg, nil)
	connectErr := c.connect()
	if connectErr == nil {
		t.Fatal("Expected auth error")
	}
	c.Close()
}

// --- More edge cases ---

func TestContextCancellation(t *testing.T) {
	c := New(DefaultConfig(), nil)
	select {
	case <-c.ctx.Done():
		t.Error("Context should not be done initially")
	default:
	}
	c.Close()
	select {
	case <-c.ctx.Done():
	default:
		t.Error("Context should be done after close")
	}
}

func TestMaxTunnelsAfterConnect(t *testing.T) {
	server := newMockServer(t)
	defer server.Close()

	cfg := DefaultConfig()
	cfg.ServerAddr = server.addr
	cfg.Token = server.token
	cfg.Reconnect = false

	c := New(cfg, nil)
	defer c.Close()

	if c.maxTunnels != 0 {
		t.Errorf("maxTunnels should be 0 before connect, got %d", c.maxTunnels)
	}

	err := c.Connect()
	if err != nil {
		t.Fatalf("Connect failed: %v", err)
	}

	if c.maxTunnels != 10 {
		t.Errorf("maxTunnels should be 10 after connect, got %d", c.maxTunnels)
	}
}

// --- Stream handler tests ---

func TestFindTunnelForStream(t *testing.T) {
	c := New(DefaultConfig(), nil)

	// No tunnel stored
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()
	m := mux.New(c1, mux.DefaultConfig())
	stream, _ := m.OpenStream()
	stream.SetMetadata("", "", "nonexistent")

	result := c.findTunnelForStream(stream)
	if result != nil {
		t.Error("Expected nil for nonexistent tunnel")
	}

	// Store a tunnel and find it
	tun := &Tunnel{ID: "tun-1", LocalAddr: "localhost:3000", client: c}
	c.tunnels.Store("tun-1", tun)
	stream.SetMetadata("", "", "tun-1")

	result = c.findTunnelForStream(stream)
	if result == nil {
		t.Fatal("Expected to find tunnel")
	}
	if result.ID != "tun-1" {
		t.Errorf("tunnel ID = %q, want tun-1", result.ID)
	}
}

// --- handleStream tests ---

func TestHandleStreamHTTP(t *testing.T) {
	// Start a local HTTP server
	localServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte("hello from local"))
	}))
	defer localServer.Close()

	c1, c2 := net.Pipe()
	clientMux := mux.New(c1, mux.DefaultConfig())
	serverMux := mux.New(c2, mux.DefaultConfig())
	go clientMux.Run()
	go serverMux.Run()

	cfg := DefaultConfig()
	c := New(cfg, nil)
	c.mux = clientMux
	c.connected.Store(true)

	localAddr := strings.TrimPrefix(localServer.URL, "http://")
	tun := &Tunnel{ID: "tun-http", LocalAddr: localAddr, Type: proto.TunnelTypeHTTP, client: c}
	c.tunnels.Store("tun-http", tun)

	// Start handling streams
	go c.handleStreams()

	// Open a stream from server side and send STREAM_OPEN
	stream, err := serverMux.OpenStream()
	if err != nil {
		t.Fatalf("OpenStream failed: %v", err)
	}

	openFrame, _ := proto.EncodeJSONPayload(proto.FrameStreamOpen, stream.ID(), &proto.StreamOpen{
		TunnelID: "tun-http", RemoteAddr: "1.2.3.4:5678", Protocol: "http",
	})
	serverMux.GetFrameWriter().Write(openFrame)

	// Wait for the stream to be accepted on the client side
	time.Sleep(100 * time.Millisecond)

	// Write an HTTP request through the stream
	httpReq := "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
	stream.Write([]byte(httpReq))

	// Read the HTTP response from the stream
	reader := bufio.NewReader(stream)
	resp, err := http.ReadResponse(reader, nil)
	if err != nil {
		t.Fatalf("Failed to read response: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "hello from local" {
		t.Errorf("Expected body 'hello from local', got %q", string(body))
	}

	c1.Close()
	c2.Close()
}

func TestHandleStreamTCP(t *testing.T) {
	// Start a local TCP echo server
	echoListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to start echo server: %v", err)
	}
	defer echoListener.Close()

	go func() {
		for {
			conn, err := echoListener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				io.Copy(conn, conn)
			}()
		}
	}()

	c1, c2 := net.Pipe()
	clientMux := mux.New(c1, mux.DefaultConfig())
	serverMux := mux.New(c2, mux.DefaultConfig())
	go clientMux.Run()
	go serverMux.Run()

	cfg := DefaultConfig()
	c := New(cfg, nil)
	c.mux = clientMux
	c.connected.Store(true)

	localAddr := echoListener.Addr().String()
	tun := &Tunnel{ID: "tun-tcp", LocalAddr: localAddr, Type: proto.TunnelTypeTCP, client: c}
	c.tunnels.Store("tun-tcp", tun)

	// Start handling streams
	go c.handleStreams()

	// Open a stream from server side and send STREAM_OPEN
	stream, err := serverMux.OpenStream()
	if err != nil {
		t.Fatalf("OpenStream failed: %v", err)
	}

	openFrame, _ := proto.EncodeJSONPayload(proto.FrameStreamOpen, stream.ID(), &proto.StreamOpen{
		TunnelID: "tun-tcp", RemoteAddr: "1.2.3.4:5678", Protocol: "tcp",
	})
	serverMux.GetFrameWriter().Write(openFrame)

	// Wait for the stream to be accepted
	time.Sleep(100 * time.Millisecond)

	// Write data through the stream
	testData := "hello echo"
	stream.Write([]byte(testData))

	// Read the echoed data
	buf := make([]byte, 256)
	n, err := stream.Read(buf)
	if err != nil {
		t.Fatalf("Failed to read echo: %v", err)
	}
	if string(buf[:n]) != testData {
		t.Errorf("Expected echo %q, got %q", testData, string(buf[:n]))
	}

	c1.Close()
	c2.Close()
}

func TestHandleStreamUnknownProtocol(t *testing.T) {
	c1, c2 := net.Pipe()
	clientMux := mux.New(c1, mux.DefaultConfig())
	serverMux := mux.New(c2, mux.DefaultConfig())
	go clientMux.Run()
	go serverMux.Run()

	cfg := DefaultConfig()
	c := New(cfg, nil)
	c.mux = clientMux
	c.connected.Store(true)

	// Start handling streams
	go c.handleStreams()

	// Open a stream with unknown protocol
	stream, err := serverMux.OpenStream()
	if err != nil {
		t.Fatalf("OpenStream failed: %v", err)
	}

	openFrame, _ := proto.EncodeJSONPayload(proto.FrameStreamOpen, stream.ID(), &proto.StreamOpen{
		TunnelID: "tun-unknown", RemoteAddr: "1.2.3.4:5678", Protocol: "unknown",
	})
	serverMux.GetFrameWriter().Write(openFrame)

	// Wait for the stream to be accepted and handled (reset)
	time.Sleep(100 * time.Millisecond)

	// The stream should have been reset - reading should fail
	buf := make([]byte, 10)
	_, err = stream.Read(buf)
	if err == nil {
		t.Error("Expected error reading from reset stream")
	}

	c1.Close()
	c2.Close()
}

// --- handleHTTPStream edge cases ---

func TestHandleHTTPStreamNoTunnel(t *testing.T) {
	c1, c2 := net.Pipe()
	clientMux := mux.New(c1, mux.DefaultConfig())
	serverMux := mux.New(c2, mux.DefaultConfig())
	go clientMux.Run()
	go serverMux.Run()

	cfg := DefaultConfig()
	c := New(cfg, nil)
	c.mux = clientMux
	c.connected.Store(true)
	// Do NOT store any tunnel

	// Open a stream with a tunnel ID that doesn't exist
	stream, _ := serverMux.OpenStream()
	openFrame, _ := proto.EncodeJSONPayload(proto.FrameStreamOpen, stream.ID(), &proto.StreamOpen{
		TunnelID: "nonexistent", RemoteAddr: "1.2.3.4:5678", Protocol: "http",
	})
	serverMux.GetFrameWriter().Write(openFrame)

	// Accept stream on client side and call handleStream directly
	clientStream, err := clientMux.AcceptStream()
	if err != nil {
		t.Fatalf("AcceptStream failed: %v", err)
	}

	// handleStream should reset the stream because tunnel is not found
	c.handleStream(clientStream)

	// The server-side stream should be reset
	buf := make([]byte, 10)
	_, err = stream.Read(buf)
	if err == nil {
		t.Error("Expected error reading from reset stream")
	}

	c1.Close()
	c2.Close()
}

func TestHandleHTTPStreamBadRequest(t *testing.T) {
	c1, c2 := net.Pipe()
	clientMux := mux.New(c1, mux.DefaultConfig())
	serverMux := mux.New(c2, mux.DefaultConfig())
	go clientMux.Run()
	go serverMux.Run()

	cfg := DefaultConfig()
	c := New(cfg, nil)
	c.mux = clientMux
	c.connected.Store(true)

	tun := &Tunnel{ID: "tun-bad", LocalAddr: "127.0.0.1:1", Type: proto.TunnelTypeHTTP, client: c}
	c.tunnels.Store("tun-bad", tun)

	// Open a stream
	stream, _ := serverMux.OpenStream()
	openFrame, _ := proto.EncodeJSONPayload(proto.FrameStreamOpen, stream.ID(), &proto.StreamOpen{
		TunnelID: "tun-bad", RemoteAddr: "1.2.3.4:5678", Protocol: "http",
	})
	serverMux.GetFrameWriter().Write(openFrame)

	clientStream, err := clientMux.AcceptStream()
	if err != nil {
		t.Fatalf("AcceptStream failed: %v", err)
	}

	// Write invalid HTTP data, then close the stream so ReadRequest fails
	stream.Write([]byte("not a valid http request\r\n\r\n"))
	stream.Close()

	// handleHTTPStream should return without panic (ReadRequest will fail)
	c.handleHTTPStream(clientStream)

	c1.Close()
	c2.Close()
}

func TestHandleHTTPStreamLocalServerDown(t *testing.T) {
	c1, c2 := net.Pipe()
	clientMux := mux.New(c1, mux.DefaultConfig())
	serverMux := mux.New(c2, mux.DefaultConfig())
	go clientMux.Run()
	go serverMux.Run()

	cfg := DefaultConfig()
	c := New(cfg, nil)
	c.mux = clientMux
	c.connected.Store(true)

	// Use an address where nothing is listening
	tun := &Tunnel{ID: "tun-down", LocalAddr: "127.0.0.1:1", Type: proto.TunnelTypeHTTP, client: c}
	c.tunnels.Store("tun-down", tun)

	// Open a stream
	stream, _ := serverMux.OpenStream()
	openFrame, _ := proto.EncodeJSONPayload(proto.FrameStreamOpen, stream.ID(), &proto.StreamOpen{
		TunnelID: "tun-down", RemoteAddr: "1.2.3.4:5678", Protocol: "http",
	})
	serverMux.GetFrameWriter().Write(openFrame)

	clientStream, err := clientMux.AcceptStream()
	if err != nil {
		t.Fatalf("AcceptStream failed: %v", err)
	}

	// Write a valid HTTP request
	httpReq := "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n"
	stream.Write([]byte(httpReq))

	// handleHTTPStream should send 502 response since local server is down
	c.handleHTTPStream(clientStream)

	// Read the 502 response from the server-side stream
	buf := make([]byte, 1024)
	n, _ := stream.Read(buf)
	response := string(buf[:n])
	if !strings.Contains(response, "502 Bad Gateway") {
		t.Errorf("Expected 502 Bad Gateway, got: %s", response)
	}

	c1.Close()
	c2.Close()
}

// --- handleTCPStream edge cases ---

func TestHandleTCPStreamNoTunnel(t *testing.T) {
	c1, c2 := net.Pipe()
	clientMux := mux.New(c1, mux.DefaultConfig())
	serverMux := mux.New(c2, mux.DefaultConfig())
	go clientMux.Run()
	go serverMux.Run()

	cfg := DefaultConfig()
	c := New(cfg, nil)
	c.mux = clientMux
	c.connected.Store(true)

	// Open a stream with nonexistent tunnel
	stream, _ := serverMux.OpenStream()
	openFrame, _ := proto.EncodeJSONPayload(proto.FrameStreamOpen, stream.ID(), &proto.StreamOpen{
		TunnelID: "nonexistent", RemoteAddr: "1.2.3.4:5678", Protocol: "tcp",
	})
	serverMux.GetFrameWriter().Write(openFrame)

	clientStream, err := clientMux.AcceptStream()
	if err != nil {
		t.Fatalf("AcceptStream failed: %v", err)
	}

	// handleTCPStream should reset stream because tunnel not found
	c.handleTCPStream(clientStream)

	// Server-side stream should be reset
	buf := make([]byte, 10)
	_, err = stream.Read(buf)
	if err == nil {
		t.Error("Expected error from reset stream")
	}

	c1.Close()
	c2.Close()
}

func TestHandleTCPStreamDialError(t *testing.T) {
	c1, c2 := net.Pipe()
	clientMux := mux.New(c1, mux.DefaultConfig())
	serverMux := mux.New(c2, mux.DefaultConfig())
	go clientMux.Run()
	go serverMux.Run()

	cfg := DefaultConfig()
	c := New(cfg, nil)
	c.mux = clientMux
	c.connected.Store(true)

	// Use a bad address so net.Dial fails
	tun := &Tunnel{ID: "tun-bad-tcp", LocalAddr: "127.0.0.1:1", Type: proto.TunnelTypeTCP, client: c}
	c.tunnels.Store("tun-bad-tcp", tun)

	stream, _ := serverMux.OpenStream()
	openFrame, _ := proto.EncodeJSONPayload(proto.FrameStreamOpen, stream.ID(), &proto.StreamOpen{
		TunnelID: "tun-bad-tcp", RemoteAddr: "1.2.3.4:5678", Protocol: "tcp",
	})
	serverMux.GetFrameWriter().Write(openFrame)

	clientStream, err := clientMux.AcceptStream()
	if err != nil {
		t.Fatalf("AcceptStream failed: %v", err)
	}

	// handleTCPStream should return without panic (dial will fail)
	c.handleTCPStream(clientStream)

	c1.Close()
	c2.Close()
}

// --- handleStreams exit test ---

func TestHandleStreamsExitOnMuxClose(t *testing.T) {
	c1, c2 := net.Pipe()
	clientMux := mux.New(c1, mux.DefaultConfig())
	go clientMux.Run()

	cfg := DefaultConfig()
	c := New(cfg, nil)
	c.mux = clientMux
	c.connected.Store(true)

	done := make(chan struct{})
	go func() {
		c.handleStreams()
		close(done)
	}()

	// Close the mux to trigger handleStreams exit
	c2.Close()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Error("handleStreams did not exit on mux close")
	}
}

// --- authenticate new select paths ---

func TestAuthenticateMuxDone(t *testing.T) {
	c1, c2 := net.Pipe()

	cfg := Config{HeartbeatInterval: time.Second}
	c := New(cfg, slog.Default())
	c.conn = c1
	c.mux = mux.New(c1, mux.DefaultConfig())
	go c.mux.Run()

	// Server side: use a mux, accept the auth request, then close mux without response
	serverMux := mux.New(c2, mux.DefaultConfig())
	go serverMux.Run()
	go func() {
		// Drain control frame then close server mux.
		select {
		case <-serverMux.ControlFrame():
		case <-serverMux.Done():
		}
		// Close the server-side connection to make client mux.Done() fire
		c2.Close()
	}()

	err := c.authenticate()
	if err == nil {
		t.Fatal("Expected error when mux done fires during authenticate")
	}
	if !strings.Contains(err.Error(), "connection closed") {
		t.Errorf("Expected 'connection closed' error, got: %v", err)
	}
	c1.Close()
}

func TestAuthenticateCtxDone(t *testing.T) {
	c1, c2 := net.Pipe()

	cfg := Config{HeartbeatInterval: time.Second}
	c := New(cfg, slog.Default())
	c.conn = c1
	c.mux = mux.New(c1, mux.DefaultConfig())
	go c.mux.Run()

	// Server side: use a mux but never respond
	serverMux := mux.New(c2, mux.DefaultConfig())
	go serverMux.Run()

	// Drain server control frames so it doesn't block
	go func() {
		for {
			select {
			case <-serverMux.ControlFrame():
			case <-serverMux.Done():
				return
			}
		}
	}()

	// Cancel client context while waiting for auth response
	go func() {
		time.Sleep(50 * time.Millisecond)
		c.cancel()
	}()

	err := c.authenticate()
	if err == nil {
		t.Fatal("Expected error when ctx done fires during authenticate")
	}
	if !strings.Contains(err.Error(), "cancelled") {
		t.Errorf("Expected 'cancelled' error, got: %v", err)
	}
	c1.Close()
	c2.Close()
}

func TestAuthenticateUnexpectedFrameType(t *testing.T) {
	c1, c2 := net.Pipe()

	cfg := Config{HeartbeatInterval: time.Second}
	c := New(cfg, slog.Default())
	c.conn = c1
	c.mux = mux.New(c1, mux.DefaultConfig())
	go c.mux.Run()

	serverMux := mux.New(c2, mux.DefaultConfig())
	go serverMux.Run()
	go func() {
		select {
		case <-serverMux.ControlFrame():
		case <-serverMux.Done():
			return
		}
		// Send a tunnel response frame instead of auth response
		resp := &proto.TunnelResponse{OK: true, TunnelID: "tun-1"}
		respFrame, _ := proto.EncodeJSONPayload(proto.FrameTunnelRes, proto.ControlStreamID, resp)
		serverMux.GetFrameWriter().Write(respFrame)
		<-serverMux.Done()
	}()

	err := c.authenticate()
	if err == nil {
		t.Fatal("Expected error for unexpected frame type")
	}
	if !strings.Contains(err.Error(), "unexpected frame type") {
		t.Errorf("Expected 'unexpected frame type' error, got: %v", err)
	}
	c1.Close()
	c2.Close()
}

// --- openTunnel new select paths ---

func TestOpenTunnelMuxDone(t *testing.T) {
	client, serverMux := makeConnectedClient(t)

	go func() {
		// Read and discard the tunnel request control frame, then close
		select {
		case <-serverMux.ControlFrame():
		case <-serverMux.Done():
		}
		// Close the underlying connection to trigger mux.Done()
		client.conn.Close()
	}()

	req := &proto.TunnelRequest{
		Type:      proto.TunnelTypeHTTP,
		LocalAddr: "localhost:3000",
	}
	_, err := client.openTunnel(req)
	if err == nil {
		t.Fatal("Expected error when mux done fires during openTunnel")
	}
	if !strings.Contains(err.Error(), "connection closed") {
		t.Errorf("Expected 'connection closed' error, got: %v", err)
	}
}

func TestOpenTunnelCtxDone(t *testing.T) {
	client, serverMux := makeConnectedClient(t)

	// Drain server control frames
	go func() {
		for {
			select {
			case <-serverMux.ControlFrame():
			case <-serverMux.Done():
				return
			}
		}
	}()

	// Cancel context while waiting for tunnel response
	go func() {
		time.Sleep(50 * time.Millisecond)
		client.cancel()
	}()

	req := &proto.TunnelRequest{
		Type:      proto.TunnelTypeHTTP,
		LocalAddr: "localhost:3000",
	}
	_, err := client.openTunnel(req)
	if err == nil {
		t.Fatal("Expected error when ctx done fires during openTunnel")
	}
	if !strings.Contains(err.Error(), "cancelled") {
		t.Errorf("Expected 'cancelled' error, got: %v", err)
	}
	client.conn.Close()
}

func TestOpenTunnelUnexpectedFrameType(t *testing.T) {
	client, serverMux := makeConnectedClient(t)

	go func() {
		select {
		case <-serverMux.ControlFrame():
		case <-serverMux.Done():
			return
		}
		// Send an auth response instead of tunnel response
		resp := &proto.AuthResponse{OK: true, SessionID: "sess-1"}
		respFrame, _ := proto.EncodeJSONPayload(proto.FrameAuthRes, proto.ControlStreamID, resp)
		serverMux.GetFrameWriter().Write(respFrame)
		<-serverMux.Done()
	}()

	req := &proto.TunnelRequest{
		Type:      proto.TunnelTypeHTTP,
		LocalAddr: "localhost:3000",
	}
	_, err := client.openTunnel(req)
	if err == nil {
		t.Fatal("Expected error for unexpected frame type")
	}
	if !strings.Contains(err.Error(), "unexpected frame type") {
		t.Errorf("Expected 'unexpected frame type' error, got: %v", err)
	}
	client.conn.Close()
}

// Suppress unused import warnings - ensure all imports are used
var _ = fmt.Sprintf
var _ = bufio.NewReader
var _ = httptest.NewServer
var _ = strings.Contains
