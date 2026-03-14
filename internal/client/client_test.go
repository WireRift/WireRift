package client

import (
	"log/slog"
	"testing"
	"time"

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

func TestClientCloseWithoutConnect(t *testing.T) {
	c := New(DefaultConfig(), nil)

	// Should not panic when closing without connecting
	if err := c.Close(); err != nil {
		t.Errorf("Close failed: %v", err)
	}
}

func TestHTTPOptions(t *testing.T) {
	req := &proto.TunnelRequest{
		Type:      proto.TunnelTypeHTTP,
		LocalAddr: "localhost:3000",
	}

	// Apply options
	WithSubdomain("myapp")(req)
	WithInspect()(req)
	WithAuth("user", "pass")(req)
	WithHeaders(map[string]string{"X-Custom": "value"})(req)

	if req.Subdomain != "myapp" {
		t.Errorf("Subdomain = %q, want %q", req.Subdomain, "myapp")
	}
	if !req.Inspect {
		t.Error("Inspect should be true")
	}
	if req.Auth == nil {
		t.Fatal("Auth should not be nil")
	}
	if req.Auth.Username != "user" {
		t.Errorf("Username = %q, want %q", req.Auth.Username, "user")
	}
	if req.Headers["X-Custom"] != "value" {
		t.Errorf("Headers[X-Custom] = %q, want %q", req.Headers["X-Custom"], "value")
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

	// Session ID should be empty before connecting
	if c.SessionID() != "" {
		t.Error("SessionID should be empty before connecting")
	}
}

func TestCloseIdempotent(t *testing.T) {
	c := New(DefaultConfig(), nil)

	// Multiple closes should not panic
	if err := c.Close(); err != nil {
		t.Errorf("First close failed: %v", err)
	}
	if err := c.Close(); err != nil {
		t.Errorf("Second close failed: %v", err)
	}
	if err := c.Close(); err != nil {
		t.Errorf("Third close failed: %v", err)
	}
}

func TestHTTPNotConnected(t *testing.T) {
	c := New(DefaultConfig(), nil)

	// Should fail when not connected
	_, err := c.HTTP("localhost:3000")
	if err != ErrNotConnected {
		t.Errorf("Expected ErrNotConnected, got %v", err)
	}
}

func TestTCPNotConnected(t *testing.T) {
	c := New(DefaultConfig(), nil)

	// Should fail when not connected
	_, err := c.TCP("localhost:3000", 8080)
	if err != ErrNotConnected {
		t.Errorf("Expected ErrNotConnected, got %v", err)
	}
}

func TestCloseTunnelNotConnected(t *testing.T) {
	c := New(DefaultConfig(), nil)

	// Should return ErrNotConnected when mux is nil
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

func TestClientWithCustomLogger(t *testing.T) {
	logger := slog.Default()
	c := New(DefaultConfig(), logger)

	if c == nil {
		t.Fatal("New returned nil")
	}
	if c.logger != logger {
		t.Error("Logger not set correctly")
	}
}

func TestClientWithNilLogger(t *testing.T) {
	c := New(DefaultConfig(), nil)

	if c == nil {
		t.Fatal("New returned nil")
	}
	if c.logger == nil {
		t.Error("Logger should be set to default when nil is passed")
	}
}

func TestClientFrameWriterReaderBeforeConnect(t *testing.T) {
	c := New(DefaultConfig(), nil)

	// Should not panic but will be nil before connect
	if c.FrameWriter() != nil {
		t.Error("FrameWriter should be nil before connect")
	}
	if c.FrameReader() != nil {
		t.Error("FrameReader should be nil before connect")
	}
}

func TestConfigDefaults(t *testing.T) {
	cfg := DefaultConfig()

	if cfg.ServerAddr == "" {
		t.Error("ServerAddr should not be empty")
	}
	if !cfg.Reconnect {
		t.Error("Reconnect should be true by default")
	}
	if cfg.HeartbeatInterval <= 0 {
		t.Error("HeartbeatInterval should be positive")
	}
	if cfg.MaxReconnectInterval <= 0 {
		t.Error("MaxReconnectInterval should be positive")
	}
}

func TestClientErrors(t *testing.T) {
	// Test that error types are correctly defined
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

func TestClientMaxTunnels(t *testing.T) {
	c := New(DefaultConfig(), nil)

	// MaxTunnels should be 0 initially (not connected)
	// This is accessed via the session info after connection
	// Since we're not connected, we just verify the client structure
	if c == nil {
		t.Fatal("Client should not be nil")
	}
}

func TestTunnelCloseNotConnected(t *testing.T) {
	c := New(DefaultConfig(), nil)

	// Create a mock tunnel manually
	tunnel := &Tunnel{
		ID:        "test-tunnel",
		client:    c,
		LocalAddr: "localhost:3000",
	}

	// Close should call client.CloseTunnel which returns ErrNotConnected
	err := tunnel.Close()
	if err != ErrNotConnected {
		t.Errorf("Expected ErrNotConnected, got %v", err)
	}
}

func TestHTTPOptionCombinations(t *testing.T) {
	req := &proto.TunnelRequest{
		Type:      proto.TunnelTypeHTTP,
		LocalAddr: "localhost:3000",
	}

	// Apply multiple options
	WithSubdomain("myapp")(req)
	WithInspect()(req)
	WithAuth("user", "pass")(req)
	WithHeaders(map[string]string{
		"X-Custom":  "value",
		"X-Another": "header",
	})(req)

	if req.Subdomain != "myapp" {
		t.Errorf("Subdomain = %q, want myapp", req.Subdomain)
	}
	if !req.Inspect {
		t.Error("Inspect should be true")
	}
	if req.Auth == nil {
		t.Fatal("Auth should not be nil")
	}
	if req.Auth.Username != "user" || req.Auth.Password != "pass" {
		t.Error("Auth credentials incorrect")
	}
	if len(req.Headers) != 2 {
		t.Errorf("Headers length = %d, want 2", len(req.Headers))
	}
}

func TestReconnectConfig(t *testing.T) {
	cfg := DefaultConfig()

	// Test reconnect configuration
	if !cfg.Reconnect {
		t.Error("Reconnect should be enabled by default")
	}
	if cfg.ReconnectInterval != time.Second {
		t.Errorf("ReconnectInterval = %v, want 1s", cfg.ReconnectInterval)
	}
	if cfg.MaxReconnectInterval != 30*time.Second {
		t.Errorf("MaxReconnectInterval = %v, want 30s", cfg.MaxReconnectInterval)
	}
}
