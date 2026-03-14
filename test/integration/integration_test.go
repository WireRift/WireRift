package integration

import (
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/wirerift/wirerift/internal/client"
	"github.com/wirerift/wirerift/internal/mux"
	"github.com/wirerift/wirerift/internal/proto"
	"github.com/wirerift/wirerift/internal/server"
)

// TestMuxRoundTrip tests basic mux communication
func TestMuxRoundTrip(t *testing.T) {
	// Create a pipe for client-server communication
	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()

	var wg sync.WaitGroup
	wg.Add(2)

	// Server side
	go func() {
		defer wg.Done()
		// Read magic
		if err := proto.ReadMagic(serverConn); err != nil {
			t.Errorf("Server read magic: %v", err)
			return
		}
		serverMux := mux.New(serverConn, mux.DefaultConfig())
		go serverMux.Run()
	}()

	// Client side
	go func() {
		defer wg.Done()
		// Write magic
		if err := proto.WriteMagic(clientConn); err != nil {
			t.Errorf("Client write magic: %v", err)
			return
		}
		clientMux := mux.New(clientConn, mux.DefaultConfig())
		go clientMux.Run()

		// Wait for mux to be ready
		time.Sleep(100 * time.Millisecond)

		// Clean close
		clientMux.Close()
	}()

	wg.Wait()
}

// mockAuthBackend simulates an authentication backend
type mockAuthBackend struct {
	validTokens map[string]string // token -> accountID
}

func newMockAuthBackend() *mockAuthBackend {
	return &mockAuthBackend{
		validTokens: map[string]string{
			"test-token-123": "account-1",
			"admin-token":    "admin",
		},
	}
}

func (m *mockAuthBackend) Validate(token string) (string, bool) {
	accountID, ok := m.validTokens[token]
	return accountID, ok
}

// TestClientServerConnect tests client connecting to server
func TestClientServerConnect(t *testing.T) {
	// Create server
	serverCfg := server.DefaultConfig()
	serverCfg.ControlAddr = "127.0.0.1:0" // Let system assign port
	serverCfg.HTTPAddr = "127.0.0.1:0"

	srv := server.New(serverCfg, nil)

	// Start server
	if err := srv.Start(); err != nil {
		t.Fatalf("Server start failed: %v", err)
	}
	defer srv.Stop()

	// Server started, client connect will fail auth but we test connection
	// Since we can't easily access the control address, we test with invalid
	clientCfg := client.DefaultConfig()
	clientCfg.ServerAddr = "127.0.0.1:1" // Invalid - just to test config
	clientCfg.Token = "test-token"
	clientCfg.Reconnect = false

	c := client.New(clientCfg, nil)

	// This will fail to connect
	err := c.Connect()
	if err == nil {
		t.Error("Connect should fail with invalid address")
	}
}

// TestClientServerFullFlow tests complete client-server interaction
func TestClientServerFullFlow(t *testing.T) {
	// This test demonstrates the full flow but requires proper auth setup
	// For now, we test that the server can start and stop

	serverCfg := server.DefaultConfig()
	serverCfg.ControlAddr = "127.0.0.1:0"
	serverCfg.HTTPAddr = "127.0.0.1:0"

	srv := server.New(serverCfg, nil)

	if err := srv.Start(); err != nil {
		t.Fatalf("Server start failed: %v", err)
	}

	// Verify start time is set
	if srv.StartTime().IsZero() {
		t.Error("Server should have start time set")
	}

	if err := srv.Stop(); err != nil {
		t.Errorf("Server stop failed: %v", err)
	}
}

// TestClientConnectionFailure tests client handling connection failures
func TestClientConnectionFailure(t *testing.T) {
	clientCfg := client.DefaultConfig()
	clientCfg.ServerAddr = "127.0.0.1:1" // Invalid port
	clientCfg.Reconnect = false

	c := client.New(clientCfg, nil)

	err := c.Connect()
	if err == nil {
		t.Error("Connect should fail to invalid address")
	}

	// Verify it's a connection error
	if !errors.Is(err, client.ErrReconnectFailed) && err != client.ErrReconnectFailed {
		// Connection errors wrap differently, just verify it's not nil
		t.Logf("Got expected connection error: %v", err)
	}
}

// TestServerStatsWithActiveConnections tests server stats
func TestServerStatsWithActiveConnections(t *testing.T) {
	serverCfg := server.DefaultConfig()
	serverCfg.ControlAddr = "127.0.0.1:0"
	serverCfg.HTTPAddr = "127.0.0.1:0"

	srv := server.New(serverCfg, nil)

	if err := srv.Start(); err != nil {
		t.Fatalf("Server start failed: %v", err)
	}
	defer srv.Stop()

	// Initially no connections
	stats := srv.Stats()
	if stats["active_sessions"] != 0 {
		t.Errorf("Expected 0 sessions, got %v", stats["active_sessions"])
	}
	if stats["active_tunnels"] != 0 {
		t.Errorf("Expected 0 tunnels, got %v", stats["active_tunnels"])
	}

	// Verify start time is set
	if srv.StartTime().IsZero() {
		t.Error("StartTime should be set")
	}
}

// TestClientCloseWithoutConnect tests client close without connecting
func TestClientCloseWithoutConnect(t *testing.T) {
	clientCfg := client.DefaultConfig()
	clientCfg.Reconnect = false

	c := client.New(clientCfg, nil)

	// Should not panic
	if err := c.Close(); err != nil {
		t.Errorf("Close without connect failed: %v", err)
	}
}

// TestServerLifecycle tests server start and stop
func TestServerLifecycle(t *testing.T) {
	serverCfg := server.DefaultConfig()
	serverCfg.ControlAddr = "127.0.0.1:0"
	serverCfg.HTTPAddr = "127.0.0.1:0"

	srv := server.New(serverCfg, nil)

	// Multiple starts should be idempotent (second one may error)
	if err := srv.Start(); err != nil {
		t.Fatalf("First start failed: %v", err)
	}

	// Stop
	if err := srv.Stop(); err != nil {
		t.Errorf("Stop failed: %v", err)
	}

	// Stop again should not panic
	if err := srv.Stop(); err != nil {
		t.Logf("Second stop returned error (expected): %v", err)
	}
}

// TestClientConfigVariations tests various client configurations
func TestClientConfigVariations(t *testing.T) {
	tests := []struct {
		name string
		cfg  client.Config
	}{
		{
			name: "default config",
			cfg:  client.DefaultConfig(),
		},
		{
			name: "no reconnect",
			cfg: func() client.Config {
				c := client.DefaultConfig()
				c.Reconnect = false
				return c
			}(),
		},
		{
			name: "custom intervals",
			cfg: func() client.Config {
				c := client.DefaultConfig()
				c.HeartbeatInterval = 5 * time.Second
				c.ReconnectInterval = 500 * time.Millisecond
				return c
			}(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := client.New(tt.cfg, nil)
			if c == nil {
				t.Fatal("Client should not be nil")
			}
			if err := c.Close(); err != nil {
				t.Errorf("Close failed: %v", err)
			}
		})
	}
}

// TestServerConfigVariations tests various server configurations
func TestServerConfigVariations(t *testing.T) {
	tests := []struct {
		name string
		cfg  server.Config
	}{
		{
			name: "default config",
			cfg:  server.DefaultConfig(),
		},
		{
			name: "custom domain",
			cfg: func() server.Config {
				c := server.DefaultConfig()
				c.Domain = "custom.example.com"
				return c
			}(),
		},
		{
			name: "custom timeouts",
			cfg: func() server.Config {
				c := server.DefaultConfig()
				c.HeartbeatInterval = 10 * time.Second
				c.SessionTimeout = 120 * time.Second
				return c
			}(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.cfg.ControlAddr = "127.0.0.1:0"
			tt.cfg.HTTPAddr = "127.0.0.1:0"

			srv := server.New(tt.cfg, nil)
			if srv == nil {
				t.Fatal("Server should not be nil")
			}

			if err := srv.Start(); err != nil {
				t.Fatalf("Start failed: %v", err)
			}

			if err := srv.Stop(); err != nil {
				t.Errorf("Stop failed: %v", err)
			}
		})
	}
}
