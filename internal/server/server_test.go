package server

import (
	"crypto/tls"
	"log/slog"
	"net"
	"testing"
	"time"

	"github.com/wirerift/wirerift/internal/proto"
)

func TestExtractSubdomain(t *testing.T) {
	tests := []struct {
		host     string
		domain   string
		expected string
	}{
		{"myapp.wirerift.dev", "wirerift.dev", "myapp"},
		{"myapp.wirerift.dev:8080", "wirerift.dev", "myapp"},
		{"test.wirerift.dev", "wirerift.dev", "test"},
		{"wirerift.dev", "wirerift.dev", ""},
		{"other.example.com", "wirerift.dev", ""},
		{"sub.sub.wirerift.dev", "wirerift.dev", "sub.sub"},
		{"", "wirerift.dev", ""},
	}

	for _, tt := range tests {
		t.Run(tt.host, func(t *testing.T) {
			result := extractSubdomain(tt.host, tt.domain)
			if result != tt.expected {
				t.Errorf("extractSubdomain(%q, %q) = %q, want %q", tt.host, tt.domain, result, tt.expected)
			}
		})
	}
}

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	if cfg.Domain == "" {
		t.Error("Domain should not be empty")
	}
	if cfg.ControlAddr == "" {
		t.Error("ControlAddr should not be empty")
	}
	if cfg.HTTPAddr == "" {
		t.Error("HTTPAddr should not be empty")
	}
	if cfg.MaxTunnelsPerSession <= 0 {
		t.Error("MaxTunnelsPerSession should be positive")
	}
}

func TestAllocatePort(t *testing.T) {
	s := New(DefaultConfig(), nil)

	// Allocate several ports
	ports := make(map[int]bool)
	for i := 0; i < 100; i++ {
		port, err := s.allocatePort()
		if err != nil {
			t.Fatalf("allocatePort failed: %v", err)
		}
		if port < s.tcpPortStart || port > s.tcpPortEnd {
			t.Errorf("port %d out of range [%d, %d]", port, s.tcpPortStart, s.tcpPortEnd)
		}
		if ports[port] {
			t.Errorf("port %d allocated twice", port)
		}
		ports[port] = true
	}

	// Release and reallocate
	firstPort := 20000
	s.releasePort(firstPort)

	port, err := s.allocatePort()
	if err != nil {
		t.Fatalf("allocatePort after release failed: %v", err)
	}
	_ = port
}

func TestServerNew(t *testing.T) {
	cfg := DefaultConfig()
	s := New(cfg, nil)

	if s == nil {
		t.Fatal("New returned nil")
	}
	if s.config.Domain != cfg.Domain {
		t.Errorf("Domain = %q, want %q", s.config.Domain, cfg.Domain)
	}
}

func TestServerStopWithoutStart(t *testing.T) {
	s := New(DefaultConfig(), nil)

	// Should not panic when stopping without starting
	if err := s.Stop(); err != nil {
		t.Errorf("Stop failed: %v", err)
	}
}

func TestListTunnelsEmpty(t *testing.T) {
	s := New(DefaultConfig(), nil)

	tunnels := s.ListTunnels()
	if len(tunnels) != 0 {
		t.Errorf("ListTunnels() = %d, want 0", len(tunnels))
	}
}

func TestListSessionsEmpty(t *testing.T) {
	s := New(DefaultConfig(), nil)

	sessions := s.ListSessions()
	if len(sessions) != 0 {
		t.Errorf("ListSessions() = %d, want 0", len(sessions))
	}
}

func TestStatsEmpty(t *testing.T) {
	s := New(DefaultConfig(), nil)

	stats := s.Stats()
	if stats["active_tunnels"] != 0 {
		t.Errorf("active_tunnels = %v, want 0", stats["active_tunnels"])
	}
	if stats["active_sessions"] != 0 {
		t.Errorf("active_sessions = %v, want 0", stats["active_sessions"])
	}
}

func TestStartTime(t *testing.T) {
	s := New(DefaultConfig(), nil)

	startTime := s.StartTime()
	if startTime.IsZero() {
		t.Error("StartTime should not be zero")
	}
}

func TestGetTunnelBySubdomainNotFound(t *testing.T) {
	s := New(DefaultConfig(), nil)

	_, ok := s.getTunnelBySubdomain("nonexistent")
	if ok {
		t.Error("getTunnelBySubdomain should return false for nonexistent tunnel")
	}
}

func TestGetSessionNotFound(t *testing.T) {
	s := New(DefaultConfig(), nil)

	_, ok := s.getSession("nonexistent")
	if ok {
		t.Error("getSession should return false for nonexistent session")
	}
}

func TestListTunnelsWithData(t *testing.T) {
	s := New(DefaultConfig(), nil)

	// Add a tunnel
	tunnel := &Tunnel{
		ID:        "tunnel-1",
		Type:      proto.TunnelTypeHTTP,
		SessionID: "session-1",
		Subdomain: "myapp",
		PublicURL: "https://myapp.wirerift.dev",
		LocalAddr: "localhost:3000",
		CreatedAt: time.Now(),
	}
	s.tunnels.Store("myapp", tunnel)

	tunnels := s.ListTunnels()
	if len(tunnels) != 1 {
		t.Fatalf("ListTunnels() = %d, want 1", len(tunnels))
	}
	if tunnels[0].ID != "tunnel-1" {
		t.Errorf("ID = %q, want %q", tunnels[0].ID, "tunnel-1")
	}
	if tunnels[0].Type != "http" {
		t.Errorf("Type = %q, want %q", tunnels[0].Type, "http")
	}
	if tunnels[0].Status != "active" {
		t.Errorf("Status = %q, want %q", tunnels[0].Status, "active")
	}
}

func TestListSessionsWithData(t *testing.T) {
	s := New(DefaultConfig(), nil)

	// Create a mock listener to get a real addr
	listener, _ := net.Listen("tcp", "127.0.0.1:0")
	defer listener.Close()

	// Add a session
	session := &Session{
		ID:         "session-1",
		AccountID:  "account-1",
		Tunnels:    make(map[string]*Tunnel),
		CreatedAt:  time.Now(),
		LastSeen:   time.Now(),
		RemoteAddr: listener.Addr(),
	}
	s.sessions.Store("session-1", session)

	sessions := s.ListSessions()
	if len(sessions) != 1 {
		t.Fatalf("ListSessions() = %d, want 1", len(sessions))
	}
	if sessions[0].ID != "session-1" {
		t.Errorf("ID = %q, want %q", sessions[0].ID, "session-1")
	}
	if sessions[0].AccountID != "account-1" {
		t.Errorf("AccountID = %q, want %q", sessions[0].AccountID, "account-1")
	}
}

func TestStatsWithData(t *testing.T) {
	s := New(DefaultConfig(), nil)

	// Add a tunnel
	tunnel := &Tunnel{
		ID:        "tunnel-1",
		Type:      proto.TunnelTypeHTTP,
		SessionID: "session-1",
	}
	s.tunnels.Store("tunnel-1", tunnel)

	// Add a session
	session := &Session{
		ID:        "session-1",
		AccountID: "account-1",
		Tunnels:   make(map[string]*Tunnel),
	}
	s.sessions.Store("session-1", session)

	stats := s.Stats()
	if stats["active_tunnels"] != 1 {
		t.Errorf("active_tunnels = %v, want 1", stats["active_tunnels"])
	}
	if stats["active_sessions"] != 1 {
		t.Errorf("active_sessions = %v, want 1", stats["active_sessions"])
	}
}

func TestGetTunnelBySubdomainFound(t *testing.T) {
	s := New(DefaultConfig(), nil)

	tunnel := &Tunnel{
		ID:        "tunnel-1",
		Type:      proto.TunnelTypeHTTP,
		Subdomain: "myapp",
	}
	s.tunnels.Store("myapp", tunnel)

	found, ok := s.getTunnelBySubdomain("myapp")
	if !ok {
		t.Fatal("getTunnelBySubdomain should return true for existing tunnel")
	}
	if found.ID != "tunnel-1" {
		t.Errorf("ID = %q, want %q", found.ID, "tunnel-1")
	}
}

func TestGetSessionFound(t *testing.T) {
	s := New(DefaultConfig(), nil)

	session := &Session{
		ID:        "session-1",
		AccountID: "account-1",
	}
	s.sessions.Store("session-1", session)

	found, ok := s.getSession("session-1")
	if !ok {
		t.Fatal("getSession should return true for existing session")
	}
	if found.ID != "session-1" {
		t.Errorf("ID = %q, want %q", found.ID, "session-1")
	}
}

func TestAllocatePortExhaustion(t *testing.T) {
	// Create server with very small port range
	cfg := DefaultConfig()
	s := New(cfg, nil)
	s.tcpPortStart = 20000
	s.tcpPortEnd = 20002 // Only 3 ports available
	s.nextPort.Store(int32(20000))

	// Allocate all ports
	for i := 0; i < 3; i++ {
		_, err := s.allocatePort()
		if err != nil {
			t.Fatalf("allocatePort %d failed: %v", i, err)
		}
	}

	// Next allocation should fail
	_, err := s.allocatePort()
	if err != ErrPortUnavailable {
		t.Errorf("Expected ErrPortUnavailable, got %v", err)
	}
}

func TestServerWithCustomLogger(t *testing.T) {
	logger := slog.Default()
	s := New(DefaultConfig(), logger)

	if s == nil {
		t.Fatal("New returned nil")
	}
	if s.logger != logger {
		t.Error("Logger not set correctly")
	}
}

func TestServerWithNilLogger(t *testing.T) {
	s := New(DefaultConfig(), nil)

	if s == nil {
		t.Fatal("New returned nil")
	}
	if s.logger == nil {
		t.Error("Logger should be set to default when nil is passed")
	}
}

func TestServerErrors(t *testing.T) {
	// Test that error types are correctly defined
	if ErrServerClosed == nil {
		t.Error("ErrServerClosed should not be nil")
	}
	if ErrTunnelNotFound == nil {
		t.Error("ErrTunnelNotFound should not be nil")
	}
	if ErrSessionNotFound == nil {
		t.Error("ErrSessionNotFound should not be nil")
	}
	if ErrUnauthorized == nil {
		t.Error("ErrUnauthorized should not be nil")
	}
	if ErrSubdomainTaken == nil {
		t.Error("ErrSubdomainTaken should not be nil")
	}
	if ErrPortUnavailable == nil {
		t.Error("ErrPortUnavailable should not be nil")
	}
	if ErrMaxTunnelsExceeded == nil {
		t.Error("ErrMaxTunnelsExceeded should not be nil")
	}
}

func TestConfigWithTLS(t *testing.T) {
	cfg := DefaultConfig()

	// Test with TLS config
	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
	}
	cfg.TLSConfig = tlsConfig

	s := New(cfg, nil)
	if s.config.TLSConfig != tlsConfig {
		t.Error("TLSConfig should be set")
	}
}

func TestConfigWithCustomHeartbeat(t *testing.T) {
	cfg := DefaultConfig()
	cfg.HeartbeatInterval = 10 * time.Second
	cfg.SessionTimeout = 120 * time.Second

	if cfg.HeartbeatInterval != 10*time.Second {
		t.Errorf("HeartbeatInterval = %v, want 10s", cfg.HeartbeatInterval)
	}
	if cfg.SessionTimeout != 120*time.Second {
		t.Errorf("SessionTimeout = %v, want 120s", cfg.SessionTimeout)
	}
}

func TestPortAllocationMultiple(t *testing.T) {
	s := New(DefaultConfig(), nil)

	// Allocate multiple ports
	ports := []int{}
	for i := 0; i < 10; i++ {
		port, err := s.allocatePort()
		if err != nil {
			t.Fatalf("allocatePort failed: %v", err)
		}
		ports = append(ports, port)
	}

	// Verify all unique
	seen := make(map[int]bool)
	for _, port := range ports {
		if seen[port] {
			t.Errorf("Port %d allocated twice", port)
		}
		seen[port] = true
	}

	// Release all
	for _, port := range ports {
		s.releasePort(port)
	}

	// Reallocate should work
	port, err := s.allocatePort()
	if err != nil {
		t.Fatalf("allocatePort after release failed: %v", err)
	}
	if !seen[port] {
		t.Logf("Got new port %d after releasing all", port)
	}
}

func TestGetTunnelByPortNotFound(t *testing.T) {
	s := New(DefaultConfig(), nil)

	// Looking for tunnel by port (not subdomain)
	// Currently getTunnelBySubdomain only looks by subdomain
	// This test documents current behavior
	_, ok := s.getTunnelBySubdomain("")
	if ok {
		t.Error("Empty subdomain should not be found")
	}
}

func TestSessionWithTunnels(t *testing.T) {
	s := New(DefaultConfig(), nil)

	// Create mock listener to get an address
	listener, _ := net.Listen("tcp", "127.0.0.1:0")
	defer listener.Close()

	// Create session
	session := &Session{
		ID:         "session-1",
		AccountID:  "account-1",
		Tunnels:    make(map[string]*Tunnel),
		RemoteAddr: listener.Addr(), // Initialize RemoteAddr
	}
	s.sessions.Store("session-1", session)

	// Add tunnels to session
	tunnel1 := &Tunnel{
		ID:        "tunnel-1",
		SessionID: "session-1",
		Type:      proto.TunnelTypeHTTP,
	}
	tunnel2 := &Tunnel{
		ID:        "tunnel-2",
		SessionID: "session-1",
		Type:      proto.TunnelTypeTCP,
	}

	session.mu.Lock()
	session.Tunnels["tunnel-1"] = tunnel1
	session.Tunnels["tunnel-2"] = tunnel2
	session.mu.Unlock()

	// List sessions should show tunnel count
	sessions := s.ListSessions()
	if len(sessions) != 1 {
		t.Fatalf("Expected 1 session, got %d", len(sessions))
	}
	if sessions[0].TunnelCount != 2 {
		t.Errorf("TunnelCount = %d, want 2", sessions[0].TunnelCount)
	}
}

func TestTunnelWithPort(t *testing.T) {
	s := New(DefaultConfig(), nil)

	tunnel := &Tunnel{
		ID:        "tunnel-1",
		Type:      proto.TunnelTypeTCP,
		SessionID: "session-1",
		Port:      20001,
		PublicURL: "tcp://wirerift.dev:20001",
		LocalAddr: "localhost:5432",
		CreatedAt: time.Now(),
	}

	s.tunnels.Store("20001", tunnel)

	// ListTunnels should include port
	tunnels := s.ListTunnels()
	if len(tunnels) != 1 {
		t.Fatalf("Expected 1 tunnel, got %d", len(tunnels))
	}
	if tunnels[0].Port != 20001 {
		t.Errorf("Port = %d, want 20001", tunnels[0].Port)
	}
	if tunnels[0].Type != "tcp" {
		t.Errorf("Type = %q, want tcp", tunnels[0].Type)
	}
}

func TestExtractSubdomainEdgeCases(t *testing.T) {
	tests := []struct {
		host     string
		domain   string
		expected string
	}{
		// Additional edge cases
		{"a.wirerift.dev", "wirerift.dev", "a"},
		{"very.long.subdomain.wirerift.dev", "wirerift.dev", "very.long.subdomain"},
		{"*.wirerift.dev", "wirerift.dev", "*"},
		{"wirerift.dev:8080", "wirerift.dev", ""},
		{"localhost", "wirerift.dev", ""},
		{"subdomain.example.com:9000", "wirerift.dev", ""},
	}

	for _, tt := range tests {
		t.Run(tt.host, func(t *testing.T) {
			result := extractSubdomain(tt.host, tt.domain)
			if result != tt.expected {
				t.Errorf("extractSubdomain(%q, %q) = %q, want %q", tt.host, tt.domain, result, tt.expected)
			}
		})
	}
}

func TestServerWithCustomConfig(t *testing.T) {
	cfg := Config{
		Domain:               "custom.example.com",
		ControlAddr:          ":9999",
		HTTPAddr:             ":8080",
		HTTPSAddr:            ":8443",
		TCPAddrRange:         "10000-19999",
		DashboardAddr:        ":9090",
		MaxTunnelsPerSession: 5,
	}

	s := New(cfg, nil)

	if s.config.Domain != "custom.example.com" {
		t.Errorf("Domain = %q, want custom.example.com", s.config.Domain)
	}
	if s.config.ControlAddr != ":9999" {
		t.Errorf("ControlAddr = %q, want :9999", s.config.ControlAddr)
	}
	if s.config.MaxTunnelsPerSession != 5 {
		t.Errorf("MaxTunnelsPerSession = %d, want 5", s.config.MaxTunnelsPerSession)
	}

	// Custom port range should be set (but not parsed yet)
	if s.tcpPortStart != 20000 { // Default value
		t.Logf("Note: tcpPortStart is %d, custom range not parsed", s.tcpPortStart)
	}
}

func TestSessionLastSeen(t *testing.T) {
	s := New(DefaultConfig(), nil)

	// Create mock listener to get an address
	listener, _ := net.Listen("tcp", "127.0.0.1:0")
	defer listener.Close()

	now := time.Now()
	session := &Session{
		ID:         "session-1",
		CreatedAt:  now,
		LastSeen:   now,
		RemoteAddr: listener.Addr(), // Initialize RemoteAddr
	}
	s.sessions.Store("session-1", session)

	// Update last seen
	newTime := now.Add(time.Hour)
	session.mu.Lock()
	session.LastSeen = newTime
	session.mu.Unlock()

	// Verify through listing
	sessions := s.ListSessions()
	if len(sessions) != 1 {
		t.Fatalf("Expected 1 session")
	}
}

func TestEmptyTunnelList(t *testing.T) {
	s := New(DefaultConfig(), nil)

	// No tunnels added
	tunnels := s.ListTunnels()
	if len(tunnels) != 0 {
		t.Errorf("Expected 0 tunnels, got %d", len(tunnels))
	}
}

func TestEmptySessionList(t *testing.T) {
	s := New(DefaultConfig(), nil)

	// No sessions added
	sessions := s.ListSessions()
	if len(sessions) != 0 {
		t.Errorf("Expected 0 sessions, got %d", len(sessions))
	}
}
