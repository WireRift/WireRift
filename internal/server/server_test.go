package server

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

	"github.com/wirerift/wirerift/internal/auth"
	"github.com/wirerift/wirerift/internal/mux"
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

// TestHandleControlConnection tests handleControlConnection with valid auth
func TestHandleControlConnection(t *testing.T) {
	authMgr := auth.NewManager()
	cfg := DefaultConfig()
	cfg.AuthManager = authMgr
	s := New(cfg, nil)

	serverConn, clientConn := net.Pipe()
	defer clientConn.Close()

	done := make(chan struct{})
	go func() {
		s.handleControlConnection(serverConn)
		close(done)
	}()

	// Write magic
	proto.WriteMagic(clientConn)

	// Send auth request with valid token
	authReq := &proto.AuthRequest{Token: authMgr.DevToken(), Version: "1.0.0"}
	frame, _ := proto.EncodeJSONPayload(proto.FrameAuthReq, 0, authReq)

	fw := proto.NewFrameWriter(clientConn)
	fr := proto.NewFrameReader(clientConn)
	fw.Write(frame)

	// Read auth response
	respFrame, err := fr.Read()
	if err != nil {
		t.Fatalf("Failed to read auth response: %v", err)
	}
	if respFrame.Type != proto.FrameAuthRes {
		t.Fatalf("Expected AUTH_RES, got %v", respFrame.Type)
	}

	var authRes proto.AuthResponse
	proto.DecodeJSONPayload(respFrame, &authRes)
	if !authRes.OK {
		t.Fatalf("Auth should succeed, got error: %s", authRes.Error)
	}
	if authRes.SessionID == "" {
		t.Error("SessionID should not be empty")
	}

	// Close client to end session
	clientConn.Close()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Error("handleControlConnection did not exit")
	}
}

// TestHandleControlConnectionInvalidMagic tests handleControlConnection with invalid magic
func TestHandleControlConnectionInvalidMagic(t *testing.T) {
	s := New(DefaultConfig(), nil)

	// Create a pipe
	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()

	// Start handleControlConnection in a goroutine
	go s.handleControlConnection(serverConn)

	// Write invalid data (not magic)
	// Write may fail if server closes connection first, which is expected
	_, _ = clientConn.Write([]byte("invalid data"))

	// Give it time to process
	time.Sleep(100 * time.Millisecond)

	// Connection should be closed due to invalid magic - test passes if we get here
}

// TestHandleHTTPRequestInvalidHost tests handleHTTPRequest with invalid host
func TestHandleHTTPRequestInvalidHost(t *testing.T) {
	s := New(DefaultConfig(), nil)

	// Create HTTP request with invalid host (not matching domain)
	req, _ := http.NewRequest("GET", "/", nil)
	req.Host = "invalid.example.com"

	rr := httptest.NewRecorder()
	s.handleHTTPRequest(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400, got %d", rr.Code)
	}
	if body := rr.Body.String(); !strings.Contains(body, "Invalid host") {
		t.Errorf("Expected 'Invalid host' in body, got: %s", body)
	}
}

// TestHandleHTTPRequestTunnelNotFound tests handleHTTPRequest when tunnel not found
func TestHandleHTTPRequestTunnelNotFound(t *testing.T) {
	s := New(DefaultConfig(), nil)

	// Create HTTP request with valid domain but no tunnel
	req, _ := http.NewRequest("GET", "/", nil)
	req.Host = "nonexistent.wirerift.dev"

	rr := httptest.NewRecorder()
	s.handleHTTPRequest(rr, req)

	if rr.Code != http.StatusBadGateway {
		t.Errorf("Expected status 502, got %d", rr.Code)
	}
	if body := rr.Body.String(); !strings.Contains(body, "Tunnel not found") {
		t.Errorf("Expected 'Tunnel not found' in body, got: %s", body)
	}
}

// TestHandleHTTPRequestSessionNotFound tests handleHTTPRequest when session not found
func TestHandleHTTPRequestSessionNotFound(t *testing.T) {
	s := New(DefaultConfig(), nil)

	// Create a tunnel but no session
	tunnel := &Tunnel{
		ID:        "tunnel-1",
		Type:      proto.TunnelTypeHTTP,
		Subdomain: "test",
		SessionID: "nonexistent-session",
	}
	s.tunnels.Store("test", tunnel)

	// Create HTTP request
	req, _ := http.NewRequest("GET", "/", nil)
	req.Host = "test.wirerift.dev"

	rr := httptest.NewRecorder()
	s.handleHTTPRequest(rr, req)

	if rr.Code != http.StatusBadGateway {
		t.Errorf("Expected status 502, got %d", rr.Code)
	}
	if body := rr.Body.String(); !strings.Contains(body, "Session not found") {
		t.Errorf("Expected 'Session not found' in body, got: %s", body)
	}
}

// TestAcceptControlConnections tests the accept loop behavior
func TestAcceptControlConnections(t *testing.T) {
	serverCfg := DefaultConfig()
	serverCfg.ControlAddr = "127.0.0.1:0"
	serverCfg.HTTPAddr = "" // Don't start HTTP

	s := New(serverCfg, nil)

	// Use proper Start which sets up context and lifecycle
	if err := s.Start(); err != nil {
		t.Fatalf("Start failed: %v", err)
	}

	// Get the control address
	controlAddr := s.controlListener.Addr().String()

	// Connect a client
	conn, err := net.Dial("tcp", controlAddr)
	if err != nil {
		s.Stop()
		t.Fatalf("Failed to connect: %v", err)
	}

	// Write magic
	if err := proto.WriteMagic(conn); err != nil {
		conn.Close()
		s.Stop()
		t.Fatalf("Failed to write magic: %v", err)
	}

	// Give it time to be accepted
	time.Sleep(100 * time.Millisecond)

	// Clean close
	conn.Close()
	if err := s.Stop(); err != nil {
		t.Errorf("Stop failed: %v", err)
	}
}

// TestStartStopWithHTTP tests server start and stop with HTTP listener
func TestStartStopWithHTTP(t *testing.T) {
	serverCfg := DefaultConfig()
	serverCfg.ControlAddr = "127.0.0.1:0"
	serverCfg.HTTPAddr = "127.0.0.1:0"

	s := New(serverCfg, nil)

	if err := s.Start(); err != nil {
		t.Fatalf("Start failed: %v", err)
	}

	// Verify listeners are set
	if s.controlListener == nil {
		t.Error("controlListener should be set")
	}
	if s.httpListener == nil {
		t.Error("httpListener should be set")
	}

	// Stop
	if err := s.Stop(); err != nil {
		t.Errorf("Stop failed: %v", err)
	}
}

// TestStartControlListenerError tests Start when control listener fails
func TestStartControlListenerError(t *testing.T) {
	serverCfg := DefaultConfig()
	serverCfg.ControlAddr = "invalid-addr-no-port"
	serverCfg.HTTPAddr = "127.0.0.1:0"

	s := New(serverCfg, nil)

	err := s.Start()
	if err == nil {
		s.Stop()
		t.Fatal("Expected error from invalid control address")
	}
	if !strings.Contains(err.Error(), "start control listener") {
		t.Errorf("Expected 'start control listener' in error, got: %v", err)
	}
}

// TestStartHTTPListenerError tests Start when HTTP listener fails
func TestStartHTTPListenerError(t *testing.T) {
	// First, bind a port so it's occupied
	blocker, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to create blocker listener: %v", err)
	}
	defer blocker.Close()
	blockedAddr := blocker.Addr().String()

	serverCfg := DefaultConfig()
	serverCfg.ControlAddr = "127.0.0.1:0"
	serverCfg.HTTPAddr = blockedAddr // Already in use

	s := New(serverCfg, nil)

	err = s.Start()
	if err == nil {
		s.Stop()
		t.Fatal("Expected error from occupied HTTP address")
	}
	if !strings.Contains(err.Error(), "start HTTP listener") {
		t.Errorf("Expected 'start HTTP listener' in error, got: %v", err)
	}
	// Clean up the control listener that was successfully started
	if s.controlListener != nil {
		s.controlListener.Close()
	}
}

// TestForwardHTTPRequest tests the forwardHTTPRequest stub
func TestForwardHTTPRequestMuxClosed(t *testing.T) {
	s := New(DefaultConfig(), nil)

	// Create a mux that is already closed so OpenStream fails
	c1, c2 := net.Pipe()
	defer c2.Close()
	m := mux.New(c1, mux.DefaultConfig())
	m.Close()

	tunnel := &Tunnel{
		ID:        "tunnel-1",
		Type:      proto.TunnelTypeHTTP,
		Subdomain: "test",
		SessionID: "session-1",
	}

	session := &Session{
		ID:        "session-1",
		AccountID: "account-1",
		Mux:       m,
	}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "http://test.wirerift.dev/", nil)

	s.forwardHTTPRequest(rr, req, session, tunnel)

	if rr.Code != http.StatusBadGateway {
		t.Errorf("Expected status 502, got %d", rr.Code)
	}
	if body := rr.Body.String(); !strings.Contains(body, "Failed to open stream") {
		t.Errorf("Expected 'Failed to open stream' in body, got: %s", body)
	}
}

// TestStopWithSessions tests Stop when sessions with Mux exist
func TestStopWithSessions(t *testing.T) {
	serverCfg := DefaultConfig()
	serverCfg.ControlAddr = "127.0.0.1:0"
	serverCfg.HTTPAddr = "127.0.0.1:0"

	s := New(serverCfg, nil)

	if err := s.Start(); err != nil {
		t.Fatalf("Start failed: %v", err)
	}

	// Create a pipe to provide a connection for Mux
	c1, c2 := net.Pipe()
	defer c2.Close()

	m := mux.New(c1, mux.DefaultConfig())

	session := &Session{
		ID:         "session-with-mux",
		AccountID:  "account-1",
		Mux:        m,
		Tunnels:    make(map[string]*Tunnel),
		CreatedAt:  time.Now(),
		LastSeen:   time.Now(),
		RemoteAddr: c1.RemoteAddr(),
	}
	s.sessions.Store("session-with-mux", session)

	// Stop should close the session's mux without panic
	if err := s.Stop(); err != nil {
		t.Errorf("Stop failed: %v", err)
	}
}

// TestHandleHTTPRequestWithSessionFound tests the full flow with tunnel AND session found
func TestHandleHTTPRequestWithSessionFound(t *testing.T) {
	s := New(DefaultConfig(), nil)

	// Create a pipe for the mux
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	m := mux.New(c1, mux.DefaultConfig())
	go m.Run()

	// Store both tunnel and session
	tunnel := &Tunnel{
		ID:        "tunnel-1",
		Type:      proto.TunnelTypeHTTP,
		Subdomain: "fulltest",
		SessionID: "session-full",
	}
	s.tunnels.Store("fulltest", tunnel)

	session := &Session{
		ID:         "session-full",
		AccountID:  "account-1",
		Mux:        m,
		Tunnels:    map[string]*Tunnel{"tunnel-1": tunnel},
		CreatedAt:  time.Now(),
		LastSeen:   time.Now(),
		RemoteAddr: c1.RemoteAddr(),
	}
	s.sessions.Store("session-full", session)

	// On the "client" side (c2), use a mux to accept the STREAM_OPEN and respond
	clientMux := mux.New(c2, mux.DefaultConfig())
	go clientMux.Run()

	// Accept the stream and write a valid HTTP response back
	go func() {
		stream, err := clientMux.AcceptStream()
		if err != nil {
			return
		}
		defer stream.Close()

		// Read the serialized HTTP request from the stream using HTTP framing
		reader := bufio.NewReader(stream)
		httpReq, err := http.ReadRequest(reader)
		if err != nil {
			return
		}
		httpReq.Body.Close()

		// Write a valid HTTP response back through the stream
		resp := "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK"
		stream.Write([]byte(resp))
	}()

	// Make HTTP request
	req := httptest.NewRequest("GET", "http://fulltest.wirerift.dev/path", nil)
	req.Host = "fulltest.wirerift.dev"
	rr := httptest.NewRecorder()

	s.handleHTTPRequest(rr, req)

	// forwardHTTPRequest should now proxy through the mux and get a 200 response
	if rr.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", rr.Code)
	}
	if body := rr.Body.String(); body != "OK" {
		t.Errorf("Expected body 'OK', got: %s", body)
	}
}

// TestAcceptControlConnectionsErrorThenDone tests accept error followed by context cancellation
func TestAcceptControlConnectionsErrorThenDone(t *testing.T) {
	serverCfg := DefaultConfig()
	serverCfg.ControlAddr = "127.0.0.1:0"

	s := New(serverCfg, nil)

	// Start the control listener
	if err := s.startControlListener(); err != nil {
		t.Fatalf("startControlListener failed: %v", err)
	}

	// Cancel context first, then close listener to trigger accept error with ctx done
	s.cancel()

	// Close the listener to trigger accept error
	s.controlListener.Close()

	// Wait for goroutine to finish
	s.wg.Wait()
}

// TestStopWithHTTPSListener tests Stop when httpsListener is set
func TestStopWithHTTPSListener(t *testing.T) {
	s := New(DefaultConfig(), nil)

	// Manually set up an httpsListener
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to create listener: %v", err)
	}
	s.httpsListener = listener

	if err := s.Stop(); err != nil {
		t.Errorf("Stop failed: %v", err)
	}
}

// TestHandleControlConnectionCtxDone tests handleControlConnection exiting via ctx.Done during auth
func TestHandleControlConnectionCtxDone(t *testing.T) {
	s := New(DefaultConfig(), nil)

	serverConn, clientConn := net.Pipe()
	defer clientConn.Close()

	// Write magic from client side
	go func() {
		proto.WriteMagic(clientConn)
		// Don't send auth - let it wait
	}()

	done := make(chan struct{})
	go func() {
		s.handleControlConnection(serverConn)
		close(done)
	}()

	// Give time for magic to be read and mux to start
	time.Sleep(100 * time.Millisecond)

	// Cancel context to trigger ctx.Done() path in handleAuth
	s.cancel()

	select {
	case <-done:
		// Success
	case <-time.After(2 * time.Second):
		t.Error("handleControlConnection did not exit after context cancellation")
	}
}

// --- New tests for auth and tunnel management ---

func TestGenerateSubdomain(t *testing.T) {
	sub1 := generateSubdomain()
	sub2 := generateSubdomain()

	if len(sub1) != 8 {
		t.Errorf("Expected subdomain length 8, got %d", len(sub1))
	}
	if sub1 == sub2 {
		t.Error("Two generated subdomains should not be identical")
	}
	// Verify only valid characters
	for _, c := range sub1 {
		if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')) {
			t.Errorf("Invalid character %c in subdomain", c)
		}
	}
}

func TestNewWithAuthManager(t *testing.T) {
	authMgr := auth.NewManager()
	cfg := DefaultConfig()
	cfg.AuthManager = authMgr
	s := New(cfg, nil)

	if s.authManager != authMgr {
		t.Error("AuthManager should be the provided one")
	}
}

func TestNewWithoutAuthManager(t *testing.T) {
	cfg := DefaultConfig()
	s := New(cfg, nil)

	if s.authManager == nil {
		t.Error("AuthManager should be auto-created when nil")
	}
}

// helper: creates a server with auth, performs magic + auth handshake, returns the session ID and mux pipes
func setupAuthenticatedSession(t *testing.T) (*Server, net.Conn, *proto.FrameWriter, *proto.FrameReader, string) {
	t.Helper()
	authMgr := auth.NewManager()
	cfg := DefaultConfig()
	cfg.AuthManager = authMgr
	cfg.MaxTunnelsPerSession = 3
	s := New(cfg, nil)

	serverConn, clientConn := net.Pipe()

	go s.handleControlConnection(serverConn)

	// Write magic
	proto.WriteMagic(clientConn)

	fw := proto.NewFrameWriter(clientConn)
	fr := proto.NewFrameReader(clientConn)

	// Send auth request
	authReq := &proto.AuthRequest{Token: authMgr.DevToken(), Version: "1.0.0"}
	frame, _ := proto.EncodeJSONPayload(proto.FrameAuthReq, 0, authReq)
	fw.Write(frame)

	// Read auth response
	respFrame, err := fr.Read()
	if err != nil {
		clientConn.Close()
		t.Fatalf("Failed to read auth response: %v", err)
	}

	var authRes proto.AuthResponse
	proto.DecodeJSONPayload(respFrame, &authRes)
	if !authRes.OK {
		clientConn.Close()
		t.Fatalf("Auth failed: %s", authRes.Error)
	}

	return s, clientConn, fw, fr, authRes.SessionID
}

func TestHandleAuthSuccess(t *testing.T) {
	authMgr := auth.NewManager()
	cfg := DefaultConfig()
	cfg.AuthManager = authMgr
	s := New(cfg, nil)

	c1, c2 := net.Pipe()
	defer c1.Close()

	m := mux.New(c1, mux.DefaultConfig())
	go m.Run()

	// Send auth request from client side
	go func() {
		fw := proto.NewFrameWriter(c2)
		authReq := &proto.AuthRequest{Token: authMgr.DevToken()}
		frame, _ := proto.EncodeJSONPayload(proto.FrameAuthReq, 0, authReq)
		fw.Write(frame)
		// Read response
		fr := proto.NewFrameReader(c2)
		fr.Read()
		io.Copy(io.Discard, c2)
	}()

	session, err := s.handleAuth(m, c1.RemoteAddr())
	if err != nil {
		t.Fatalf("handleAuth failed: %v", err)
	}
	if session == nil {
		t.Fatal("session should not be nil")
	}
	if session.AccountID == "" {
		t.Error("AccountID should not be empty")
	}
	if !strings.HasPrefix(session.ID, "sess_") {
		t.Errorf("SessionID should start with sess_, got %s", session.ID)
	}
}

func TestHandleAuthInvalidToken(t *testing.T) {
	authMgr := auth.NewManager()
	cfg := DefaultConfig()
	cfg.AuthManager = authMgr
	s := New(cfg, nil)

	c1, c2 := net.Pipe()
	defer c1.Close()

	m := mux.New(c1, mux.DefaultConfig())
	go m.Run()

	go func() {
		fw := proto.NewFrameWriter(c2)
		authReq := &proto.AuthRequest{Token: "invalid-token"}
		frame, _ := proto.EncodeJSONPayload(proto.FrameAuthReq, 0, authReq)
		fw.Write(frame)
		// Read response
		fr := proto.NewFrameReader(c2)
		fr.Read()
		io.Copy(io.Discard, c2)
	}()

	_, err := s.handleAuth(m, c1.RemoteAddr())
	if err == nil {
		t.Fatal("Expected auth error for invalid token")
	}
	if !strings.Contains(err.Error(), "invalid token") {
		t.Errorf("Expected 'invalid token' in error, got: %v", err)
	}
}

func TestHandleAuthWrongFrameType(t *testing.T) {
	s := New(DefaultConfig(), nil)

	c1, c2 := net.Pipe()
	defer c1.Close()

	m := mux.New(c1, mux.DefaultConfig())
	go m.Run()

	go func() {
		fw := proto.NewFrameWriter(c2)
		// Send a tunnel request instead of auth
		req := &proto.TunnelRequest{Type: proto.TunnelTypeHTTP, LocalAddr: "localhost:3000"}
		frame, _ := proto.EncodeJSONPayload(proto.FrameTunnelReq, 0, req)
		fw.Write(frame)
		io.Copy(io.Discard, c2)
	}()

	_, err := s.handleAuth(m, c1.RemoteAddr())
	if err == nil {
		t.Fatal("Expected error for wrong frame type")
	}
	if !strings.Contains(err.Error(), "expected AUTH_REQ") {
		t.Errorf("Expected 'expected AUTH_REQ' in error, got: %v", err)
	}
}

func TestHandleAuthConnectionClosedBeforeAuth(t *testing.T) {
	s := New(DefaultConfig(), nil)

	c1, c2 := net.Pipe()

	m := mux.New(c1, mux.DefaultConfig())
	go m.Run()

	// Close connection immediately to trigger "connection closed before auth"
	c2.Close()

	// Wait for mux to detect closure
	time.Sleep(50 * time.Millisecond)

	_, err := s.handleAuth(m, c1.RemoteAddr())
	if err == nil {
		t.Fatal("Expected error when connection closed before auth")
	}
}

func TestHandleAuthDecodeError(t *testing.T) {
	s := New(DefaultConfig(), nil)

	c1, c2 := net.Pipe()
	defer c1.Close()

	m := mux.New(c1, mux.DefaultConfig())
	go m.Run()

	go func() {
		fw := proto.NewFrameWriter(c2)
		// Send AUTH_REQ with invalid JSON payload
		badFrame := &proto.Frame{
			Version:  proto.Version,
			Type:     proto.FrameAuthReq,
			StreamID: 0,
			Payload:  []byte("not valid json{{{"),
		}
		fw.Write(badFrame)
		io.Copy(io.Discard, c2)
	}()

	_, err := s.handleAuth(m, c1.RemoteAddr())
	if err == nil {
		t.Fatal("Expected error for invalid JSON")
	}
	if !strings.Contains(err.Error(), "decode auth request") {
		t.Errorf("Expected 'decode auth request' in error, got: %v", err)
	}
}

func TestHandleAuthTimeout(t *testing.T) {
	s := New(DefaultConfig(), nil)

	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	m := mux.New(c1, mux.DefaultConfig())
	go m.Run()

	// Don't send anything - let it timeout
	// We override the timeout by creating a custom test that uses a short timeout
	// Since handleAuth uses 10s timeout, we test via context cancellation instead
	// Cancel server context to trigger the ctx.Done path
	go func() {
		time.Sleep(50 * time.Millisecond)
		s.cancel()
	}()

	_, err := s.handleAuth(m, c1.RemoteAddr())
	if err == nil {
		t.Fatal("Expected error from server shutdown")
	}
	if !strings.Contains(err.Error(), "server shutting down") {
		t.Errorf("Expected 'server shutting down' in error, got: %v", err)
	}
}

func TestHandleTunnelRequestHTTP(t *testing.T) {
	s, clientConn, fw, fr, _ := setupAuthenticatedSession(t)
	defer clientConn.Close()
	_ = s

	// Send tunnel request
	req := &proto.TunnelRequest{
		Type:      proto.TunnelTypeHTTP,
		Subdomain: "mytest",
		LocalAddr: "localhost:3000",
	}
	frame, _ := proto.EncodeJSONPayload(proto.FrameTunnelReq, 0, req)
	fw.Write(frame)

	// Read response
	respFrame, err := fr.Read()
	if err != nil {
		t.Fatalf("Failed to read tunnel response: %v", err)
	}

	var res proto.TunnelResponse
	proto.DecodeJSONPayload(respFrame, &res)
	if !res.OK {
		t.Fatalf("Tunnel creation should succeed, got error: %s", res.Error)
	}
	if res.Type != proto.TunnelTypeHTTP {
		t.Errorf("Type = %q, want http", res.Type)
	}
	if !strings.Contains(res.PublicURL, "mytest") {
		t.Errorf("PublicURL should contain subdomain, got %s", res.PublicURL)
	}
	if !strings.HasPrefix(res.TunnelID, "tun_") {
		t.Errorf("TunnelID should start with tun_, got %s", res.TunnelID)
	}

	// Verify tunnel is stored in global map
	_, ok := s.getTunnelBySubdomain("mytest")
	if !ok {
		t.Error("Tunnel should be stored in global tunnels map")
	}
}

func TestHandleTunnelRequestHTTPAutoSubdomain(t *testing.T) {
	s, clientConn, fw, fr, _ := setupAuthenticatedSession(t)
	defer clientConn.Close()
	_ = s

	// Send tunnel request without subdomain
	req := &proto.TunnelRequest{
		Type:      proto.TunnelTypeHTTP,
		LocalAddr: "localhost:3000",
	}
	frame, _ := proto.EncodeJSONPayload(proto.FrameTunnelReq, 0, req)
	fw.Write(frame)

	respFrame, err := fr.Read()
	if err != nil {
		t.Fatalf("Failed to read tunnel response: %v", err)
	}

	var res proto.TunnelResponse
	proto.DecodeJSONPayload(respFrame, &res)
	if !res.OK {
		t.Fatalf("Tunnel creation should succeed, got error: %s", res.Error)
	}
	if res.PublicURL == "" {
		t.Error("PublicURL should not be empty")
	}
}

func TestHandleTunnelRequestSubdomainTaken(t *testing.T) {
	s, clientConn, fw, fr, _ := setupAuthenticatedSession(t)
	defer clientConn.Close()

	// Pre-store a tunnel with subdomain "taken"
	s.tunnels.Store("taken", &Tunnel{ID: "existing", Subdomain: "taken"})

	req := &proto.TunnelRequest{
		Type:      proto.TunnelTypeHTTP,
		Subdomain: "taken",
		LocalAddr: "localhost:3000",
	}
	frame, _ := proto.EncodeJSONPayload(proto.FrameTunnelReq, 0, req)
	fw.Write(frame)

	respFrame, err := fr.Read()
	if err != nil {
		t.Fatalf("Failed to read tunnel response: %v", err)
	}

	var res proto.TunnelResponse
	proto.DecodeJSONPayload(respFrame, &res)
	if res.OK {
		t.Fatal("Tunnel creation should fail for taken subdomain")
	}
	if !strings.Contains(res.Error, "subdomain already taken") {
		t.Errorf("Expected 'subdomain already taken' error, got: %s", res.Error)
	}
}

func TestHandleTunnelRequestMaxTunnelsExceeded(t *testing.T) {
	_, clientConn, fw, fr, _ := setupAuthenticatedSession(t)
	defer clientConn.Close()

	// Create 3 tunnels (the max)
	for i := 0; i < 3; i++ {
		req := &proto.TunnelRequest{
			Type:      proto.TunnelTypeHTTP,
			Subdomain: fmt.Sprintf("test%d", i),
			LocalAddr: "localhost:3000",
		}
		frame, _ := proto.EncodeJSONPayload(proto.FrameTunnelReq, 0, req)
		fw.Write(frame)

		respFrame, err := fr.Read()
		if err != nil {
			t.Fatalf("Failed to read tunnel response %d: %v", i, err)
		}
		var res proto.TunnelResponse
		proto.DecodeJSONPayload(respFrame, &res)
		if !res.OK {
			t.Fatalf("Tunnel %d should succeed: %s", i, res.Error)
		}
	}

	// 4th tunnel should fail
	req := &proto.TunnelRequest{
		Type:      proto.TunnelTypeHTTP,
		Subdomain: "overflow",
		LocalAddr: "localhost:3000",
	}
	frame, _ := proto.EncodeJSONPayload(proto.FrameTunnelReq, 0, req)
	fw.Write(frame)

	respFrame, err := fr.Read()
	if err != nil {
		t.Fatalf("Failed to read tunnel response: %v", err)
	}
	var res proto.TunnelResponse
	proto.DecodeJSONPayload(respFrame, &res)
	if res.OK {
		t.Fatal("Tunnel creation should fail when max tunnels exceeded")
	}
	if !strings.Contains(res.Error, "max tunnels exceeded") {
		t.Errorf("Expected 'max tunnels exceeded' error, got: %s", res.Error)
	}
}

func TestHandleTunnelRequestUnsupportedType(t *testing.T) {
	_, clientConn, fw, fr, _ := setupAuthenticatedSession(t)
	defer clientConn.Close()

	req := &proto.TunnelRequest{
		Type:      "websocket",
		LocalAddr: "localhost:3000",
	}
	frame, _ := proto.EncodeJSONPayload(proto.FrameTunnelReq, 0, req)
	fw.Write(frame)

	respFrame, err := fr.Read()
	if err != nil {
		t.Fatalf("Failed to read tunnel response: %v", err)
	}
	var res proto.TunnelResponse
	proto.DecodeJSONPayload(respFrame, &res)
	if res.OK {
		t.Fatal("Tunnel creation should fail for unsupported type")
	}
	if !strings.Contains(res.Error, "unsupported tunnel type") {
		t.Errorf("Expected 'unsupported tunnel type' error, got: %s", res.Error)
	}
}

func TestHandleTunnelRequestInvalidJSON(t *testing.T) {
	_, clientConn, fw, fr, _ := setupAuthenticatedSession(t)
	defer clientConn.Close()

	badFrame := &proto.Frame{
		Version:  proto.Version,
		Type:     proto.FrameTunnelReq,
		StreamID: 0,
		Payload:  []byte("invalid json{{{"),
	}
	fw.Write(badFrame)

	respFrame, err := fr.Read()
	if err != nil {
		t.Fatalf("Failed to read tunnel response: %v", err)
	}
	var res proto.TunnelResponse
	proto.DecodeJSONPayload(respFrame, &res)
	if res.OK {
		t.Fatal("Tunnel creation should fail for invalid JSON")
	}
	if !strings.Contains(res.Error, "invalid request") {
		t.Errorf("Expected 'invalid request' error, got: %s", res.Error)
	}
}

func TestHandleTunnelClose(t *testing.T) {
	s, clientConn, fw, fr, _ := setupAuthenticatedSession(t)
	defer clientConn.Close()

	// Create a tunnel first
	req := &proto.TunnelRequest{
		Type:      proto.TunnelTypeHTTP,
		Subdomain: "closeme",
		LocalAddr: "localhost:3000",
	}
	frame, _ := proto.EncodeJSONPayload(proto.FrameTunnelReq, 0, req)
	fw.Write(frame)

	respFrame, err := fr.Read()
	if err != nil {
		t.Fatalf("Failed to read tunnel response: %v", err)
	}
	var res proto.TunnelResponse
	proto.DecodeJSONPayload(respFrame, &res)
	if !res.OK {
		t.Fatalf("Tunnel creation should succeed: %s", res.Error)
	}

	// Verify tunnel exists
	_, ok := s.getTunnelBySubdomain("closeme")
	if !ok {
		t.Fatal("Tunnel should exist before close")
	}

	// Close the tunnel
	closeReq := &proto.TunnelClose{TunnelID: res.TunnelID}
	closeFrame, _ := proto.EncodeJSONPayload(proto.FrameTunnelClose, 0, closeReq)
	fw.Write(closeFrame)

	// Give time for close to process
	time.Sleep(100 * time.Millisecond)

	// Verify tunnel is removed
	_, ok = s.getTunnelBySubdomain("closeme")
	if ok {
		t.Error("Tunnel should be removed after close")
	}
}

func TestHandleTunnelCloseNonExistent(t *testing.T) {
	_, clientConn, fw, _, _ := setupAuthenticatedSession(t)
	defer clientConn.Close()

	// Close a tunnel that doesn't exist - should not panic
	closeReq := &proto.TunnelClose{TunnelID: "nonexistent"}
	closeFrame, _ := proto.EncodeJSONPayload(proto.FrameTunnelClose, 0, closeReq)
	fw.Write(closeFrame)

	// Give time to process
	time.Sleep(50 * time.Millisecond)
	// No panic = pass
}

func TestHandleTunnelCloseInvalidJSON(t *testing.T) {
	_, clientConn, fw, _, _ := setupAuthenticatedSession(t)
	defer clientConn.Close()

	badFrame := &proto.Frame{
		Version:  proto.Version,
		Type:     proto.FrameTunnelClose,
		StreamID: 0,
		Payload:  []byte("bad json"),
	}
	fw.Write(badFrame)

	// Give time to process - should not panic
	time.Sleep(50 * time.Millisecond)
}

func TestRemoveSession(t *testing.T) {
	s := New(DefaultConfig(), nil)

	// Create a session with HTTP and TCP tunnels
	session := &Session{
		ID:        "sess-remove-test",
		AccountID: "account-1",
		Tunnels:   make(map[string]*Tunnel),
	}

	httpTunnel := &Tunnel{
		ID:        "tun-http",
		Type:      proto.TunnelTypeHTTP,
		SessionID: "sess-remove-test",
		Subdomain: "removeme",
	}
	tcpTunnel := &Tunnel{
		ID:        "tun-tcp",
		Type:      proto.TunnelTypeTCP,
		SessionID: "sess-remove-test",
		Port:      25000,
	}

	session.Tunnels["tun-http"] = httpTunnel
	session.Tunnels["tun-tcp"] = tcpTunnel
	s.sessions.Store("sess-remove-test", session)
	s.tunnels.Store("removeme", httpTunnel)
	s.tunnels.Store("tcp:25000", tcpTunnel)
	s.tcpPorts.Store(25000, true)

	// Remove session
	s.removeSession("sess-remove-test")

	// Verify session is removed
	_, ok := s.getSession("sess-remove-test")
	if ok {
		t.Error("Session should be removed")
	}

	// Verify tunnels are cleaned up
	_, ok = s.getTunnelBySubdomain("removeme")
	if ok {
		t.Error("HTTP tunnel should be cleaned up")
	}

	if _, loaded := s.tunnels.Load("tcp:25000"); loaded {
		t.Error("TCP tunnel should be cleaned up")
	}

	// Verify port is released
	if _, loaded := s.tcpPorts.Load(25000); loaded {
		t.Error("TCP port should be released")
	}
}

func TestRemoveSessionNonExistent(t *testing.T) {
	s := New(DefaultConfig(), nil)

	// Should not panic
	s.removeSession("nonexistent")
}

func TestRemoveSessionEmpty(t *testing.T) {
	s := New(DefaultConfig(), nil)

	session := &Session{
		ID:      "sess-empty",
		Tunnels: make(map[string]*Tunnel),
	}
	s.sessions.Store("sess-empty", session)

	s.removeSession("sess-empty")

	_, ok := s.getSession("sess-empty")
	if ok {
		t.Error("Session should be removed")
	}
}

func TestHandleTunnelRequestsExitOnMuxDone(t *testing.T) {
	authMgr := auth.NewManager()
	cfg := DefaultConfig()
	cfg.AuthManager = authMgr
	s := New(cfg, nil)

	c1, c2 := net.Pipe()
	m := mux.New(c1, mux.DefaultConfig())
	go m.Run()

	session := &Session{
		ID:      "sess-test",
		Tunnels: make(map[string]*Tunnel),
	}

	done := make(chan struct{})
	go func() {
		s.handleTunnelRequests(m, session)
		close(done)
	}()

	// Close the connection to trigger mux.Done()
	c2.Close()

	select {
	case <-done:
		// Success
	case <-time.After(2 * time.Second):
		t.Error("handleTunnelRequests did not exit on mux done")
	}
}

func TestHandleTunnelRequestsExitOnCtxDone(t *testing.T) {
	s := New(DefaultConfig(), nil)

	c1, c2 := net.Pipe()
	defer c2.Close()
	m := mux.New(c1, mux.DefaultConfig())
	go m.Run()

	session := &Session{
		ID:      "sess-test",
		Tunnels: make(map[string]*Tunnel),
	}

	done := make(chan struct{})
	go func() {
		s.handleTunnelRequests(m, session)
		close(done)
	}()

	// Cancel context
	s.cancel()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Error("handleTunnelRequests did not exit on ctx done")
	}
}

func TestSessionCleanupOnDisconnect(t *testing.T) {
	s, clientConn, fw, fr, sessionID := setupAuthenticatedSession(t)

	// Create a tunnel
	req := &proto.TunnelRequest{
		Type:      proto.TunnelTypeHTTP,
		Subdomain: "cleanup",
		LocalAddr: "localhost:3000",
	}
	frame, _ := proto.EncodeJSONPayload(proto.FrameTunnelReq, 0, req)
	fw.Write(frame)

	respFrame, _ := fr.Read()
	var res proto.TunnelResponse
	proto.DecodeJSONPayload(respFrame, &res)
	if !res.OK {
		t.Fatalf("Tunnel creation failed: %s", res.Error)
	}

	// Verify session and tunnel exist
	_, ok := s.getSession(sessionID)
	if !ok {
		t.Fatal("Session should exist")
	}
	_, ok = s.getTunnelBySubdomain("cleanup")
	if !ok {
		t.Fatal("Tunnel should exist")
	}

	// Close connection to trigger session cleanup
	clientConn.Close()
	time.Sleep(200 * time.Millisecond)

	// Session and tunnel should be cleaned up via removeSession defer
	_, ok = s.getSession(sessionID)
	if ok {
		t.Error("Session should be cleaned up after disconnect")
	}
	_, ok = s.getTunnelBySubdomain("cleanup")
	if ok {
		t.Error("Tunnel should be cleaned up after disconnect")
	}
}

func TestHandleTunnelCloseTCPTunnel(t *testing.T) {
	s := New(DefaultConfig(), nil)

	session := &Session{
		ID:      "sess-tcp",
		Tunnels: make(map[string]*Tunnel),
	}
	tcpTunnel := &Tunnel{
		ID:        "tun-tcp-close",
		Type:      proto.TunnelTypeTCP,
		SessionID: "sess-tcp",
		Port:      25001,
	}
	session.Tunnels["tun-tcp-close"] = tcpTunnel
	s.tunnels.Store("tcp:25001", tcpTunnel)
	s.tcpPorts.Store(25001, true)

	// Create a frame for closing
	closeReq := &proto.TunnelClose{TunnelID: "tun-tcp-close"}
	frame, _ := proto.EncodeJSONPayload(proto.FrameTunnelClose, 0, closeReq)

	s.handleTunnelClose(session, frame)

	// Verify cleanup
	if _, loaded := s.tunnels.Load("tcp:25001"); loaded {
		t.Error("TCP tunnel should be removed")
	}
	if _, loaded := s.tcpPorts.Load(25001); loaded {
		t.Error("TCP port should be released")
	}
}

func TestProxyTCPConnectionOpenStreamError(t *testing.T) {
	s := New(DefaultConfig(), nil)

	c1, c2 := net.Pipe()
	defer c2.Close()

	m := mux.New(c1, mux.DefaultConfig())
	m.Close() // Close mux to make OpenStream fail

	tunnel := &Tunnel{ID: "tun-1"}
	session := &Session{ID: "sess-1", Mux: m}

	conn1, conn2 := net.Pipe()
	defer conn2.Close()

	// Should return without panic when OpenStream fails
	s.proxyTCPConnection(conn1, tunnel, session)
}

func TestStartTCPTunnelListenerInvalidPort(t *testing.T) {
	srv := New(DefaultConfig(), nil)

	tunnel := &Tunnel{ID: "tun-1"}

	c1, c2 := net.Pipe()
	defer c2.Close()
	m := mux.New(c1, mux.DefaultConfig())
	session := &Session{
		ID:  "sess-1",
		Mux: m,
	}

	// Port -1 will cause net.Listen to fail
	srv.startTCPTunnelListener(-1, tunnel, session)
	// Should return without panic - test passes if we get here
}

func TestHandleControlConnectionAuthFailed(t *testing.T) {
	authMgr := auth.NewManager()
	cfg := DefaultConfig()
	cfg.AuthManager = authMgr
	s := New(cfg, nil)

	serverConn, clientConn := net.Pipe()

	done := make(chan struct{})
	go func() {
		s.handleControlConnection(serverConn)
		close(done)
	}()

	// Write magic
	proto.WriteMagic(clientConn)

	// Send auth with bad token
	fw := proto.NewFrameWriter(clientConn)
	fr := proto.NewFrameReader(clientConn)
	authReq := &proto.AuthRequest{Token: "bad-token"}
	frame, _ := proto.EncodeJSONPayload(proto.FrameAuthReq, 0, authReq)
	fw.Write(frame)

	// Read auth failure response
	respFrame, err := fr.Read()
	if err != nil {
		t.Fatalf("Failed to read auth response: %v", err)
	}
	var authRes proto.AuthResponse
	proto.DecodeJSONPayload(respFrame, &authRes)
	if authRes.OK {
		t.Error("Auth should fail")
	}

	// handleControlConnection should close the connection
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Error("handleControlConnection did not exit after auth failure")
	}
	clientConn.Close()
}

// TestHandleTunnelRequestTCP tests TCP tunnel creation through the full authenticated flow.
func TestHandleTunnelRequestTCP(t *testing.T) {
	s, clientConn, fw, fr, _ := setupAuthenticatedSession(t)

	// Request a TCP tunnel
	req := &proto.TunnelRequest{
		Type:      proto.TunnelTypeTCP,
		LocalAddr: "localhost:5432",
	}
	frame, _ := proto.EncodeJSONPayload(proto.FrameTunnelReq, 0, req)
	fw.Write(frame)

	respFrame, err := fr.Read()
	if err != nil {
		t.Fatalf("Failed to read tunnel response: %v", err)
	}

	var res proto.TunnelResponse
	proto.DecodeJSONPayload(respFrame, &res)
	if !res.OK {
		t.Fatalf("TCP tunnel creation should succeed, got error: %s", res.Error)
	}
	if res.Type != proto.TunnelTypeTCP {
		t.Errorf("Type = %q, want tcp", res.Type)
	}
	if !strings.HasPrefix(res.TunnelID, "tun_") {
		t.Errorf("TunnelID should start with tun_, got %s", res.TunnelID)
	}
	if !strings.Contains(res.PublicURL, "tcp://") {
		t.Errorf("PublicURL should contain tcp://, got %s", res.PublicURL)
	}

	clientConn.Close()
	time.Sleep(100 * time.Millisecond)
	s.cancel()
	s.wg.Wait()
}

// TestHandleTunnelRequestTCPPortExhaustion tests TCP tunnel creation when no ports are available.
func TestHandleTunnelRequestTCPPortExhaustion(t *testing.T) {
	authMgr := auth.NewManager()
	cfg := DefaultConfig()
	cfg.AuthManager = authMgr
	cfg.MaxTunnelsPerSession = 10
	s := New(cfg, nil)

	// Use a very small port range and exhaust it
	s.tcpPortStart = 20000
	s.tcpPortEnd = 20000
	s.nextPort.Store(int32(20000))
	// Allocate the one possible port
	s.tcpPorts.Store(20001, true)

	c1, c2 := net.Pipe()
	m := mux.New(c1, mux.DefaultConfig())
	go m.Run()

	session := &Session{
		ID:      "sess-port-exhaust",
		Tunnels: make(map[string]*Tunnel),
	}

	// We need to read response via the raw pipe since mux's Run handles routing
	// Call handleTunnelRequest directly but read from the raw c2 side
	req := &proto.TunnelRequest{
		Type:      proto.TunnelTypeTCP,
		LocalAddr: "localhost:5432",
	}
	frame, _ := proto.EncodeJSONPayload(proto.FrameTunnelReq, 0, req)

	// handleTunnelRequest writes the response via m.GetFrameWriter() which writes to c1
	// The mux.Run() goroutine reads from c1, but control frames go to controlCh
	// Since we call handleTunnelRequest directly, it writes TUNNEL_RES directly via frameWriter
	// The mux.Run() on c1 reads from c1 (reads what c2 writes) - but we're writing on c1 via frameWriter
	// Actually the frameWriter writes to the underlying conn (c1), which c2 can read
	go s.handleTunnelRequest(m, session, frame)

	fr := proto.NewFrameReader(c2)
	respFrame, err := fr.Read()
	if err != nil {
		t.Fatalf("Failed to read tunnel response: %v", err)
	}

	var res proto.TunnelResponse
	proto.DecodeJSONPayload(respFrame, &res)
	if res.OK {
		t.Fatal("TCP tunnel creation should fail when no ports available")
	}
	if !strings.Contains(res.Error, "no ports available") {
		t.Errorf("Expected 'no ports available' error, got: %s", res.Error)
	}

	c2.Close()
	m.Close()
}

// TestStartTCPTunnelListenerAcceptAndProxy tests a TCP tunnel listener that accepts a connection.
func TestStartTCPTunnelListenerAcceptAndProxy(t *testing.T) {
	s := New(DefaultConfig(), nil)

	c1, c2 := net.Pipe()
	m := mux.New(c1, mux.DefaultConfig())
	go m.Run()

	tunnel := &Tunnel{ID: "tun-tcp-listen"}
	session := &Session{ID: "sess-tcp-listen", Mux: m}

	// Use port 0 to get a random available port
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to create listener: %v", err)
	}
	listenAddr := listener.Addr().String()
	listener.Close() // Close so startTCPTunnelListener can bind it

	// Extract port
	_, portStr, _ := net.SplitHostPort(listenAddr)
	var port int
	fmt.Sscanf(portStr, "%d", &port)

	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		s.startTCPTunnelListener(port, tunnel, session)
	}()

	// Give time for listener to start
	time.Sleep(50 * time.Millisecond)

	// Connect to the TCP tunnel
	conn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		// The listener may have started on a different port or not at all
		t.Logf("Could not connect to TCP tunnel listener: %v", err)
		s.cancel()
		c2.Close()
		s.wg.Wait()
		return
	}

	// Give time for the proxy goroutine to start and attempt OpenStream
	time.Sleep(50 * time.Millisecond)

	conn.Close()
	c2.Close()
	s.cancel()
	s.wg.Wait()
}

// TestProxyTCPConnectionWriteError tests proxyTCPConnection when frame write fails.
func TestProxyTCPConnectionWriteError(t *testing.T) {
	s := New(DefaultConfig(), nil)

	c1, c2 := net.Pipe()
	m := mux.New(c1, mux.DefaultConfig())
	go m.Run()

	tunnel := &Tunnel{ID: "tun-proxy-err"}
	session := &Session{ID: "sess-proxy-err", Mux: m}

	// Close the other end of the pipe so frame write fails
	c2.Close()
	time.Sleep(50 * time.Millisecond)

	conn1, conn2 := net.Pipe()
	defer conn2.Close()

	// proxyTCPConnection should handle the error gracefully
	s.proxyTCPConnection(conn1, tunnel, session)
}

// TestProxyTCPConnectionBidiCopy tests proxyTCPConnection with successful stream open and data transfer.
func TestProxyTCPConnectionBidiCopy(t *testing.T) {
	s := New(DefaultConfig(), nil)

	c1, c2 := net.Pipe()
	m := mux.New(c1, mux.DefaultConfig())
	go m.Run()

	tunnel := &Tunnel{ID: "tun-bidi"}
	session := &Session{ID: "sess-bidi", Mux: m}

	// Create a connection to proxy
	proxyConn, proxyRemote := net.Pipe()

	done := make(chan struct{})
	go func() {
		s.proxyTCPConnection(proxyConn, tunnel, session)
		close(done)
	}()

	// On the "server mux" side (c2), read the STREAM_OPEN frame, then read/write data
	go func() {
		fr := proto.NewFrameReader(c2)
		// Read the STREAM_OPEN frame that proxyTCPConnection sends
		frame, err := fr.Read()
		if err != nil {
			return
		}
		_ = frame // STREAM_OPEN frame

		// Close to end the proxy
		time.Sleep(50 * time.Millisecond)
		c2.Close()
	}()

	// Write some data from the proxy remote end
	go func() {
		time.Sleep(20 * time.Millisecond)
		proxyRemote.Write([]byte("hello"))
		proxyRemote.Close()
	}()

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Error("proxyTCPConnection did not complete")
		proxyRemote.Close()
		c2.Close()
	}
}

// TestStartTCPTunnelListenerCtxDone tests that startTCPTunnelListener exits on context cancellation.
func TestStartTCPTunnelListenerCtxDone(t *testing.T) {
	s := New(DefaultConfig(), nil)

	c1, c2 := net.Pipe()
	defer c2.Close()
	m := mux.New(c1, mux.DefaultConfig())
	go m.Run()

	tunnel := &Tunnel{ID: "tun-ctx-done"}
	session := &Session{ID: "sess-ctx-done", Mux: m}

	// Find a free port
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to find free port: %v", err)
	}
	_, portStr, _ := net.SplitHostPort(listener.Addr().String())
	var port int
	fmt.Sscanf(portStr, "%d", &port)
	listener.Close()

	done := make(chan struct{})
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		s.startTCPTunnelListener(port, tunnel, session)
		close(done)
	}()

	// Give time for listener to start
	time.Sleep(50 * time.Millisecond)

	// Cancel context to stop the listener
	s.cancel()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Error("startTCPTunnelListener did not exit on ctx done")
	}
}

// TestStartTCPTunnelListenerMuxDone tests that startTCPTunnelListener exits on mux done.
func TestStartTCPTunnelListenerMuxDone(t *testing.T) {
	s := New(DefaultConfig(), nil)

	c1, c2 := net.Pipe()
	m := mux.New(c1, mux.DefaultConfig())
	go m.Run()

	tunnel := &Tunnel{ID: "tun-mux-done"}
	session := &Session{ID: "sess-mux-done", Mux: m}

	// Find a free port
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to find free port: %v", err)
	}
	_, portStr, _ := net.SplitHostPort(listener.Addr().String())
	var port int
	fmt.Sscanf(portStr, "%d", &port)
	listener.Close()

	done := make(chan struct{})
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		s.startTCPTunnelListener(port, tunnel, session)
		close(done)
	}()

	// Give time for listener to start
	time.Sleep(50 * time.Millisecond)

	// Close the mux to trigger mux.Done()
	c2.Close()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Error("startTCPTunnelListener did not exit on mux done")
	}
}

// TestHandleTunnelRequestTCPViaFullFlow tests TCP tunnel creation through the full authenticated flow.
func TestHandleTunnelRequestTCPViaFullFlow(t *testing.T) {
	s, clientConn, fw, fr, _ := setupAuthenticatedSession(t)

	// Request a TCP tunnel
	req := &proto.TunnelRequest{
		Type:      proto.TunnelTypeTCP,
		LocalAddr: "localhost:5432",
	}
	frame, _ := proto.EncodeJSONPayload(proto.FrameTunnelReq, 0, req)
	fw.Write(frame)

	respFrame, err := fr.Read()
	if err != nil {
		t.Fatalf("Failed to read tunnel response: %v", err)
	}

	var res proto.TunnelResponse
	proto.DecodeJSONPayload(respFrame, &res)
	if !res.OK {
		t.Fatalf("TCP tunnel creation should succeed, got error: %s", res.Error)
	}
	if res.Type != proto.TunnelTypeTCP {
		t.Errorf("Type = %q, want tcp", res.Type)
	}
	if !strings.Contains(res.PublicURL, "tcp://") {
		t.Errorf("PublicURL should start with tcp://, got %s", res.PublicURL)
	}

	// Close client to trigger cleanup
	clientConn.Close()
	time.Sleep(100 * time.Millisecond)
	s.cancel()
	s.wg.Wait()
}

// writeFailConn wraps a net.Conn and makes Write fail after a configurable number of successful writes.
type writeFailConn struct {
	net.Conn
	writesLeft int
	mu         sync.Mutex
}

func (w *writeFailConn) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.writesLeft <= 0 {
		return 0, fmt.Errorf("write blocked")
	}
	w.writesLeft--
	return w.Conn.Write(p)
}

// TestForwardHTTPRequestStreamOpenWriteError tests forwardHTTPRequest when
// the STREAM_OPEN frame write fails.
func TestForwardHTTPRequestStreamOpenWriteError(t *testing.T) {
	s := New(DefaultConfig(), nil)

	c1, c2 := net.Pipe()
	// Wrap c1 so that writes fail after 0 successful writes (immediately)
	wfc := &writeFailConn{Conn: c1, writesLeft: 0}
	m := mux.New(wfc, mux.DefaultConfig())
	// Don't run the mux read loop - we don't need it for this test

	// Drain reads on c2 so writes don't block
	go io.Copy(io.Discard, c2)

	tunnel := &Tunnel{ID: "tun-write-err", Type: proto.TunnelTypeHTTP, Subdomain: "test", SessionID: "sess-1"}
	session := &Session{ID: "sess-1", AccountID: "account-1", Mux: m}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "http://test.wirerift.dev/", nil)
	s.forwardHTTPRequest(rr, req, session, tunnel)

	if rr.Code != http.StatusBadGateway {
		t.Errorf("Expected status 502, got %d", rr.Code)
	}
	body := rr.Body.String()
	if !strings.Contains(body, "Failed to send stream open") {
		t.Errorf("Expected 'Failed to send stream open' in body, got: %s", body)
	}
	c1.Close()
	c2.Close()
}

// errorReader is a reader that always returns an error.
type errorReader struct{}

func (e *errorReader) Read(p []byte) (int, error) {
	return 0, fmt.Errorf("read error")
}

func (e *errorReader) Close() error {
	return nil
}

// TestForwardHTTPRequestSerializeError tests forwardHTTPRequest when SerializeRequest fails.
func TestForwardHTTPRequestSerializeError(t *testing.T) {
	s := New(DefaultConfig(), nil)

	c1, c2 := net.Pipe()
	m := mux.New(c1, mux.DefaultConfig())
	go m.Run()

	clientMux := mux.New(c2, mux.DefaultConfig())
	go clientMux.Run()

	tunnel := &Tunnel{ID: "tun-ser-err", Type: proto.TunnelTypeHTTP, Subdomain: "test", SessionID: "sess-1"}
	session := &Session{ID: "sess-1", AccountID: "account-1", Mux: m}

	// Drain streams on the client side
	go func() {
		for {
			stream, err := clientMux.AcceptStream()
			if err != nil {
				return
			}
			stream.Close()
		}
	}()

	rr := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "http://test.wirerift.dev/", &errorReader{})
	req.Host = "test.wirerift.dev"

	s.forwardHTTPRequest(rr, req, session, tunnel)

	if rr.Code != http.StatusInternalServerError {
		t.Errorf("Expected status 500, got %d", rr.Code)
	}
	body := rr.Body.String()
	if !strings.Contains(body, "Failed to serialize request") {
		t.Errorf("Expected 'Failed to serialize request' in body, got: %s", body)
	}

	c1.Close()
	c2.Close()
}

// TestForwardHTTPRequestStreamWriteError tests forwardHTTPRequest when stream.Write fails.
// We create a scenario where the stream is opened but the mux connection dies
// before the stream can be written to. We use forwardHTTPRequest directly,
// manually controlling when the mux connection is closed.
func TestForwardHTTPRequestStreamWriteError(t *testing.T) {
	s := New(DefaultConfig(), nil)

	c1, c2 := net.Pipe()
	m := mux.New(c1, mux.DefaultConfig())
	go m.Run()

	// Do NOT run a mux on c2 - instead, manually read frames and close c2
	// at the right time to make stream.Write fail
	go func() {
		fr := proto.NewFrameReader(c2)
		// Read the STREAM_OPEN frame that forwardHTTPRequest sends
		_, err := fr.Read()
		if err != nil {
			return
		}
		// Now close c2 so the next write (stream.Write of request data) fails
		c2.Close()
	}()

	tunnel := &Tunnel{ID: "tun-sw-err", Type: proto.TunnelTypeHTTP, Subdomain: "test", SessionID: "sess-1"}
	session := &Session{ID: "sess-1", AccountID: "account-1", Mux: m}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "http://test.wirerift.dev/", nil)
	req.Host = "test.wirerift.dev"

	s.forwardHTTPRequest(rr, req, session, tunnel)

	if rr.Code != http.StatusBadGateway {
		t.Errorf("Expected status 502, got %d", rr.Code)
	}
	body := rr.Body.String()
	if !strings.Contains(body, "Failed to write request to stream") {
		t.Errorf("Expected 'Failed to write request to stream' in body, got: %s", body)
	}

	c1.Close()
}

// TestForwardHTTPRequestReadError tests forwardHTTPRequest when reading from stream fails.
func TestForwardHTTPRequestReadError(t *testing.T) {
	s := New(DefaultConfig(), nil)

	c1, c2 := net.Pipe()
	m := mux.New(c1, mux.DefaultConfig())
	go m.Run()

	clientMux := mux.New(c2, mux.DefaultConfig())
	go clientMux.Run()

	tunnel := &Tunnel{ID: "tun-read-err", Type: proto.TunnelTypeHTTP, Subdomain: "test", SessionID: "sess-1"}
	session := &Session{ID: "sess-1", AccountID: "account-1", Mux: m}

	// Accept streams, read the request data, then reset (so ReadAll gets an error)
	go func() {
		stream, err := clientMux.AcceptStream()
		if err != nil {
			return
		}
		// Read a bit of data from the stream so Write succeeds
		buf := make([]byte, 4096)
		stream.Read(buf)
		// Reset the stream to make ReadAll fail on the server side
		stream.Reset()
	}()

	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "http://test.wirerift.dev/", nil)
	req.Host = "test.wirerift.dev"

	s.forwardHTTPRequest(rr, req, session, tunnel)

	if rr.Code != http.StatusBadGateway {
		t.Errorf("Expected status 502, got %d", rr.Code)
	}
	body := rr.Body.String()
	if !strings.Contains(body, "Failed to read response from stream") {
		t.Errorf("Expected 'Failed to read response from stream' in body, got: %s", body)
	}

	c1.Close()
	c2.Close()
}

// TestForwardHTTPRequestDeserializeError tests forwardHTTPRequest when the response cannot be deserialized.
func TestForwardHTTPRequestDeserializeError(t *testing.T) {
	s := New(DefaultConfig(), nil)

	c1, c2 := net.Pipe()
	m := mux.New(c1, mux.DefaultConfig())
	go m.Run()

	clientMux := mux.New(c2, mux.DefaultConfig())
	go clientMux.Run()

	tunnel := &Tunnel{ID: "tun-deser-err", Type: proto.TunnelTypeHTTP, Subdomain: "test", SessionID: "sess-1"}
	session := &Session{ID: "sess-1", AccountID: "account-1", Mux: m}

	// Accept streams, read the request, send invalid HTTP response data
	go func() {
		stream, err := clientMux.AcceptStream()
		if err != nil {
			return
		}
		// Read the HTTP request from the stream
		reader := bufio.NewReader(stream)
		httpReq, err := http.ReadRequest(reader)
		if err != nil {
			stream.Close()
			return
		}
		httpReq.Body.Close()

		// Write invalid response data (not a valid HTTP response)
		stream.Write([]byte("not a valid http response"))
		stream.Close()
	}()

	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "http://test.wirerift.dev/", nil)
	req.Host = "test.wirerift.dev"

	s.forwardHTTPRequest(rr, req, session, tunnel)

	if rr.Code != http.StatusBadGateway {
		t.Errorf("Expected status 502, got %d", rr.Code)
	}
	body := rr.Body.String()
	if !strings.Contains(body, "Failed to deserialize response") {
		t.Errorf("Expected 'Failed to deserialize response' in body, got: %s", body)
	}

	c1.Close()
	c2.Close()
}
