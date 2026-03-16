package integration

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/wirerift/wirerift/internal/auth"
	"github.com/wirerift/wirerift/internal/client"
	"github.com/wirerift/wirerift/internal/server"
)

// TestEndToEndHTTPTunnel tests the complete HTTP tunnel flow:
// local service <- client <- mux <- server <- edge HTTP request
func TestEndToEndHTTPTunnel(t *testing.T) {
	// 1. Start a local HTTP service (simulates user's app)
	localService := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Test", "wirerift")
		w.WriteHeader(200)
		fmt.Fprintf(w, "Hello from %s %s", r.Method, r.URL.Path)
	}))
	defer localService.Close()

	// 2. Start the tunnel server
	authMgr := auth.NewManager()
	srvCfg := server.DefaultConfig()
	srvCfg.ControlAddr = "127.0.0.1:0"
	srvCfg.HTTPAddr = "127.0.0.1:0"
	srvCfg.AuthManager = authMgr

	srv := server.New(srvCfg, nil)
	if err := srv.Start(); err != nil {
		t.Fatalf("Server start: %v", err)
	}
	defer srv.Stop()

	// Get the actual control address
	controlAddr := srv.ControlAddr()

	// 3. Connect a client
	clientCfg := client.DefaultConfig()
	clientCfg.ServerAddr = controlAddr
	clientCfg.Token = authMgr.DevToken()
	clientCfg.Reconnect = false

	c := client.New(clientCfg, nil)
	if err := c.Connect(); err != nil {
		t.Fatalf("Client connect: %v", err)
	}
	defer c.Close()

	// 4. Create an HTTP tunnel pointing to local service
	localAddr := strings.TrimPrefix(localService.URL, "http://")
	tunnel, err := c.HTTP(localAddr, client.WithSubdomain("e2etest"))
	if err != nil {
		t.Fatalf("Create HTTP tunnel: %v", err)
	}

	t.Logf("Tunnel created: %s -> %s", tunnel.PublicURL, localAddr)

	// 5. Send an HTTP request through the edge (server's HTTP listener)
	httpAddr := srv.HTTPAddr()
	req, _ := http.NewRequest("GET", fmt.Sprintf("http://%s/hello?foo=bar", httpAddr), nil)
	req.Host = fmt.Sprintf("e2etest.%s", srvCfg.Domain)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Edge HTTP request: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != 200 {
		t.Errorf("Status = %d, want 200. Body: %s", resp.StatusCode, body)
	}
	if !strings.Contains(string(body), "Hello from GET /hello") {
		t.Errorf("Body = %q, want to contain 'Hello from GET /hello'", body)
	}
	if resp.Header.Get("X-Test") != "wirerift" {
		t.Errorf("X-Test header = %q, want 'wirerift'", resp.Header.Get("X-Test"))
	}

	t.Logf("E2E HTTP tunnel test passed! Response: %s", body)
}

// TestEndToEndTCPTunnel tests the complete TCP tunnel flow.
func TestEndToEndTCPTunnel(t *testing.T) {
	// 1. Start a local TCP echo server
	echoListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
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
				buf := make([]byte, 1024)
				for {
					n, err := conn.Read(buf)
					if err != nil {
						return
					}
					conn.Write(buf[:n])
				}
			}()
		}
	}()

	// 2. Start the tunnel server
	authMgr := auth.NewManager()
	srvCfg := server.DefaultConfig()
	srvCfg.ControlAddr = "127.0.0.1:0"
	srvCfg.HTTPAddr = "127.0.0.1:0"
	srvCfg.AuthManager = authMgr

	srv := server.New(srvCfg, nil)
	if err := srv.Start(); err != nil {
		t.Fatalf("Server start: %v", err)
	}
	defer srv.Stop()

	controlAddr := srv.ControlAddr()

	// 3. Connect a client
	clientCfg := client.DefaultConfig()
	clientCfg.ServerAddr = controlAddr
	clientCfg.Token = authMgr.DevToken()
	clientCfg.Reconnect = false

	c := client.New(clientCfg, nil)
	if err := c.Connect(); err != nil {
		t.Fatalf("Client connect: %v", err)
	}
	defer c.Close()

	// 4. Create a TCP tunnel
	localAddr := echoListener.Addr().String()
	tunnel, err := c.TCP(localAddr, 0)
	if err != nil {
		t.Fatalf("Create TCP tunnel: %v", err)
	}

	t.Logf("TCP tunnel created: %s -> %s", tunnel.PublicURL, localAddr)

	// Give the TCP tunnel listener time to start
	time.Sleep(200 * time.Millisecond)

	// 5. Connect to the TCP tunnel port and send data
	// Extract port from PublicURL (format: "tcp://domain:port")
	tunnelPort := tunnel.Port
	if tunnelPort == 0 {
		// Parse from PublicURL
		parts := strings.Split(tunnel.PublicURL, ":")
		if len(parts) >= 3 {
			fmt.Sscanf(parts[2], "%d", &tunnelPort)
		}
	}

	tcpConn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", tunnelPort), 5*time.Second)
	if err != nil {
		t.Fatalf("Connect to TCP tunnel: %v", err)
	}
	defer tcpConn.Close()

	// Send data and verify echo
	testData := "Hello TCP Tunnel!"
	tcpConn.Write([]byte(testData))
	tcpConn.SetReadDeadline(time.Now().Add(5 * time.Second))

	buf := make([]byte, 1024)
	n, err := tcpConn.Read(buf)
	if err != nil {
		t.Fatalf("Read from TCP tunnel: %v", err)
	}

	if string(buf[:n]) != testData {
		t.Errorf("TCP echo = %q, want %q", string(buf[:n]), testData)
	}

	t.Logf("E2E TCP tunnel test passed! Echoed: %s", string(buf[:n]))
}

// TestMultipleTunnels tests creating multiple tunnels on one connection.
func TestMultipleTunnels(t *testing.T) {
	authMgr := auth.NewManager()
	srvCfg := server.DefaultConfig()
	srvCfg.ControlAddr = "127.0.0.1:0"
	srvCfg.HTTPAddr = "127.0.0.1:0"
	srvCfg.AuthManager = authMgr

	srv := server.New(srvCfg, nil)
	if err := srv.Start(); err != nil {
		t.Fatalf("Server start: %v", err)
	}
	defer srv.Stop()

	clientCfg := client.DefaultConfig()
	clientCfg.ServerAddr = srv.ControlAddr()
	clientCfg.Token = authMgr.DevToken()
	clientCfg.Reconnect = false

	c := client.New(clientCfg, nil)
	if err := c.Connect(); err != nil {
		t.Fatalf("Client connect: %v", err)
	}
	defer c.Close()

	// Create multiple HTTP tunnels
	tunnel1, err := c.HTTP("localhost:3001")
	if err != nil {
		t.Fatalf("Create tunnel 1: %v", err)
	}
	tunnel2, err := c.HTTP("localhost:3002")
	if err != nil {
		t.Fatalf("Create tunnel 2: %v", err)
	}

	if tunnel1.ID == tunnel2.ID {
		t.Error("Tunnels should have different IDs")
	}

	t.Logf("Multiple tunnels: %s, %s", tunnel1.PublicURL, tunnel2.PublicURL)
}

// TestClientReconnect tests that client can reconnect after disconnect.
func TestClientReconnect(t *testing.T) {
	authMgr := auth.NewManager()
	srvCfg := server.DefaultConfig()
	srvCfg.ControlAddr = "127.0.0.1:0"
	srvCfg.HTTPAddr = "127.0.0.1:0"
	srvCfg.AuthManager = authMgr

	srv := server.New(srvCfg, nil)
	if err := srv.Start(); err != nil {
		t.Fatalf("Server start: %v", err)
	}
	defer srv.Stop()

	// First connection
	clientCfg := client.DefaultConfig()
	clientCfg.ServerAddr = srv.ControlAddr()
	clientCfg.Token = authMgr.DevToken()
	clientCfg.Reconnect = false

	c1 := client.New(clientCfg, nil)
	if err := c1.Connect(); err != nil {
		t.Fatalf("First connect: %v", err)
	}

	session1 := c1.SessionID()
	c1.Close()

	// Second connection
	c2 := client.New(clientCfg, nil)
	if err := c2.Connect(); err != nil {
		t.Fatalf("Second connect: %v", err)
	}
	defer c2.Close()

	session2 := c2.SessionID()

	if session1 == session2 {
		t.Error("Different connections should have different session IDs")
	}

	t.Logf("Reconnect: session1=%s, session2=%s", session1, session2)
}

// TestFixedTokenAuth tests that a user-specified token works for auth.
func TestFixedTokenAuth(t *testing.T) {
	myToken := "my-super-secret-token-12345"

	// Server with fixed token
	authMgr := auth.NewManager(myToken)
	if authMgr.DevToken() != myToken {
		t.Fatalf("DevToken = %q, want %q", authMgr.DevToken(), myToken)
	}

	srvCfg := server.DefaultConfig()
	srvCfg.ControlAddr = "127.0.0.1:0"
	srvCfg.HTTPAddr = "127.0.0.1:0"
	srvCfg.AuthManager = authMgr

	srv := server.New(srvCfg, nil)
	if err := srv.Start(); err != nil {
		t.Fatalf("Server start: %v", err)
	}
	defer srv.Stop()

	// Client connects with same fixed token
	clientCfg := client.DefaultConfig()
	clientCfg.ServerAddr = srv.ControlAddr()
	clientCfg.Token = myToken
	clientCfg.Reconnect = false

	c := client.New(clientCfg, nil)
	if err := c.Connect(); err != nil {
		t.Fatalf("Connect with fixed token failed: %v", err)
	}
	defer c.Close()

	if !c.IsConnected() {
		t.Error("Client should be connected")
	}

	// Create tunnel to verify full auth flow
	tunnel, err := c.HTTP("localhost:9999", client.WithSubdomain("fixedtoken"))
	if err != nil {
		t.Fatalf("Create tunnel: %v", err)
	}
	if tunnel.PublicURL == "" {
		t.Error("Tunnel should have a public URL")
	}

	t.Logf("Fixed token auth works: session=%s, tunnel=%s", c.SessionID(), tunnel.PublicURL)
}

// TestWrongTokenRejected tests that wrong token is rejected.
func TestWrongTokenRejected(t *testing.T) {
	authMgr := auth.NewManager("correct-token")

	srvCfg := server.DefaultConfig()
	srvCfg.ControlAddr = "127.0.0.1:0"
	srvCfg.HTTPAddr = "127.0.0.1:0"
	srvCfg.AuthManager = authMgr

	srv := server.New(srvCfg, nil)
	if err := srv.Start(); err != nil {
		t.Fatalf("Server start: %v", err)
	}
	defer srv.Stop()

	// Client with wrong token
	clientCfg := client.DefaultConfig()
	clientCfg.ServerAddr = srv.ControlAddr()
	clientCfg.Token = "wrong-token"
	clientCfg.Reconnect = false

	c := client.New(clientCfg, nil)
	err := c.Connect()
	if err == nil {
		c.Close()
		t.Fatal("Expected auth failure with wrong token")
	}
	if !strings.Contains(err.Error(), "authentication failed") {
		t.Errorf("Expected 'authentication failed' error, got: %v", err)
	}

	t.Logf("Wrong token correctly rejected: %v", err)
}

// TestEndToEndHTTPTunnelWithFixedToken tests the complete flow with a user-specified token.
func TestEndToEndHTTPTunnelWithFixedToken(t *testing.T) {
	fixedToken := "e2e-test-token-abc123"

	// Local service
	localService := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("hello from fixed-token tunnel"))
	}))
	defer localService.Close()

	// Server
	authMgr := auth.NewManager(fixedToken)
	srvCfg := server.DefaultConfig()
	srvCfg.ControlAddr = "127.0.0.1:0"
	srvCfg.HTTPAddr = "127.0.0.1:0"
	srvCfg.AuthManager = authMgr

	srv := server.New(srvCfg, nil)
	if err := srv.Start(); err != nil {
		t.Fatalf("Server start: %v", err)
	}
	defer srv.Stop()

	// Client
	clientCfg := client.DefaultConfig()
	clientCfg.ServerAddr = srv.ControlAddr()
	clientCfg.Token = fixedToken
	clientCfg.Reconnect = false

	c := client.New(clientCfg, nil)
	if err := c.Connect(); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer c.Close()

	// Tunnel
	localAddr := strings.TrimPrefix(localService.URL, "http://")
	tunnel, err := c.HTTP(localAddr, client.WithSubdomain("tokentest"))
	if err != nil {
		t.Fatalf("Create tunnel: %v", err)
	}

	// Request through edge
	req, _ := http.NewRequest("GET", fmt.Sprintf("http://%s/", srv.HTTPAddr()), nil)
	req.Host = fmt.Sprintf("tokentest.%s", srvCfg.Domain)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Edge request: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != 200 {
		t.Errorf("Status = %d, want 200", resp.StatusCode)
	}
	if string(body) != "hello from fixed-token tunnel" {
		t.Errorf("Body = %q", body)
	}

	t.Logf("E2E with fixed token passed: %s -> %s -> %s", tunnel.PublicURL, localAddr, string(body))
}
