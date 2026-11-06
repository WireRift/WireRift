package client

import (
	"bufio"
	"errors"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/wirerift/wirerift/internal/mux"
	"github.com/wirerift/wirerift/internal/proto"
)

func TestClientRejectsSecondConnect(t *testing.T) {
	server := newMockServer(t)
	defer server.Close()
	cfg := DefaultConfig()
	cfg.ServerAddr = server.addr
	cfg.Token = server.token
	cfg.Reconnect = false
	cfg.HeartbeatInterval = time.Hour
	c := New(cfg, nil)
	if err := c.Connect(); err != nil {
		t.Fatalf("control: first Connect failed: %v", err)
	}
	if !c.IsConnected() {
		t.Fatal("control: first Connect did not publish connected state")
	}
	firstMux := c.currentMux()
	c.connMu.RLock()
	firstConn := c.conn
	c.connMu.RUnlock()

	if err := c.Connect(); err == nil {
		// Pre-fix cleanup: both generations must be closed explicitly because
		// the second Connect overwrote the only published owner pointers.
		secondMux := c.currentMux()
		c.connMu.RLock()
		secondConn := c.conn
		c.connMu.RUnlock()
		c.cancel()
		_ = firstMux.Close()
		_ = firstConn.Close()
		_ = secondMux.Close()
		_ = secondConn.Close()
		done := make(chan struct{})
		go func() { c.wg.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Fatal("second Connect was accepted and orphaned a mux goroutine")
		}
		t.Fatal("second Connect was accepted; expected a lifecycle error")
	}
	if err := c.Close(); err != nil {
		t.Fatalf("Close after rejected second Connect: %v", err)
	}
}

func TestClientCanRetryConnectAfterFailure(t *testing.T) {
	server := newMockServer(t)
	defer server.Close()
	cfg := DefaultConfig()
	cfg.ServerAddr = server.addr
	cfg.Token = "wrong-token"
	cfg.Reconnect = false
	c := New(cfg, nil)
	if err := c.Connect(); !errors.Is(err, ErrAuthFailed) {
		t.Fatalf("first Connect error = %v, want ErrAuthFailed", err)
	}
	c.config.Token = server.token
	if err := c.Connect(); err != nil {
		t.Fatalf("retry after failed Connect: %v", err)
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestCloseWinsOverInFlightConnect(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	authSeen := make(chan struct{})
	releaseResponse := make(chan struct{})
	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		if err := proto.ReadMagic(conn); err != nil {
			return
		}
		serverMux := mux.New(conn, mux.DefaultConfig())
		go serverMux.Run()
		select {
		case frame := <-serverMux.ControlFrame():
			if frame.Type != proto.FrameAuthReq {
				return
			}
			close(authSeen)
		case <-serverMux.Done():
			return
		}
		<-releaseResponse
		response, _ := proto.EncodeJSONPayload(proto.FrameAuthRes, proto.ControlStreamID, &proto.AuthResponse{
			OK: true, SessionID: "stale-session", MaxTunnels: 10,
		})
		_ = serverMux.GetFrameWriter().Write(response)
		_ = serverMux.Close()
	}()

	cfg := DefaultConfig()
	cfg.ServerAddr = listener.Addr().String()
	cfg.Token = "token"
	cfg.Reconnect = false
	c := New(cfg, nil)
	connectDone := make(chan error, 1)
	go func() { connectDone <- c.Connect() }()
	select {
	case <-authSeen:
	case <-time.After(2 * time.Second):
		t.Fatal("Connect did not reach gated authentication")
	}
	closeDone := make(chan error, 1)
	go func() { closeDone <- c.Close() }()
	select {
	case err := <-closeDone:
		if err != nil {
			t.Fatalf("Close during Connect: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Close did not cancel the in-flight Connect")
	}
	close(releaseResponse)
	if err := <-connectDone; err == nil {
		t.Fatal("stale Connect published after Close won the lifecycle")
	}
	if c.IsConnected() {
		t.Fatal("client remained connected after Close won")
	}
	if err := c.Connect(); err == nil {
		t.Fatal("closed client accepted a later Connect")
	}
	<-serverDone
}

func TestReconnectCloseOwnership(t *testing.T) {
	t.Run("control reconnect publishes replacement", func(t *testing.T) {
		c, old, release, done := startGatedTunnelRecreate(t)
		close(release)
		<-done
		value, ok := c.tunnels.Load("replacement")
		if !ok {
			t.Fatal("control: an open tunnel was not re-created")
		}
		if value != old || old.ID != "replacement" {
			t.Fatalf("reconnect replaced the caller's handle instead of advancing it: value=%p old=%p id=%q", value, old, old.ID)
		}
		if err := old.Close(); err != nil {
			t.Fatalf("close stable replacement handle: %v", err)
		}
		if _, ok := c.tunnels.Load("replacement"); ok {
			t.Fatal("stable handle Close left replacement registered")
		}
		_ = c.currentMux().Close()
		if c.conn != nil {
			_ = c.conn.Close()
		}
		_ = old
	})

	t.Run("close wins over stale recreate response", func(t *testing.T) {
		c, old, release, done := startGatedTunnelRecreate(t)
		if err := old.Close(); err != nil {
			t.Fatalf("close old tunnel while recreation is pending: %v", err)
		}
		close(release)
		<-done
		var active []string
		c.tunnels.Range(func(key, _ any) bool {
			active = append(active, key.(string))
			return true
		})
		if len(active) != 0 {
			t.Fatalf("closed tunnel was resurrected by stale reconnect response; active=%v", active)
		}
		if err := old.Close(); err != nil {
			t.Fatalf("repeated Tunnel.Close should be idempotent: %v", err)
		}
		_ = c.currentMux().Close()
		if c.conn != nil {
			_ = c.conn.Close()
		}
	})
}

func startGatedTunnelRecreate(t *testing.T) (*Client, *Tunnel, chan struct{}, chan struct{}) {
	t.Helper()
	c, serverMux := makeConnectedClient(t)
	old := &Tunnel{
		ID:        "original",
		Type:      proto.TunnelTypeHTTP,
		LocalAddr: "localhost:8080",
		client:    c,
		request: &proto.TunnelRequest{
			Type:      proto.TunnelTypeHTTP,
			LocalAddr: "localhost:8080",
		},
	}
	c.tunnels.Store(old.ID, old)
	requestSeen := make(chan struct{})
	release := make(chan struct{})
	serverErr := make(chan error, 1)
	go func() {
		select {
		case frame := <-serverMux.ControlFrame():
			if frame.Type != proto.FrameTunnelReq {
				serverErr <- errors.New("first control frame was not TUNNEL_REQ")
				return
			}
			close(requestSeen)
		case <-serverMux.Done():
			serverErr <- errors.New("server mux closed before tunnel request")
			return
		}
		<-release
		response, _ := proto.EncodeJSONPayload(proto.FrameTunnelRes, proto.ControlStreamID, &proto.TunnelResponse{
			OK:        true,
			TunnelID:  "replacement",
			Type:      proto.TunnelTypeHTTP,
			PublicURL: "https://replacement.example",
		})
		serverErr <- serverMux.GetFrameWriter().Write(response)
	}()
	done := make(chan struct{})
	go func() {
		c.recreateTunnels()
		close(done)
	}()
	select {
	case <-requestSeen:
	case err := <-serverErr:
		t.Fatalf("gated recreate setup: %v", err)
	case <-time.After(2 * time.Second):
		t.Fatal("gated recreate did not send request")
	}
	t.Cleanup(func() {
		select {
		case err := <-serverErr:
			if err != nil {
				t.Errorf("recreate responder: %v", err)
			}
		default:
		}
		_ = serverMux.Close()
	})
	return c, old, release, done
}

func TestCloseOwnsActiveHTTPHandlers(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	accepted := make(chan net.Conn, 1)
	serverErr := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			serverErr <- err
			return
		}
		if _, err := http.ReadRequest(bufio.NewReader(conn)); err != nil {
			_ = conn.Close()
			serverErr <- err
			return
		}
		accepted <- conn
	}()

	clientConn, serverConn := net.Pipe()
	clientMux := mux.New(clientConn, mux.DefaultConfig())
	serverMux := mux.New(serverConn, mux.DefaultConfig())
	c := New(DefaultConfig(), nil)
	c.connMu.Lock()
	c.conn, c.mux = clientConn, clientMux
	c.connMu.Unlock()
	c.connected.Store(true)
	c.tunnels.Store("http-tunnel", &Tunnel{
		ID:        "http-tunnel",
		Type:      proto.TunnelTypeHTTP,
		LocalAddr: ln.Addr().String(),
		client:    c,
	})
	c.wg.Add(2)
	go func() { defer c.wg.Done(); _ = clientMux.Run() }()
	go func() { defer c.wg.Done(); c.handleStreams(clientMux) }()
	go serverMux.Run()

	stream, err := serverMux.OpenStream()
	if err != nil {
		t.Fatal(err)
	}
	open, _ := proto.EncodeJSONPayload(proto.FrameStreamOpen, stream.ID(), &proto.StreamOpen{
		Protocol: "http",
		TunnelID: "http-tunnel",
	})
	if err := serverMux.GetFrameWriter().Write(open); err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(stream, "GET / HTTP/1.1\r\nHost: local\r\nConnection: close\r\n\r\n"); err != nil {
		t.Fatal(err)
	}

	var local net.Conn
	select {
	case local = <-accepted:
	case err := <-serverErr:
		t.Fatalf("local HTTP control failed: %v", err)
	case <-time.After(2 * time.Second):
		t.Fatal("client did not forward the HTTP request to the local service")
	}
	defer local.Close()
	var tracked *trackedLocalConn
	c.localConns.Range(func(key, _ any) bool {
		tracked = key.(*trackedLocalConn)
		return false
	})
	if tracked == nil {
		t.Fatal("forwarded request did not register its local transport connection")
	}

	if err := c.Close(); err != nil {
		t.Fatalf("Client.Close: %v", err)
	}
	afterClose := 0
	c.localConns.Range(func(_, _ any) bool { afterClose++; return true })
	if afterClose != 0 {
		t.Fatalf("Client.Close left %d tracked local HTTP connections", afterClose)
	}
	if _, err := tracked.Write([]byte("after-close")); err == nil {
		t.Fatal("tracked local connection remained writable after Client.Close")
	}
	_ = serverMux.Close()
}
