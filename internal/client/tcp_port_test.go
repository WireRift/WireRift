package client

import (
	"net"
	"sync"
	"testing"
	"time"

	"github.com/wirerift/wirerift/internal/mux"
	"github.com/wirerift/wirerift/internal/proto"
)

// portServer is a tiny control server for TCP tunnel requests: it hands out
// ports from a list, and can refuse a requested port as taken.
type portServer struct {
	ln net.Listener

	mu       sync.Mutex
	requests []proto.TunnelRequest
	assign   []int        // ports given to requests that ask for port 0, in order
	taken    map[int]bool // requested ports refused with "port already taken"
	conns    []net.Conn
}

func newPortServer(t *testing.T, assign []int) *portServer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ps := &portServer{ln: ln, assign: assign, taken: map[int]bool{}}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			ps.mu.Lock()
			ps.conns = append(ps.conns, c)
			ps.mu.Unlock()
			go ps.handle(c)
		}
	}()
	return ps
}

func (ps *portServer) handle(conn net.Conn) {
	defer conn.Close()
	magic := make([]byte, 4)
	if _, err := conn.Read(magic); err != nil {
		return
	}
	m := mux.New(conn, mux.DefaultConfig())
	go m.Run()
	for {
		select {
		case f, ok := <-m.ControlFrame():
			if !ok {
				return
			}
			switch f.Type {
			case proto.FrameAuthReq:
				out, _ := proto.EncodeJSONPayload(proto.FrameAuthRes, proto.ControlStreamID, &proto.AuthResponse{OK: true, SessionID: "s", MaxTunnels: 10})
				_ = m.GetFrameWriter().Write(out)
			case proto.FrameTunnelReq:
				var req proto.TunnelRequest
				if proto.DecodeJSONPayload(f, &req) != nil {
					return
				}
				ps.mu.Lock()
				ps.requests = append(ps.requests, req)
				res := &proto.TunnelResponse{OK: true, TunnelID: "t" + time.Now().Format("150405.000000"), Type: req.Type}
				switch {
				case req.RemotePort != 0 && ps.taken[req.RemotePort]:
					res = &proto.TunnelResponse{OK: false, Error: "port already taken"}
				case req.RemotePort != 0:
					res.Port = req.RemotePort
				default:
					res.Port, ps.assign = ps.assign[0], ps.assign[1:]
				}
				if res.OK {
					res.PublicURL = "tcp://t.example:" + itoa(res.Port)
				}
				ps.mu.Unlock()
				out, _ := proto.EncodeJSONPayload(proto.FrameTunnelRes, proto.ControlStreamID, res)
				_ = m.GetFrameWriter().Write(out)
			}
		case <-m.Done():
			return
		}
	}
}

// portOf reads a tunnel's port under its lock: a reconnect rewrites it.
func portOf(t *Tunnel) int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.Port
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

func (ps *portServer) dropConnections() {
	ps.mu.Lock()
	defer ps.mu.Unlock()
	for _, c := range ps.conns {
		c.Close()
	}
	ps.conns = nil
}

func (ps *portServer) requestLog() []proto.TunnelRequest {
	ps.mu.Lock()
	defer ps.mu.Unlock()
	return append([]proto.TunnelRequest(nil), ps.requests...)
}

func waitUntil(t *testing.T, cond func() bool, what string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func newPortClient(t *testing.T, ps *portServer) *Client {
	t.Helper()
	cfg := DefaultConfig()
	cfg.ServerAddr = ps.ln.Addr().String()
	cfg.Token = "x"
	cfg.ReconnectInterval = 20 * time.Millisecond
	cfg.HeartbeatInterval = time.Hour
	c := New(cfg, nil)
	if err := c.Connect(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

func TestTCPReconnectAsksForThePreviousPort(t *testing.T) {
	ps := newPortServer(t, []int{20005, 20006})
	c := newPortClient(t, ps)
	tun, err := c.TCP("127.0.0.1:1", 0)
	if err != nil {
		t.Fatal(err)
	}
	if portOf(tun) != 20005 {
		t.Fatalf("assigned port %d, want 20005", portOf(tun))
	}

	ps.dropConnections()
	waitUntil(t, func() bool { return len(ps.requestLog()) >= 2 }, "the re-creation request")
	second := ps.requestLog()[1]
	if second.RemotePort != 20005 || !second.Reconnect {
		t.Errorf("reconnect request = %+v, want RemotePort 20005 with Reconnect", second)
	}
	waitUntil(t, func() bool { return c.IsConnected() && portOf(tun) == 20005 }, "the tunnel to come back on the same port")
	if got := len(ps.requestLog()); got != 2 {
		t.Errorf("%d requests, want exactly the original and one re-creation", got)
	}
}

func TestTCPReconnectSettlesForNewPortWhenTaken(t *testing.T) {
	old := tunnelRetryBase
	tunnelRetryBase = time.Millisecond
	defer func() { tunnelRetryBase = old }()

	ps := newPortServer(t, []int{20005, 20009})
	c := newPortClient(t, ps)
	tun, err := c.TCP("127.0.0.1:1", 0)
	if err != nil {
		t.Fatal(err)
	}
	ps.mu.Lock()
	ps.taken[20005] = true // someone else got it while the client was away
	ps.mu.Unlock()

	ps.dropConnections()
	waitUntil(t, func() bool { return portOf(tun) == 20009 }, "the tunnel to settle for a new port")
	reqs := ps.requestLog()
	last := reqs[len(reqs)-1]
	if last.RemotePort != 0 || !last.Reconnect {
		t.Errorf("fallback request = %+v, want RemotePort 0", last)
	}
	pinned := 0
	for _, r := range reqs[1 : len(reqs)-1] {
		if r.RemotePort == 20005 {
			pinned++
		}
	}
	if pinned == 0 {
		t.Error("the client never tried the previous port first")
	}
}

func TestExplicitTCPPortIsNotRewritten(t *testing.T) {
	old := tunnelRetryBase
	tunnelRetryBase = time.Millisecond
	defer func() { tunnelRetryBase = old }()

	ps := newPortServer(t, []int{20011})
	c := newPortClient(t, ps)
	tun, err := c.TCP("127.0.0.1:1", 20020) // the user asked for this port
	if err != nil {
		t.Fatal(err)
	}
	if portOf(tun) != 20020 {
		t.Fatalf("port %d, want 20020", portOf(tun))
	}
	ps.mu.Lock()
	ps.taken[20020] = true
	ps.mu.Unlock()
	ps.dropConnections()
	waitUntil(t, func() bool { return len(ps.requestLog()) >= 3 }, "retries of the requested port")
	for _, r := range ps.requestLog()[1:] {
		if r.RemotePort != 20020 {
			t.Fatalf("a port the user asked for was replaced by %d", r.RemotePort)
		}
	}
	if portOf(tun) != 20020 {
		t.Errorf("port changed to %d", portOf(tun))
	}
}
