package server

// Regression test for the server-side heartbeat keepalive. In production
// only the client sends HEARTBEAT pings (client.go heartbeat loop); the
// server mux answers each ping with an ACK but never sends pings itself,
// so it never receives an ACK. Mux.lastHeartbeat was only recorded on ACK,
// which left the server's LastHeartbeat() permanently zero and the
// keepalive branch in handleTunnelRequests dead — session cleanup then
// killed healthy, idle-but-pinging tunnels after SessionTimeout, while the
// client's dead-peer detection (driven by those ACKs) believed the link
// was perfectly healthy. The comment on handleTunnelRequests states the
// intent: heartbeat traffic must keep session.LastSeen fresh so cleanup
// does not kill active tunnels.

import (
	"net"
	"testing"
	"time"

	"github.com/wirerift/wirerift/internal/mux"
	"github.com/wirerift/wirerift/internal/proto"
)

func TestHeartbeatTrafficKeepsIdleSessionAlive(t *testing.T) {
	cfg := DefaultConfig()
	cfg.SessionTimeout = 150 * time.Millisecond // cleanup kills at 150ms idle
	cfg.HeartbeatInterval = 40 * time.Millisecond
	s := New(cfg, nil)

	// Real mux pair over net.Pipe: clientMux plays the client (sends
	// heartbeat pings), serverMux plays the server side of the session.
	c1, c2 := net.Pipe()
	defer c2.Close()
	clientMux := mux.New(c1, mux.DefaultConfig())
	serverMux := mux.New(c2, mux.DefaultConfig())
	go clientMux.Run()
	go serverMux.Run()
	defer clientMux.Close()
	defer serverMux.Close()

	// Production ping loop (mirrors client.go heartbeatLoop).
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		ticker := time.NewTicker(20 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				frame := &proto.Frame{
					Version:  proto.Version,
					Type:     proto.FrameHeartbeat,
					StreamID: 0,
					Payload:  proto.HeartbeatPayload(),
				}
				clientMux.GetFrameWriter().Write(frame)
			}
		}
	}()

	// Live session registered as pings start.
	session := &Session{
		ID:        "sess-live-ping",
		AccountID: "account-1",
		Mux:       serverMux,
		Tunnels:   make(map[string]*Tunnel),
		CreatedAt: time.Now(),
		LastSeen:  time.Now(),
	}
	s.sessions.Store("sess-live-ping", session)

	// Production keepalive loop for the session.
	loopDone := make(chan struct{})
	go func() {
		s.handleTunnelRequests(serverMux, session)
		close(loopDone)
	}()
	defer func() {
		serverMux.Close()
		select {
		case <-loopDone:
		case <-time.After(2 * time.Second):
		}
	}()

	// Control session: no traffic at all, stale from the start.
	deadSession := &Session{
		ID:        "sess-dead",
		AccountID: "account-1",
		Mux:       serverMux,
		Tunnels:   make(map[string]*Tunnel),
		CreatedAt: time.Now().Add(-time.Hour),
		LastSeen:  time.Now().Add(-time.Hour),
	}
	s.sessions.Store("sess-dead", deadSession)

	// Let several cleanup periods pass (cleanup interval is SessionTimeout/2).
	time.Sleep(600 * time.Millisecond)

	// Control: the no-traffic session must be cleaned up.
	s.cleanupInactiveSessions()
	if _, ok := s.getSession("sess-dead"); ok {
		t.Error("control: session without any traffic should have been cleaned up")
	}

	// The live-pinging session must survive: its heartbeats keep LastSeen fresh.
	s.cleanupInactiveSessions()
	if _, ok := s.getSession("sess-live-ping"); !ok {
		t.Fatal("FAIL: session with live heartbeat traffic was killed by session cleanup — " +
			"the server-side keepalive never fires because mux records lastHeartbeat only " +
			"on HEARTBEAT_ACK, which the server never receives (only the client sends pings)")
	}
}
