package mux

// Regression test for heartbeat liveness tracking. Mux.lastHeartbeat must
// advance when a HEARTBEAT ping is received, not only on HEARTBEAT_ACK: in
// this protocol only the client sends pings, so a mux that recorded liveness
// solely from ACKs never advanced on the server side, and session cleanup
// killed healthy idle tunnels. See internal/server/heartbeat_keepalive_test.go
// for the end-to-end session-survival case.

import (
	"testing"
	"time"

	"github.com/wirerift/wirerift/internal/proto"
)

func TestLastHeartbeatAdvancesOnPing(t *testing.T) {
	client, server := newTestPipe(t)
	defer client.Close()
	defer server.Close()
	// Drain the pipe from the client end so the server's synchronous ACK
	// write inside handleFrame can complete (net.Pipe is unbuffered).
	go client.Run()
	if !server.LastHeartbeat().IsZero() {
		t.Fatal("LastHeartbeat should be zero before any heartbeat traffic")
	}

	// A HEARTBEAT ping arriving at the mux (the server's steady-state input)
	// must record liveness.
	ping := &proto.Frame{
		Version:  proto.Version,
		Type:     proto.FrameHeartbeat,
		StreamID: 0,
		Payload:  proto.HeartbeatPayload(),
	}
	if err := server.handleFrame(ping); err != nil {
		t.Fatalf("handleFrame(ping): %v", err)
	}

	hb := server.LastHeartbeat()
	if hb.IsZero() {
		t.Fatal("FAIL: LastHeartbeat still zero after receiving a HEARTBEAT ping")
	}
	if time.Since(hb) > 5*time.Second {
		t.Fatalf("LastHeartbeat = %v, want a recent timestamp", hb)
	}
}
