package client

import (
	"net"
	"testing"
	"time"

	"github.com/wirerift/wirerift/internal/mux"
)

func TestStaleHeartbeatCannotDisconnectReplacement(t *testing.T) {
	oldA, oldB := net.Pipe()
	defer oldB.Close()
	oldMux := mux.New(oldA, mux.DefaultConfig())
	_ = oldMux.Close()

	newA, newB := net.Pipe()
	defer newA.Close()
	defer newB.Close()
	newMux := mux.New(newA, mux.DefaultConfig())
	c := New(DefaultConfig(), nil)
	c.connMu.Lock()
	c.mux = newMux
	c.connMu.Unlock()
	c.connected.Store(true)

	c.heartbeatLoop(oldMux)
	if !c.connected.Load() {
		t.Fatal("stale heartbeat loop marked the replacement connection disconnected")
	}
}

func TestTCPRelayAbortsLocalSocketWhenMuxFails(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	a, b := net.Pipe()
	defer b.Close()
	m := mux.New(a, mux.DefaultConfig())
	stream, err := m.OpenStream()
	if err != nil {
		t.Fatal(err)
	}
	stream.SetMetadata("", "tcp", "tun")
	c := New(DefaultConfig(), nil)
	c.tunnels.Store("tun", &Tunnel{ID: "tun", LocalAddr: ln.Addr().String(), client: c})
	done := make(chan struct{})
	go func() { c.handleTCPStream(stream); close(done) }()

	local, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer local.Close()
	_ = m.Close()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("TCP relay remained blocked on a silent local peer after mux failure")
	}
}
