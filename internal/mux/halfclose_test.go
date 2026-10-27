package mux

import (
	"net"
	"testing"
	"time"

	"github.com/wirerift/wirerift/internal/proto"
)

func halfClosePair(t *testing.T, timeout time.Duration) (*Stream, *Stream) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	acc := make(chan net.Conn, 1)
	go func() { c, _ := ln.Accept(); acc <- c }()
	c1, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	c2 := <-acc
	cfg := DefaultConfig()
	cfg.HalfCloseTimeout = timeout
	client, server := New(c1, cfg), New(c2, DefaultConfig())
	t.Cleanup(func() { client.Close(); server.Close() })

	go client.Run()
	go server.Run()

	local, err := client.OpenStream()
	if err != nil {
		t.Fatal(err)
	}
	open, _ := proto.EncodeJSONPayload(proto.FrameStreamOpen, local.ID(), &proto.StreamOpen{Protocol: "tcp"})
	if err := client.GetFrameWriter().Write(open); err != nil {
		t.Fatal(err)
	}
	remote, err := server.AcceptStream()
	if err != nil {
		t.Fatal(err)
	}
	return local, remote
}

func waitState(s *Stream, want int32, d time.Duration) bool {
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if s.state.Load() == want {
			return true
		}
		time.Sleep(10 * time.Millisecond)
	}
	return s.state.Load() == want
}

func TestHalfClosedStreamIsResetWhenThePeerStaysSilent(t *testing.T) {
	local, _ := halfClosePair(t, 150*time.Millisecond)
	local.Close()
	if !waitState(local, streamStateReset, 2*time.Second) {
		t.Fatalf("state = %d, want reset", local.state.Load())
	}
}

func TestHalfClosedStreamIsKeptWhenTheReaperIsOff(t *testing.T) {
	local, _ := halfClosePair(t, 0)
	local.Close()
	time.Sleep(300 * time.Millisecond)
	if got := local.state.Load(); got != streamStateHalfClosedLocal {
		t.Fatalf("state = %d, want half-closed", got)
	}
}

func TestPeerActivityPostponesTheHalfCloseReset(t *testing.T) {
	local, remote := halfClosePair(t, 300*time.Millisecond)
	local.Close()
	for i := 0; i < 5; i++ {
		time.Sleep(100 * time.Millisecond)
		if _, err := remote.Write([]byte("x")); err != nil {
			t.Fatal(err)
		}
	}
	if got := local.state.Load(); got != streamStateHalfClosedLocal {
		t.Fatalf("state = %d after steady peer data, want half-closed", got)
	}
	if !waitState(local, streamStateReset, 3*time.Second) {
		t.Fatalf("state = %d, want reset once the peer went silent", local.state.Load())
	}
}

func TestGoAwayTellsThePeerTheShutdownWasIntentional(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	acc := make(chan net.Conn, 1)
	go func() { c, _ := ln.Accept(); acc <- c }()
	c1, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	a, b := New(c1, DefaultConfig()), New(<-acc, DefaultConfig())
	go a.Run()
	go b.Run()

	if err := a.SendGoAway("shutdown", "bye"); err != nil {
		t.Fatal(err)
	}
	select {
	case <-b.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("peer did not close after GO_AWAY")
	}
	ga := b.GoAway()
	if ga == nil || ga.Reason != "shutdown" || ga.Message != "bye" {
		t.Fatalf("GoAway() = %+v", ga)
	}
	if a.GoAway() != nil {
		t.Fatal("sender must not report a GO_AWAY it never received")
	}
}
