package server

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/wirerift/wirerift/internal/proto"
)

func TestHeldSubdomainExpiresAndCanBeDisabled(t *testing.T) {
	cfg := DefaultConfig()
	cfg.OfflineGrace = 50 * time.Millisecond
	s := New(cfg, nil)

	s.holdSubdomain("app", "acc")
	if owner, held := s.heldBy("app"); !held || owner != "acc" {
		t.Fatalf("heldBy = %q, %v; want acc, true", owner, held)
	}
	time.Sleep(80 * time.Millisecond)
	if _, held := s.heldBy("app"); held {
		t.Fatal("hold outlived the grace period")
	}

	s.holdSubdomain("old", "acc")
	time.Sleep(80 * time.Millisecond)
	s.sweepHeld()
	if _, ok := s.held.Load("old"); ok {
		t.Fatal("sweepHeld kept an expired hold")
	}

	cfg.OfflineGrace = 0
	off := New(cfg, nil)
	off.holdSubdomain("app", "acc")
	if _, held := off.heldBy("app"); held {
		t.Fatal("OfflineGrace=0 must not hold anything")
	}
}

func TestHeldNamesSurviveARestart(t *testing.T) {
	cfg := DefaultConfig()
	cfg.OfflineGrace = time.Minute
	cfg.HeldFile = filepath.Join(t.TempDir(), "held.json")

	first := New(cfg, nil)
	first.holdSubdomain("dropped", "acc1")
	first.held.Store("expired", heldName{accountID: "acc2", until: time.Now().Add(-time.Second)})
	first.saveHeld()

	second := New(cfg, nil)
	second.loadHeld()
	if owner, held := second.heldBy("dropped"); !held || owner != "acc1" {
		t.Fatalf("heldBy(dropped) = %q, %v; want acc1, true", owner, held)
	}
	if _, held := second.heldBy("expired"); held {
		t.Fatal("an expired hold came back")
	}
	if _, err := os.Stat(cfg.HeldFile); !os.IsNotExist(err) {
		t.Fatalf("held file should be removed after loading, stat err = %v", err)
	}
}

func TestTakeOverOnlyFromTheSameAccountsOtherSession(t *testing.T) {
	s := New(DefaultConfig(), nil)
	old := &Tunnel{ID: "t1", Type: proto.TunnelTypeHTTP, SessionID: "s1", AccountID: "alice", Subdomain: "app", closed: make(chan struct{})}
	prev := &Session{ID: "s1", AccountID: "alice", Tunnels: map[string]*Tunnel{"t1": old}}
	s.sessions.Store("s1", prev)
	s.tunnels.Store("app", old)
	fresh := &Tunnel{ID: "t2", Type: proto.TunnelTypeHTTP, SessionID: "s2", AccountID: "alice", Subdomain: "app", closed: make(chan struct{})}

	if s.takeOver("app", &Session{ID: "s3", AccountID: "bob"}, fresh) {
		t.Fatal("another account took the name over")
	}
	if s.takeOver("app", &Session{ID: "s1", AccountID: "alice"}, fresh) {
		t.Fatal("a session took over from itself")
	}
	if !s.takeOver("app", &Session{ID: "s2", AccountID: "alice"}, fresh) {
		t.Fatal("same account, other session: expected takeover")
	}
	if v, _ := s.tunnels.Load("app"); v != fresh {
		t.Fatal("the name does not point at the new tunnel")
	}
	if len(prev.Tunnels) != 0 {
		t.Fatal("old tunnel is still attached to its session")
	}
}

// takeOverRaceServer wires the state the takeover race needs: session s1
// owns subdomain app through tunnel t1, registered in both maps.
func takeOverRaceServer() (*Server, *Tunnel) {
	s := New(DefaultConfig(), nil)
	old := &Tunnel{
		ID: "t1", Type: proto.TunnelTypeHTTP,
		SessionID: "s1", AccountID: "alice", Subdomain: "app",
		closed: make(chan struct{}),
	}
	prev := &Session{ID: "s1", AccountID: "alice", Tunnels: map[string]*Tunnel{"t1": old}}
	s.sessions.Store("s1", prev)
	s.tunnels.Store("app", old)
	return s, old
}

func waitForCondition(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("%s never happened within the deadline", what)
}

// TestSessionTeardownAfterTakeOverKeepsTheNewTunnel pins the takeover vs
// stale-session-teardown ordering: removeSession snapshots session.Tunnels
// and tears each captured tunnel down; takeOver swaps the subdomain key to
// the reconnecting client's replacement but cannot detach the old tunnel
// once the session is already gone from s.sessions. The teardown of the
// stale snapshot must therefore not release the name the replacement now
// owns. Seen red before the guard: teardownTunnel deleted the key
// unconditionally and the replacement's registration vanished.
func TestSessionTeardownAfterTakeOverKeepsTheNewTunnel(t *testing.T) {
	s, old := takeOverRaceServer()
	fresh := &Tunnel{
		ID: "t2", Type: proto.TunnelTypeHTTP,
		SessionID: "s2", AccountID: "alice", Subdomain: "app",
		closed: make(chan struct{}),
	}

	// Park removeSession inside teardownTunnel(old): the session is gone
	// from s.sessions and the snapshot carries the old tunnel.
	old.mu.Lock()
	teardownDone := make(chan struct{})
	go func() {
		defer close(teardownDone)
		s.removeSession("s1")
	}()
	waitForCondition(t, "stale session removal", func() bool {
		_, ok := s.sessions.Load("s1")
		return !ok
	})

	// The reconnecting client's takeover commits its swap before it parks
	// on old.mu at its own cancelExpiry.
	takeOverDone := make(chan bool, 1)
	go func() {
		sessB := &Session{ID: "s2", AccountID: "alice"}
		takeOverDone <- s.takeOver("app", sessB, fresh)
	}()
	waitForCondition(t, "takeover commit", func() bool {
		v, _ := s.tunnels.Load("app")
		return v == fresh
	})

	// Release both parked goroutines; the takeover is committed and the
	// teardown still holds the stale pointer, so the outcome is fixed.
	old.mu.Unlock()

	if !<-takeOverDone {
		t.Fatal("takeover returned false")
	}
	<-teardownDone

	if v, ok := s.tunnels.Load("app"); !ok || v != fresh {
		t.Fatalf("session teardown deleted the replacement tunnel's registration: got v=%v ok=%v", v, ok)
	}
}

// TestSessionTeardownWithoutTakeoverStillUnregisters is the control: a
// plain session teardown must still release the subdomain.
func TestSessionTeardownWithoutTakeoverStillUnregisters(t *testing.T) {
	s, _ := takeOverRaceServer()
	s.removeSession("s1")
	if v, ok := s.tunnels.Load("app"); ok {
		t.Fatalf("plain teardown kept the registration (v=%v)", v)
	}
}

// F201: a stale teardown of an evicted TCP tunnel (a session snapshot taken
// before the same account's reconnect replaced it) must leave the replacement's
// registry entry and port reservation alone.
func TestStaleTCPTeardownKeepsReplacement(t *testing.T) {
	s := New(Config{Domain: "example.test", OfflineGrace: time.Minute}, nil)
	mk := func(id, sess string) *Tunnel {
		return &Tunnel{ID: id, Type: proto.TunnelTypeTCP, SessionID: sess, AccountID: "a", Port: 20001, closed: make(chan struct{})}
	}
	old, fresh := mk("old", "s1"), mk("new", "s2")
	s.tunnels.Store("tcp:20001", old)
	s.tcpPorts.Store(20001, true)
	s.evictTCPTunnel(old)
	s.tunnels.Store("tcp:20001", fresh)
	s.tcpPorts.Store(20001, true)

	s.teardownTunnel(old) // stale
	if v, ok := s.tunnels.Load("tcp:20001"); !ok || v.(*Tunnel) != fresh {
		t.Fatal("stale teardown removed the replacement's registry entry")
	}
	if _, ok := s.tcpPorts.Load(20001); !ok {
		t.Fatal("stale teardown released the replacement's port")
	}

	s.teardownTunnel(fresh)
	if _, ok := s.tunnels.Load("tcp:20001"); ok {
		t.Fatal("the owner's teardown must unregister the tunnel")
	}
	if _, ok := s.tcpPorts.Load(20001); ok {
		t.Fatal("the owner's teardown must release the port")
	}
}
