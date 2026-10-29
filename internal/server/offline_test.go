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
