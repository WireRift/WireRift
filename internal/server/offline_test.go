package server

import (
	"testing"
	"time"
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
