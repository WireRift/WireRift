package server

import (
	"os"
	"path/filepath"
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
