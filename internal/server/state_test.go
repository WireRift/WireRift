package server

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func TestStateSurvivesRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	cfg := DefaultConfig()
	cfg.StateFile = path

	a := New(cfg, nil)
	a.recordEvent("info", "test", "acct", "", "", "before the restart")
	a.history.add(HistoryPoint{T: time.Now().Unix() - 30, Requests: 5})
	a.history.add(HistoryPoint{T: time.Now().Unix() - 5, Requests: 9})
	a.saveState()
	if fi, err := os.Stat(path); err != nil {
		t.Fatal(err)
	} else if runtime.GOOS != "windows" && fi.Mode().Perm() != 0o600 {
		t.Errorf("state file is %v, want 0600", fi.Mode().Perm())
	}

	b := New(cfg, nil)
	b.loadState()
	ev := b.Events(0, "")
	if len(ev) != 1 || ev[0].Message != "before the restart" {
		t.Fatalf("events after restart: %+v", ev)
	}
	b.recordEvent("info", "test", "", "", "", "after")
	if got := b.Events(1, ""); got[0].ID <= ev[0].ID {
		t.Errorf("event IDs restarted: %d after %d", got[0].ID, ev[0].ID)
	}
	if h := b.History(); len(h) != 2 || h[1].Requests != 9 {
		t.Errorf("history after restart: %+v", h)
	}
}

func TestStateIgnoresOldDamagedAndMissing(t *testing.T) {
	dir := t.TempDir()
	cfg := DefaultConfig()
	cfg.StateFile = filepath.Join(dir, "state.json")

	old := New(cfg, nil)
	old.events.add(Event{Message: "ancient"})
	old.events.buf[0].Time = time.Now().Add(-48 * time.Hour)
	old.history.add(HistoryPoint{T: time.Now().Add(-48 * time.Hour).Unix()})
	for i := 0; i < maxHistory+10; i++ {
		old.history.add(HistoryPoint{T: time.Now().Unix(), Requests: uint64(i)})
	}
	old.saveState()
	fresh := New(cfg, nil)
	fresh.loadState()
	if len(fresh.Events(0, "")) != 0 {
		t.Error("an event older than a day was restored")
	}
	if h := fresh.History(); len(h) != maxHistory || h[0].T < time.Now().Add(-time.Hour).Unix() {
		t.Errorf("history: %d points", len(h))
	}

	if err := os.WriteFile(cfg.StateFile, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	New(cfg, nil).loadState() // must not panic
	_ = os.Remove(cfg.StateFile)
	New(cfg, nil).loadState()
	none := New(DefaultConfig(), nil) // no state file configured
	none.saveState()
	none.loadState()

	bad := DefaultConfig()
	bad.StateFile = filepath.Join(dir, "no", "such", "dir", "state.json")
	New(bad, nil).saveState() // logs a warning, no crash
}

func TestStopSavesAndStartRestoresState(t *testing.T) {
	cfg := DefaultConfig()
	cfg.ControlAddr, cfg.HTTPAddr = "127.0.0.1:0", "127.0.0.1:0"
	cfg.StateFile = filepath.Join(t.TempDir(), "state.json")
	s := New(cfg, nil)
	if err := s.Start(); err != nil {
		t.Fatal(err)
	}
	s.recordEvent("info", "test", "", "", "", "kept across stop")
	s.Stop()
	if _, err := os.Stat(cfg.StateFile); err != nil {
		t.Fatalf("Stop did not save the state: %v", err)
	}
	s2 := New(cfg, nil)
	if err := s2.Start(); err != nil {
		t.Fatal(err)
	}
	defer s2.Stop()
	found := false
	for _, e := range s2.Events(0, "") {
		found = found || e.Message == "kept across stop"
	}
	if !found {
		t.Error("Start did not restore the saved events")
	}
}
