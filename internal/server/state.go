package server

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"
)

// The activity log and the rolling history are kept in Config.StateFile so the
// admin dashboard still shows what happened before a restart. Captured request
// bodies (the traffic inspector) are never written to disk.

const (
	stateSaveEvery = 6              // history ticks between saves (one minute)
	stateMaxAge    = 24 * time.Hour // older samples and events are not restored
)

type savedState struct {
	Events  []Event               `json:"events"`
	History []HistoryPoint        `json:"history"`
	Usage   map[string]savedUsage `json:"usage,omitempty"`
}

// savedUsage is one account's traffic totals as kept across restarts.
type savedUsage struct {
	Requests int64 `json:"requests"`
	BytesIn  int64 `json:"bytes_in"`
	BytesOut int64 `json:"bytes_out"`
}

// saveState writes the activity log and history atomically, mode 0600.
func (s *Server) saveState() {
	if s.config.StateFile == "" {
		return
	}
	s.events.mu.Lock()
	st := savedState{Events: append([]Event(nil), s.events.buf...)}
	s.events.mu.Unlock()
	st.History = s.History()
	st.Usage = map[string]savedUsage{}
	s.acctUsage.Range(func(k, v any) bool {
		c := v.(*accountCounters)
		st.Usage[k.(string)] = savedUsage{c.requests.Load(), c.bytesIn.Load(), c.bytesOut.Load()}
		return true
	})
	data, err := json.Marshal(st)
	if err != nil {
		return
	}
	tmp, err := os.CreateTemp(filepath.Dir(s.config.StateFile), ".state-*")
	if err != nil {
		s.logger.Warn("cannot save the dashboard history", "error", err)
		return
	}
	defer os.Remove(tmp.Name())
	_ = tmp.Chmod(0o600)
	_, werr := tmp.Write(data)
	if cerr := tmp.Close(); werr == nil && cerr == nil {
		if err := os.Rename(tmp.Name(), s.config.StateFile); err != nil {
			s.logger.Warn("cannot save the dashboard history", "error", err)
		}
	}
}

// loadState restores what saveState wrote. A missing or damaged file is ignored.
func (s *Server) loadState() {
	if s.config.StateFile == "" {
		return
	}
	data, err := os.ReadFile(s.config.StateFile)
	if err != nil {
		return
	}
	var st savedState
	if json.Unmarshal(data, &st) != nil {
		return
	}
	for id, u := range st.Usage {
		c := s.accountCounters(id)
		c.requests.Store(u.Requests)
		c.bytesIn.Store(u.BytesIn)
		c.bytesOut.Store(u.BytesOut)
	}
	cutoff := time.Now().Add(-stateMaxAge)
	s.events.mu.Lock()
	for _, e := range st.Events {
		if e.Time.After(cutoff) && len(s.events.buf) < maxEvents {
			s.events.buf = append(s.events.buf, e)
			if e.ID > s.events.next {
				s.events.next = e.ID
			}
		}
	}
	s.events.mu.Unlock()
	s.history.mu.Lock()
	for _, p := range st.History {
		if p.T >= cutoff.Unix() {
			s.history.buf = append(s.history.buf, p)
		}
	}
	if n := len(s.history.buf); n > maxHistory {
		s.history.buf = append([]HistoryPoint(nil), s.history.buf[n-maxHistory:]...)
	}
	s.history.mu.Unlock()
}
