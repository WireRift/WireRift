package clientui

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
)

// Saved is what the UI remembers between runs.
type Saved struct {
	Server string `json:"server,omitempty"`
	Token  string `json:"token,omitempty"` // only when the user asked to remember it
}

// Settings is the file the UI keeps in the user's configuration directory.
// A nil *Settings (or an empty path) stores nothing.
type Settings struct {
	mu   sync.Mutex
	path string
}

// NewSettings keeps the settings in path.
func NewSettings(path string) *Settings { return &Settings{path: path} }

// DefaultSettingsPath is <user config dir>/wirerift/ui.json.
func DefaultSettingsPath() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "wirerift", "ui.json"), nil
}

// Load reads the saved values; a missing or unreadable file is empty.
func (s *Settings) Load() Saved {
	if s == nil || s.path == "" {
		return Saved{}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var v Saved
	if data, err := os.ReadFile(s.path); err == nil {
		_ = json.Unmarshal(data, &v)
	}
	return v
}

// Save writes v atomically with mode 0600; an empty value removes the file.
func (s *Settings) Save(v Saved) error {
	if s == nil || s.path == "" {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if v == (Saved{}) {
		if err := os.Remove(s.path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(s.path), ".ui-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0o600); err != nil && !errors.Is(err, errors.ErrUnsupported) {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), s.path)
}
