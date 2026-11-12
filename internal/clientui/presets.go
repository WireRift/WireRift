package clientui

import (
	"errors"
	"fmt"
	"strings"
)

// maxPresets and maxPresetName keep the settings file small.
const (
	maxPresets    = 50
	maxPresetName = 40
)

// Preset is a named tunnel the user can open again with one click.
type Preset struct {
	Name string `json:"name"`
	TunnelSpec
}

// Presets returns the saved tunnel presets.
func (m *Manager) Presets() []Preset {
	return m.settings.Load().Presets
}

// SavePreset stores p, replacing a preset of the same name.
func (m *Manager) SavePreset(p Preset) error {
	p.Name = strings.TrimSpace(p.Name)
	if p.Name == "" || len(p.Name) > maxPresetName {
		return fmt.Errorf("give the preset a name of 1-%d characters", maxPresetName)
	}
	if p.Type != "http" && p.Type != "tcp" {
		return fmt.Errorf("unknown tunnel type %q", p.Type)
	}
	if _, err := LocalAddress(p.Local); err != nil {
		return err
	}
	if m.settings == nil || m.settings.path == "" {
		return errors.New("saving is off (started with -no-save)")
	}
	m.smu.Lock()
	defer m.smu.Unlock()
	saved := m.settings.Load()
	replaced := false
	for i := range saved.Presets {
		if strings.EqualFold(saved.Presets[i].Name, p.Name) {
			saved.Presets[i], replaced = p, true
		}
	}
	if !replaced {
		if len(saved.Presets) >= maxPresets {
			return fmt.Errorf("at most %d presets", maxPresets)
		}
		saved.Presets = append(saved.Presets, p)
	}
	return m.settings.Save(saved)
}

// DeletePreset removes the preset called name (no error if it is not there).
func (m *Manager) DeletePreset(name string) error {
	m.smu.Lock()
	defer m.smu.Unlock()
	saved := m.settings.Load()
	kept := saved.Presets[:0]
	for _, p := range saved.Presets {
		if !strings.EqualFold(p.Name, name) {
			kept = append(kept, p)
		}
	}
	saved.Presets = kept
	return m.settings.Save(saved)
}
