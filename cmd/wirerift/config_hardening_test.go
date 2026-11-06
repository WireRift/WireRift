package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestConfigRejectsUnknownSecurityFields(t *testing.T) {
	_, err := loadYAMLConfig([]byte("server: localhost:4443\ntunnels:\n  - type: http\n    local_port: 8080\n    authh: admin:secret\n"), &ConfigFile{})
	if err == nil || !strings.Contains(err.Error(), "authh") {
		t.Fatalf("YAML error = %v, want unknown authh field", err)
	}

	path := filepath.Join(t.TempDir(), "wirerift.json")
	if err := os.WriteFile(path, []byte(`{"server":"localhost:4443","tunnels":[{"type":"http","local_port":8080,"pinn":"secret"}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadConfig(path); err == nil || !strings.Contains(err.Error(), "pinn") {
		t.Fatalf("JSON error = %v, want unknown pinn field", err)
	}
}

func TestYAMLConfigRejectsMalformedAndInvalidBooleanValues(t *testing.T) {
	for _, data := range []string{
		"server localhost:4443\n",
		"tunnels:\n  type: http\n",
		"tunnels:\n  - type: http\n    local_port: 8080\n    inspect: sometimes\n",
	} {
		if _, err := loadYAMLConfig([]byte(data), &ConfigFile{}); err == nil {
			t.Errorf("loadYAMLConfig(%q) succeeded, want error", data)
		}
	}
}
