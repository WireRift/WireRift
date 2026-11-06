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

func TestEnvTokenFromFile(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "token")
	if err := os.WriteFile(file, []byte("  file-secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("WIRERIFT_TOKEN", "")
	t.Setenv("WIRERIFT_TOKEN_FILE", file)
	if got := envToken(); got != "file-secret" {
		t.Errorf("envToken = %q, want trimmed file content", got)
	}
	if got := parseCommonOptions().token; got != "file-secret" {
		t.Errorf("parseCommonOptions token = %q", got)
	}
	t.Setenv("WIRERIFT_TOKEN", "env-secret")
	if got := envToken(); got != "env-secret" {
		t.Errorf("WIRERIFT_TOKEN should win, got %q", got)
	}
	t.Setenv("WIRERIFT_TOKEN", "")
	t.Setenv("WIRERIFT_TOKEN_FILE", filepath.Join(dir, "missing"))
	if got := envToken(); got != "" {
		t.Errorf("missing file -> %q, want empty", got)
	}
	big := filepath.Join(dir, "big")
	_ = os.WriteFile(big, make([]byte, 5000), 0o600)
	t.Setenv("WIRERIFT_TOKEN_FILE", big)
	if got := envToken(); got != "" {
		t.Errorf("oversized file accepted")
	}
}
