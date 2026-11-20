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

// A config file that leaves a value empty falls back to the environment, in
// both formats. The "wirerift config init" template ships an empty token, so
// without the fallback a token from WIRERIFT_TOKEN or WIRERIFT_TOKEN_FILE
// would be discarded and the client would authenticate with "".
func TestConfigEmptyValueFallsBackToEnvironment(t *testing.T) {
	t.Setenv("WIRERIFT_TOKEN", "env-token")
	t.Setenv("WIRERIFT_TOKEN_FILE", "")
	t.Setenv("WIRERIFT_SERVER", "env.server:4443")

	dir := t.TempDir()
	write := func(name, content string) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}

	cases := []struct {
		name    string
		path    string
		content string
	}{
		{"yaml empty token", write("a.yaml", "server: localhost:4443\ntoken: \"\"\n"), "env-token"},
		{"yaml empty server", write("b.yaml", "server: \"\"\ntoken: file-token\n"), "file-token"},
		{"yaml empty both", write("c.yaml", "server: \"\"\ntoken: \"\"\n"), "env-token"},
		{"json empty token", write("d.json", `{"server":"localhost:4443","token":""}`), "env-token"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := loadConfig(tc.path)
			if err != nil {
				t.Fatalf("loadConfig: %v", err)
			}
			if cfg.Token != tc.content {
				t.Errorf("token = %q, want %q", cfg.Token, tc.content)
			}
		})
	}

	// The server address falls back the same way.
	cfg, err := loadConfig(write("e.yaml", "server: \"\"\ntoken: t\n"))
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if cfg.Server != "env.server:4443" {
		t.Errorf("server = %q, want %q", cfg.Server, "env.server:4443")
	}
}

// A value written in the config file still wins over the environment.
func TestConfigFileValueWinsOverEnvironment(t *testing.T) {
	t.Setenv("WIRERIFT_TOKEN", "env-token")
	t.Setenv("WIRERIFT_TOKEN_FILE", "")
	t.Setenv("WIRERIFT_SERVER", "env.server:4443")

	dir := t.TempDir()
	path := filepath.Join(dir, "wirerift.yaml")
	if err := os.WriteFile(path, []byte("server: file.server:4443\ntoken: file-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := loadConfig(path)
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if cfg.Token != "file-token" {
		t.Errorf("token = %q, want file-token", cfg.Token)
	}
	if cfg.Server != "file.server:4443" {
		t.Errorf("server = %q, want file.server:4443", cfg.Server)
	}
}
