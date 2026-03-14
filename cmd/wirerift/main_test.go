package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestGetEnv(t *testing.T) {
	// Test with no env var set
	if got := getEnv("TEST_VAR_NONEXISTENT", "default"); got != "default" {
		t.Errorf("getEnv() = %q, want default", got)
	}

	// Test with env var set
	os.Setenv("TEST_VAR_WIRERIFT", "custom_value")
	defer os.Unsetenv("TEST_VAR_WIRERIFT")

	if got := getEnv("TEST_VAR_WIRERIFT", "default"); got != "custom_value" {
		t.Errorf("getEnv() = %q, want custom_value", got)
	}
}

func TestParseCommonOptions(t *testing.T) {
	// Test defaults
	opts := parseCommonOptions()
	if opts.server != "localhost:4443" {
		t.Errorf("server = %q, want localhost:4443", opts.server)
	}

	// Test with env vars
	os.Setenv("WIRERIFT_SERVER", "custom:1234")
	os.Setenv("WIRERIFT_TOKEN", "test-token")
	defer os.Unsetenv("WIRERIFT_SERVER")
	defer os.Unsetenv("WIRERIFT_TOKEN")

	opts = parseCommonOptions()
	if opts.server != "custom:1234" {
		t.Errorf("server = %q, want custom:1234", opts.server)
	}
	if opts.token != "test-token" {
		t.Errorf("token = %q, want test-token", opts.token)
	}
}

func TestCreateLogger(t *testing.T) {
	// Test non-verbose logger
	logger := createLogger(false)
	if logger == nil {
		t.Error("createLogger(false) should not return nil")
	}

	// Test verbose logger
	logger = createLogger(true)
	if logger == nil {
		t.Error("createLogger(true) should not return nil")
	}
}

func TestLoadConfig(t *testing.T) {
	// Create temp config file
	tmpDir := t.TempDir()
	configFile := filepath.Join(tmpDir, "test_config.yaml")

	configContent := `server: custom.server:4443
token: my-test-token

tunnels:
  - type: http
    local_port: 8080
    subdomain: myapp
  - type: tcp
    local_port: 25565
`

	if err := os.WriteFile(configFile, []byte(configContent), 0644); err != nil {
		t.Fatalf("Failed to write test config: %v", err)
	}

	// Load config
	cfg, err := loadConfig(configFile)
	if err != nil {
		t.Fatalf("loadConfig failed: %v", err)
	}

	if cfg.Server != "custom.server:4443" {
		t.Errorf("Server = %q, want custom.server:4443", cfg.Server)
	}
	if cfg.Token != "my-test-token" {
		t.Errorf("Token = %q, want my-test-token", cfg.Token)
	}
	if len(cfg.Tunnels) != 2 {
		t.Fatalf("Expected 2 tunnels, got %d", len(cfg.Tunnels))
	}

	// Check first tunnel
	if cfg.Tunnels[0].Type != "http" {
		t.Errorf("Tunnel[0].Type = %q, want http", cfg.Tunnels[0].Type)
	}
	if cfg.Tunnels[0].LocalPort != 8080 {
		t.Errorf("Tunnel[0].LocalPort = %d, want 8080", cfg.Tunnels[0].LocalPort)
	}
	if cfg.Tunnels[0].Subdomain != "myapp" {
		t.Errorf("Tunnel[0].Subdomain = %q, want myapp", cfg.Tunnels[0].Subdomain)
	}

	// Check second tunnel
	if cfg.Tunnels[1].Type != "tcp" {
		t.Errorf("Tunnel[1].Type = %q, want tcp", cfg.Tunnels[1].Type)
	}
	if cfg.Tunnels[1].LocalPort != 25565 {
		t.Errorf("Tunnel[1].LocalPort = %d, want 25565", cfg.Tunnels[1].LocalPort)
	}
}

func TestLoadConfigNotFound(t *testing.T) {
	_, err := loadConfig("/nonexistent/path/config.yaml")
	if err == nil {
		t.Error("loadConfig should fail for non-existent file")
	}
}

func TestLoadConfigMinimal(t *testing.T) {
	tmpDir := t.TempDir()
	configFile := filepath.Join(tmpDir, "minimal.yaml")

	// Write minimal config
	if err := os.WriteFile(configFile, []byte("server: test.server\n"), 0644); err != nil {
		t.Fatalf("Failed to write test config: %v", err)
	}

	cfg, err := loadConfig(configFile)
	if err != nil {
		t.Fatalf("loadConfig failed: %v", err)
	}

	if cfg.Server != "test.server" {
		t.Errorf("Server = %q, want test.server", cfg.Server)
	}
	if len(cfg.Tunnels) != 0 {
		t.Errorf("Expected 0 tunnels, got %d", len(cfg.Tunnels))
	}
}

func TestLoadConfigWithEnvDefaults(t *testing.T) {
	os.Setenv("WIRERIFT_SERVER", "env.server:4443")
	os.Setenv("WIRERIFT_TOKEN", "env-token")
	defer os.Unsetenv("WIRERIFT_SERVER")
	defer os.Unsetenv("WIRERIFT_TOKEN")

	tmpDir := t.TempDir()
	configFile := filepath.Join(tmpDir, "env_test.yaml")

	// Write empty config - should use env defaults
	if err := os.WriteFile(configFile, []byte(""), 0644); err != nil {
		t.Fatalf("Failed to write test config: %v", err)
	}

	cfg, err := loadConfig(configFile)
	if err != nil {
		t.Fatalf("loadConfig failed: %v", err)
	}

	if cfg.Server != "env.server:4443" {
		t.Errorf("Server = %q, want env.server:4443", cfg.Server)
	}
	if cfg.Token != "env-token" {
		t.Errorf("Token = %q, want env-token", cfg.Token)
	}
}

func TestPrintUsage(t *testing.T) {
	// Just verify it doesn't panic
	printUsage()
}

func TestCommonOptionsStruct(t *testing.T) {
	opts := commonOptions{
		server: "test:1234",
		token:  "test-token",
	}

	if opts.server != "test:1234" {
		t.Errorf("server = %q, want test:1234", opts.server)
	}
	if opts.token != "test-token" {
		t.Errorf("token = %q, want test-token", opts.token)
	}
}

func TestConfigFileStruct(t *testing.T) {
	cfg := ConfigFile{
		Server: "test.server",
		Token:  "test-token",
		Tunnels: []TunnelConfig{
			{Type: "http", LocalPort: 8080, Subdomain: "test"},
		},
	}

	if cfg.Server != "test.server" {
		t.Errorf("Server = %q", cfg.Server)
	}
	if len(cfg.Tunnels) != 1 {
		t.Errorf("Expected 1 tunnel, got %d", len(cfg.Tunnels))
	}
}

func TestLoadConfigWithComments(t *testing.T) {
	tmpDir := t.TempDir()
	configFile := filepath.Join(tmpDir, "comments.yaml")

	configContent := `# This is a comment
server: test.server
# Another comment
token: test-token

tunnels:
  # HTTP tunnel
  - type: http
    local_port: 8080
`

	if err := os.WriteFile(configFile, []byte(configContent), 0644); err != nil {
		t.Fatalf("Failed to write test config: %v", err)
	}

	cfg, err := loadConfig(configFile)
	if err != nil {
		t.Fatalf("loadConfig failed: %v", err)
	}

	if cfg.Server != "test.server" {
		t.Errorf("Server = %q, want test.server", cfg.Server)
	}
	if cfg.Token != "test-token" {
		t.Errorf("Token = %q, want test-token", cfg.Token)
	}
}
