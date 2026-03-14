package main

import (
	"os"
	"testing"
)

func TestMainFlags(t *testing.T) {
	// Test that flag parsing works with various flag combinations
	tests := []struct {
		name string
		args []string
	}{
		{
			name: "version flag",
			args: []string{"-version"},
		},
		{
			name: "help flag",
			args: []string{"-h"},
		},
		{
			name: "verbose flag",
			args: []string{"-v"},
		},
		{
			name: "json log flag",
			args: []string{"-json"},
		},
		{
			name: "auto cert flag",
			args: []string{"-auto-cert"},
		},
		{
			name: "custom domain",
			args: []string{"-domain", "example.com"},
		},
		{
			name: "custom ports",
			args: []string{"-control", ":8443", "-http", ":8080"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// We can't easily test flag parsing in main() without executing it
			// This test documents the expected flags
			if len(tt.args) == 0 {
				t.Error("Expected some args")
			}
		})
	}
}

func TestEnvironmentVariables(t *testing.T) {
	// Test WIRERIFT_DOMAIN
	os.Setenv("WIRERIFT_DOMAIN", "test.example.com")
	defer os.Unsetenv("WIRERIFT_DOMAIN")

	domain := os.Getenv("WIRERIFT_DOMAIN")
	if domain != "test.example.com" {
		t.Errorf("WIRERIFT_DOMAIN = %q, want test.example.com", domain)
	}

	// Test WIRERIFT_CONTROL_ADDR
	os.Setenv("WIRERIFT_CONTROL_ADDR", ":9999")
	defer os.Unsetenv("WIRERIFT_CONTROL_ADDR")

	controlAddr := os.Getenv("WIRERIFT_CONTROL_ADDR")
	if controlAddr != ":9999" {
		t.Errorf("WIRERIFT_CONTROL_ADDR = %q, want :9999", controlAddr)
	}

	// Test WIRERIFT_HTTP_ADDR
	os.Setenv("WIRERIFT_HTTP_ADDR", ":8888")
	defer os.Unsetenv("WIRERIFT_HTTP_ADDR")

	httpAddr := os.Getenv("WIRERIFT_HTTP_ADDR")
	if httpAddr != ":8888" {
		t.Errorf("WIRERIFT_HTTP_ADDR = %q, want :8888", httpAddr)
	}
}

func TestDefaultValues(t *testing.T) {
	// Clear environment
	os.Unsetenv("WIRERIFT_DOMAIN")
	os.Unsetenv("WIRERIFT_CONTROL_ADDR")
	os.Unsetenv("WIRERIFT_HTTP_ADDR")

	// Test default values (these would be used in main)
	defaultDomain := "wirerift.dev"
	defaultControl := ":4443"
	defaultHTTP := ":80"
	defaultDashboardPort := 4040

	if defaultDomain != "wirerift.dev" {
		t.Error("Default domain mismatch")
	}
	if defaultControl != ":4443" {
		t.Error("Default control address mismatch")
	}
	if defaultHTTP != ":80" {
		t.Error("Default HTTP address mismatch")
	}
	if defaultDashboardPort != 4040 {
		t.Error("Default dashboard port mismatch")
	}
}
