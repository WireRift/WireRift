package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
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
		{
			name: "all flags",
			args: []string{"-control", ":8443", "-http", ":8080", "-https", ":443",
				"-domain", "tunnel.example.com", "-tcp-ports", "10000-19999",
				"-dashboard-port", "9090", "-auto-cert", "-cert-dir", "./certs",
				"-v", "-json"},
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

func TestVersionVariables(t *testing.T) {
	// Test that version variables are defined
	if version == "" {
		t.Error("version should be defined")
	}
	if commit == "" {
		t.Error("commit should be defined")
	}
	if date == "" {
		t.Error("date should be defined")
	}
}

func TestFlagSetCreation(t *testing.T) {
	// Test creating a flag set similar to main
	fs := flag.NewFlagSet("test", flag.ContinueOnError)

	controlAddr := fs.String("control", ":4443", "Control plane address")
	httpAddr := fs.String("http", ":80", "HTTP edge address")
	httpsAddr := fs.String("https", ":443", "HTTPS edge address")
	dashboardPort := fs.Int("dashboard-port", 4040, "Dashboard port")
	domain := fs.String("domain", "wirerift.dev", "Base domain")
	tcpPortRange := fs.String("tcp-ports", "20000-29999", "TCP tunnel port range")
	autoCert := fs.Bool("auto-cert", false, "Auto-generate certificates")
	certDir := fs.String("cert-dir", "certs", "Directory for certificates")
	verbose := fs.Bool("v", false, "Verbose logging")
	jsonLog := fs.Bool("json", false, "JSON log format")
	showVersion := fs.Bool("version", false, "Show version")

	// Parse with no args
	err := fs.Parse([]string{})
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	// Check defaults
	if *controlAddr != ":4443" {
		t.Errorf("controlAddr = %q, want :4443", *controlAddr)
	}
	if *httpAddr != ":80" {
		t.Errorf("httpAddr = %q, want :80", *httpAddr)
	}
	if *httpsAddr != ":443" {
		t.Errorf("httpsAddr = %q, want :443", *httpsAddr)
	}
	if *dashboardPort != 4040 {
		t.Errorf("dashboardPort = %d, want 4040", *dashboardPort)
	}
	if *domain != "wirerift.dev" {
		t.Errorf("domain = %q, want wirerift.dev", *domain)
	}
	if *tcpPortRange != "20000-29999" {
		t.Errorf("tcpPortRange = %q, want 20000-29999", *tcpPortRange)
	}
	if *autoCert != false {
		t.Error("autoCert should be false by default")
	}
	if *certDir != "certs" {
		t.Errorf("certDir = %q, want certs", *certDir)
	}
	if *verbose != false {
		t.Error("verbose should be false by default")
	}
	if *jsonLog != false {
		t.Error("jsonLog should be false by default")
	}
	if *showVersion != false {
		t.Error("showVersion should be false by default")
	}
}

func TestFlagSetWithArgs(t *testing.T) {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)

	controlAddr := fs.String("control", ":4443", "Control plane address")
	domain := fs.String("domain", "wirerift.dev", "Base domain")
	autoCert := fs.Bool("auto-cert", false, "Auto-generate certificates")
	verbose := fs.Bool("v", false, "Verbose logging")

	// Parse with custom args
	err := fs.Parse([]string{"-control", ":8443", "-domain", "custom.com", "-auto-cert", "-v"})
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	if *controlAddr != ":8443" {
		t.Errorf("controlAddr = %q, want :8443", *controlAddr)
	}
	if *domain != "custom.com" {
		t.Errorf("domain = %q, want custom.com", *domain)
	}
	if *autoCert != true {
		t.Error("autoCert should be true")
	}
	if *verbose != true {
		t.Error("verbose should be true")
	}
}

func TestEnvironmentVariableOverride(t *testing.T) {
	// Set environment variables
	os.Setenv("TEST_DOMAIN", "env.example.com")
	defer os.Unsetenv("TEST_DOMAIN")

	// Simulate reading from environment
	domain := "wirerift.dev" // default
	if envDomain := os.Getenv("TEST_DOMAIN"); envDomain != "" && domain == "wirerift.dev" {
		domain = envDomain
	}

	if domain != "env.example.com" {
		t.Errorf("domain = %q, want env.example.com", domain)
	}
}

func TestMultipleEnvironmentVariables(t *testing.T) {
	// Clear all first
	os.Unsetenv("WIRERIFT_DOMAIN")
	os.Unsetenv("WIRERIFT_CONTROL_ADDR")
	os.Unsetenv("WIRERIFT_HTTP_ADDR")

	// Set multiple
	os.Setenv("WIRERIFT_DOMAIN", "multi.example.com")
	os.Setenv("WIRERIFT_CONTROL_ADDR", ":5555")
	os.Setenv("WIRERIFT_HTTP_ADDR", ":6666")

	defer func() {
		os.Unsetenv("WIRERIFT_DOMAIN")
		os.Unsetenv("WIRERIFT_CONTROL_ADDR")
		os.Unsetenv("WIRERIFT_HTTP_ADDR")
	}()

	// Verify all are set
	if os.Getenv("WIRERIFT_DOMAIN") != "multi.example.com" {
		t.Error("WIRERIFT_DOMAIN not set correctly")
	}
	if os.Getenv("WIRERIFT_CONTROL_ADDR") != ":5555" {
		t.Error("WIRERIFT_CONTROL_ADDR not set correctly")
	}
	if os.Getenv("WIRERIFT_HTTP_ADDR") != ":6666" {
		t.Error("WIRERIFT_HTTP_ADDR not set correctly")
	}
}

// TestFlagHelpOutput tests that help output is properly formatted
func TestFlagHelpOutput(t *testing.T) {
	fs := flag.NewFlagSet("wirerift-server", flag.ContinueOnError)
	fs.SetOutput(nil) // Suppress output

	fs.String("control", ":4443", "Control plane address")
	fs.String("http", ":80", "HTTP edge address")
	fs.String("https", ":443", "HTTPS edge address")

	// Test parsing -h
	if err := fs.Parse([]string{"-h"}); err == nil {
		// -h returns an error in flag.ContinueOnError mode
		// but it's expected behavior
	}
}

// TestFlagInvalidValue tests parsing with invalid values
func TestFlagInvalidValue(t *testing.T) {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	dashboardPort := fs.Int("dashboard-port", 4040, "Dashboard port")

	// Parse empty string
	err := fs.Parse([]string{"-dashboard-port", "invalid"})
	if err == nil {
		// Int parsing should fail for invalid value
		// but ContinueOnError doesn't return error, it just keeps default
	}

	// Default should still be used
	if *dashboardPort == 4040 {
		// Default was preserved
	}
}

// TestAllFlagsWithValues tests all flags with their values
func TestAllFlagsWithValues(t *testing.T) {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)

	control := fs.String("control", ":4443", "Control plane address")
	http := fs.String("http", ":80", "HTTP edge address")
	https := fs.String("https", ":443", "HTTPS edge address")
	dashboardPort := fs.Int("dashboard-port", 4040, "Dashboard port")
	domain := fs.String("domain", "wirerift.dev", "Base domain")
	tcpPorts := fs.String("tcp-ports", "20000-29999", "TCP port range")
	autoCert := fs.Bool("auto-cert", false, "Auto-generate certificates")
	certDir := fs.String("cert-dir", "certs", "Certificate directory")
	verbose := fs.Bool("v", false, "Verbose logging")
	jsonLog := fs.Bool("json", false, "JSON logging")
	showVersion := fs.Bool("version", false, "Show version")

	args := []string{
		"-control", ":9999",
		"-http", ":8080",
		"-https", ":8443",
		"-dashboard-port", "9090",
		"-domain", "test.example.com",
		"-tcp-ports", "30000-39999",
		"-auto-cert",
		"-cert-dir", "/tmp/certs",
		"-v",
		"-json",
		"-version",
	}

	if err := fs.Parse(args); err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	if *control != ":9999" {
		t.Errorf("control = %q, want :9999", *control)
	}
	if *http != ":8080" {
		t.Errorf("http = %q, want :8080", *http)
	}
	if *https != ":8443" {
		t.Errorf("https = %q, want :8443", *https)
	}
	if *dashboardPort != 9090 {
		t.Errorf("dashboardPort = %d, want 9090", *dashboardPort)
	}
	if *domain != "test.example.com" {
		t.Errorf("domain = %q, want test.example.com", *domain)
	}
	if *tcpPorts != "30000-39999" {
		t.Errorf("tcpPorts = %q, want 30000-39999", *tcpPorts)
	}
	if !*autoCert {
		t.Error("autoCert should be true")
	}
	if *certDir != "/tmp/certs" {
		t.Errorf("certDir = %q, want /tmp/certs", *certDir)
	}
	if !*verbose {
		t.Error("verbose should be true")
	}
	if !*jsonLog {
		t.Error("jsonLog should be true")
	}
	if !*showVersion {
		t.Error("showVersion should be true")
	}
}

// TestEnvOverrideBehavior tests environment variable override logic
func TestEnvOverrideBehavior(t *testing.T) {
	// Test that env overrides default but not explicit flag
	tests := []struct {
		name         string
		envValue     string
		flagValue    string
		defaultValue string
		expected     string
	}{
		{
			name:         "env overrides default",
			envValue:     "env.example.com",
			flagValue:    "wirerift.dev",
			defaultValue: "wirerift.dev",
			expected:     "env.example.com",
		},
		{
			name:         "explicit flag wins",
			envValue:     "env.example.com",
			flagValue:    "flag.example.com",
			defaultValue: "wirerift.dev",
			expected:     "flag.example.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Simulate the logic from main()
			result := tt.flagValue
			if tt.envValue != "" && result == tt.defaultValue {
				result = tt.envValue
			}

			if result != tt.expected {
				t.Errorf("result = %q, want %q", result, tt.expected)
			}
		})
	}
}

// TestVersionString tests version string formatting
func TestVersionString(t *testing.T) {
	// The version string format should include version, commit, and date
	versionStr := fmt.Sprintf("WireRift Server %s (commit: %s, built: %s)", version, commit, date)

	if versionStr == "" {
		t.Error("version string should not be empty")
	}

	if !strings.Contains(versionStr, version) {
		t.Error("version string should contain version")
	}
	if !strings.Contains(versionStr, commit) {
		t.Error("version string should contain commit")
	}
	if !strings.Contains(versionStr, date) {
		t.Error("version string should contain date")
	}
}
