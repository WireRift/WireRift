package utils

import (
	"strings"
	"testing"
)

func TestGenerateID(t *testing.T) {
	id := GenerateID("test-", 8)

	if !strings.HasPrefix(id, "test-") {
		t.Errorf("ID should have prefix 'test-', got %q", id)
	}

	// Length should be prefix + 16 hex chars (8 bytes)
	expectedLen := len("test-") + 16
	if len(id) != expectedLen {
		t.Errorf("ID length = %d, want %d", len(id), expectedLen)
	}

	// Each call should generate a different ID
	id2 := GenerateID("test-", 8)
	if id == id2 {
		t.Error("GenerateID should produce unique IDs")
	}
}

func TestGenerateShortID(t *testing.T) {
	id := GenerateShortID()

	// Short ID is 8 hex chars (4 bytes)
	if len(id) != 8 {
		t.Errorf("Short ID length = %d, want 8", len(id))
	}

	// Should only contain hex characters
	for _, c := range id {
		if !isHexChar(c) {
			t.Errorf("Short ID contains non-hex character: %c", c)
		}
	}

	// Each call should generate a different ID
	id2 := GenerateShortID()
	if id == id2 {
		t.Error("GenerateShortID should produce unique IDs")
	}
}

func isHexChar(c rune) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')
}

func TestParseAddr(t *testing.T) {
	tests := []struct {
		addr      string
		wantHost  string
		wantPort  string
		wantError bool
	}{
		{"localhost:8080", "localhost", "8080", false},
		{"127.0.0.1:443", "127.0.0.1", "443", false},
		{"[::1]:8080", "::1", "8080", false},
		{"example.com:443", "example.com", "443", false},
		{"invalid", "", "", true},
		{"", "", "", true},
	}

	for _, tt := range tests {
		host, port, err := ParseAddr(tt.addr)

		if tt.wantError {
			if err == nil {
				t.Errorf("ParseAddr(%q) expected error, got nil", tt.addr)
			}
		} else {
			if err != nil {
				t.Errorf("ParseAddr(%q) unexpected error: %v", tt.addr, err)
				continue
			}
			if host != tt.wantHost {
				t.Errorf("ParseAddr(%q) host = %q, want %q", tt.addr, host, tt.wantHost)
			}
			if port != tt.wantPort {
				t.Errorf("ParseAddr(%q) port = %q, want %q", tt.addr, port, tt.wantPort)
			}
		}
	}
}

func TestJoinHostPort(t *testing.T) {
	result := JoinHostPort("localhost", "8080")
	if result != "localhost:8080" {
		t.Errorf("JoinHostPort = %q, want %q", result, "localhost:8080")
	}

	// IPv6 should be bracketed
	result = JoinHostPort("::1", "8080")
	if result != "[::1]:8080" {
		t.Errorf("JoinHostPort = %q, want %q", result, "[::1]:8080")
	}
}

func TestNormalizeHost(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"localhost:8080", "localhost"},
		{"example.com:443", "example.com"},
		{"localhost", "localhost"},
		{"192.168.1.1:8080", "192.168.1.1"},
		{"[::1]:8080", "[::1]"}, // Note: bracket handling is simple
	}

	for _, tt := range tests {
		result := NormalizeHost(tt.input)
		if result != tt.expected {
			t.Errorf("NormalizeHost(%q) = %q, want %q", tt.input, result, tt.expected)
		}
	}
}

func TestExtractSubdomain(t *testing.T) {
	tests := []struct {
		host       string
		baseDomain string
		expected   string
	}{
		{"app.wirerift.dev", "wirerift.dev", "app"},
		{"my-app.wirerift.dev", "wirerift.dev", "my-app"},
		{"test.app.wirerift.dev", "wirerift.dev", "test.app"},
		{"wirerift.dev", "wirerift.dev", ""},
		{"other.com", "wirerift.dev", ""},
		{"", "wirerift.dev", ""},
		{"app.wirerift.dev:443", "wirerift.dev", "app"},
	}

	for _, tt := range tests {
		result := ExtractSubdomain(tt.host, tt.baseDomain)
		if result != tt.expected {
			t.Errorf("ExtractSubdomain(%q, %q) = %q, want %q",
				tt.host, tt.baseDomain, result, tt.expected)
		}
	}
}

// TestExtractSubdomainSuffixMismatch tests ExtractSubdomain where host is longer than suffix but doesn't match
func TestExtractSubdomainSuffixMismatch(t *testing.T) {
	// Host "xxxx.other.example.com" is longer than suffix ".wirerift.dev" but doesn't end with it
	// This triggers the HasSuffix check on line 58
	result := ExtractSubdomain("xxxx.other.example.com", "wirerift.dev")
	if result != "" {
		t.Errorf("ExtractSubdomain(\"xxxx.other.example.com\", \"wirerift.dev\") = %q, want empty", result)
	}
}

func TestIsValidSubdomain(t *testing.T) {
	validTests := []string{
		"app",
		"my-app",
		"test123",
		"a",
		"abc-def-ghi",
		"myapp123",
		"APP", // uppercase is technically allowed by this implementation
	}

	for _, tt := range validTests {
		if !IsValidSubdomain(tt) {
			t.Errorf("IsValidSubdomain(%q) = false, want true", tt)
		}
	}

	invalidTests := []string{
		"",
		"-app",
		"-app-",
		"app-",
		"app_underscore",
		"app.space",
		strings.Repeat("a", 64), // too long
	}

	for _, tt := range invalidTests {
		if IsValidSubdomain(tt) {
			t.Errorf("IsValidSubdomain(%q) = true, want false", tt)
		}
	}
}

func TestIsAlphaNum(t *testing.T) {
	// Test lowercase
	for c := byte('a'); c <= 'z'; c++ {
		if !isAlphaNum(c) {
			t.Errorf("isAlphaNum(%q) = false, want true", c)
		}
	}

	// Test uppercase
	for c := byte('A'); c <= 'Z'; c++ {
		if !isAlphaNum(c) {
			t.Errorf("isAlphaNum(%q) = false, want true", c)
		}
	}

	// Test digits
	for c := byte('0'); c <= '9'; c++ {
		if !isAlphaNum(c) {
			t.Errorf("isAlphaNum(%q) = false, want true", c)
		}
	}

	// Test non-alphanumeric
	nonAlphaNum := []byte{'-', '_', '.', ' ', '!', '@', '#', '$'}
	for _, c := range nonAlphaNum {
		if isAlphaNum(c) {
			t.Errorf("isAlphaNum(%q) = true, want false", c)
		}
	}
}
