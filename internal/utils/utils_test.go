package utils

import (
	"strings"
	"testing"
)

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

func TestIsReservedSubdomain(t *testing.T) {
	for _, s := range []string{"www", "api", "admin", "dashboard"} {
		if !IsReservedSubdomain(s) {
			t.Errorf("%q should be reserved", s)
		}
	}
	if IsReservedSubdomain("myapp") {
		t.Error("myapp should not be reserved")
	}
}
