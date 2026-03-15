// Package utils provides common utility functions
package utils

import (
	"crypto/rand"
	"encoding/hex"
	"net"
	"strings"
)

// GenerateID generates a random ID with a prefix
func GenerateID(prefix string, length int) string {
	b := make([]byte, length)
	rand.Read(b)
	return prefix + hex.EncodeToString(b)
}

// GenerateShortID generates a short random ID (8 chars)
func GenerateShortID() string {
	return GenerateID("", 4)
}

// ParseAddr parses an address string (host:port)
func ParseAddr(addr string) (host string, port string, err error) {
	h, p, err := net.SplitHostPort(addr)
	if err != nil {
		return "", "", err
	}
	return h, p, nil
}

// JoinHostPort joins host and port
func JoinHostPort(host, port string) string {
	return net.JoinHostPort(host, port)
}

// NormalizeHost normalizes a host header (remove port)
func NormalizeHost(host string) string {
	// Remove port if present
	for i := len(host) - 1; i >= 0; i-- {
		if host[i] == ':' {
			host = host[:i]
			break
		}
	}
	return host
}

// ExtractSubdomain extracts the subdomain from a host
func ExtractSubdomain(host, baseDomain string) string {
	host = NormalizeHost(host)

	// Remove base domain
	suffix := "." + baseDomain
	if len(host) <= len(suffix) {
		return ""
	}
	if !strings.HasSuffix(host, suffix) {
		return ""
	}

	return host[:len(host)-len(suffix)]
}

// IsValidSubdomain checks if a subdomain is valid per RFC 1123.
func IsValidSubdomain(subdomain string) bool {
	if len(subdomain) == 0 || len(subdomain) > 63 {
		return false
	}

	// Must start and end with letter or number (RFC 1123)
	if !isAlphaNum(subdomain[0]) || !isAlphaNum(subdomain[len(subdomain)-1]) {
		return false
	}

	// Check all characters
	for _, c := range subdomain {
		if !isAlphaNum(byte(c)) && c != '-' {
			return false
		}
	}

	return true
}

func isAlphaNum(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
}
