// Package utils provides common utility functions
package utils

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
		if c > 127 || (!isAlphaNum(byte(c)) && c != '-') {
			return false
		}
	}

	return true
}

func isAlphaNum(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
}

// reservedSubdomains are names an operator or user would reasonably expect to
// belong to the service itself; tunnels cannot claim them.
var reservedSubdomains = map[string]bool{
	"www": true, "api": true, "admin": true, "dashboard": true, "app": true,
	"mail": true, "smtp": true, "ftp": true, "ns1": true, "ns2": true,
	"status": true, "wirerift": true, "localhost": true, "root": true,
	"support": true, "help": true, "login": true, "auth": true,
}

// IsReservedSubdomain reports whether a (lowercase) subdomain is reserved.
func IsReservedSubdomain(subdomain string) bool {
	return reservedSubdomains[subdomain]
}
