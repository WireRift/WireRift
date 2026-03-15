package config

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"sync"
	"time"
)

// Errors returned by config operations.
var (
	ErrDomainNotFound      = errors.New("domain not found")
	ErrDomainAlreadyExists = errors.New("domain already exists")
	ErrInvalidDomain       = errors.New("invalid domain")
	ErrDomainNotVerified   = errors.New("domain not verified")
)

// CustomDomain represents a custom domain configuration.
type CustomDomain struct {
	Domain      string    // e.g., "app.example.com"
	AccountID   string    // owner account
	TunnelID    string    // associated tunnel
	Verified    bool      // DNS verified
	VerifiedAt  time.Time // when verified
	CreatedAt   time.Time
	UpdatedAt   time.Time
	Certificate []byte // TLS certificate
	PrivateKey  []byte // TLS private key
}

// DNSRecord represents a DNS record for verification.
type DNSRecord struct {
	Type  string // "CNAME" or "TXT"
	Name  string // e.g., "_wirerift.app"
	Value string // e.g., "verify.wirerift.com" or verification code
	TTL   int    // seconds
}

// DomainManager manages custom domains.
type DomainManager struct {
	domains sync.Map // map[string]*CustomDomain

	// Base domain for tunneling
	baseDomain string

	mu sync.RWMutex
}

// NewDomainManager creates a new domain manager.
func NewDomainManager(baseDomain string) *DomainManager {
	if baseDomain == "" {
		baseDomain = "wirerift.com"
	}
	return &DomainManager{
		baseDomain: baseDomain,
	}
}

// AddDomain adds a custom domain.
func (m *DomainManager) AddDomain(domain, accountID string) (*CustomDomain, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Check if domain already exists
	if _, ok := m.domains.Load(domain); ok {
		return nil, ErrDomainAlreadyExists
	}

	// Validate domain
	if !isValidDomain(domain) {
		return nil, ErrInvalidDomain
	}

	custom := &CustomDomain{
		Domain:    domain,
		AccountID: accountID,
		Verified:  false,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	m.domains.Store(domain, custom)
	return custom, nil
}

// RemoveDomain removes a custom domain.
func (m *DomainManager) RemoveDomain(domain string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.domains.Delete(domain)
	return nil
}

// GetDomain gets a custom domain.
func (m *DomainManager) GetDomain(domain string) (*CustomDomain, error) {
	if v, ok := m.domains.Load(domain); ok {
		return v.(*CustomDomain), nil
	}
	return nil, ErrDomainNotFound
}

// VerifyDomain marks a domain as verified.
func (m *DomainManager) VerifyDomain(domain string, cert, key []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	custom, ok := m.domains.Load(domain)
	if !ok {
		return ErrDomainNotFound
	}

	c := custom.(*CustomDomain)
	c.Verified = true
	c.VerifiedAt = time.Now()
	c.UpdatedAt = time.Now()
	c.Certificate = cert
	c.PrivateKey = key

	return nil
}

// SetTunnel associates a tunnel with a domain.
func (m *DomainManager) SetTunnel(domain, tunnelID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	custom, ok := m.domains.Load(domain)
	if !ok {
		return ErrDomainNotFound
	}

	c := custom.(*CustomDomain)
	if !c.Verified {
		return ErrDomainNotVerified
	}

	c.TunnelID = tunnelID
	c.UpdatedAt = time.Now()

	return nil
}

// GetDNSRecords returns the DNS records needed for verification.
func (m *DomainManager) GetDNSRecords(domain string) ([]DNSRecord, error) {
	records := []DNSRecord{
		{
			Type:  "CNAME",
			Name:  domain,
			Value: m.baseDomain,
			TTL:   300,
		},
		{
			Type:  "TXT",
			Name:  "_wirerift." + domain,
			Value: "wirerift-verification=" + generateVerificationCode(domain),
			TTL:   300,
		},
	}
	return records, nil
}

// ListDomains lists all domains for an account.
func (m *DomainManager) ListDomains(accountID string) []*CustomDomain {
	var domains []*CustomDomain
	m.domains.Range(func(key, value any) bool {
		d := value.(*CustomDomain)
		if d.AccountID == accountID {
			domains = append(domains, d)
		}
		return true
	})
	return domains
}

// isValidDomain validates a domain name.
func isValidDomain(domain string) bool {
	if len(domain) == 0 || len(domain) > 253 {
		return false
	}
	// Cannot start or end with dot
	if domain[0] == '.' || domain[len(domain)-1] == '.' {
		return false
	}
	// Basic validation
	for _, c := range domain {
		if !isValidDomainChar(c) {
			return false
		}
	}
	return true
}

func isValidDomainChar(c rune) bool {
	return (c >= 'a' && c <= 'z') ||
		(c >= 'A' && c <= 'Z') ||
		(c >= '0' && c <= '9') ||
		c == '-' ||
		c == '.'
}

func generateVerificationCode(domain string) string {
	// Mix domain into the code so it's domain-bound but still unpredictable
	b := make([]byte, 16)
	rand.Read(b)
	return "wrv_" + domain[:min(8, len(domain))] + "_" + hex.EncodeToString(b[:8])
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
