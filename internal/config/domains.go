package config

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"net"
	"strings"
	"sync"
	"time"
)

// Errors returned by config operations.
var (
	ErrDomainNotFound      = errors.New("domain not found")
	ErrDomainAlreadyExists = errors.New("domain already exists")
	ErrInvalidDomain       = errors.New("invalid domain")
	ErrDomainNotVerified   = errors.New("domain not verified")
	ErrDNSVerification     = errors.New("DNS verification failed")
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
	VerifyCode  string // stored verification code for DNS TXT record
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

	// lookupTXT resolves TXT records (replaceable in tests).
	lookupTXT func(ctx context.Context, name string) ([]string, error)

	mu sync.RWMutex
}

// SetTXTResolver replaces the DNS TXT lookup used by CheckDNS.
func (m *DomainManager) SetTXTResolver(fn func(ctx context.Context, name string) ([]string, error)) {
	m.mu.Lock()
	m.lookupTXT = fn
	m.mu.Unlock()
}

// normalizeDomain lowercases and trims a domain: DNS names are case-insensitive,
// so "Example.com" and "example.com" must be the same entry.
func normalizeDomain(d string) string {
	return strings.ToLower(strings.TrimSpace(d))
}

// CheckDNS proves ownership of a domain by looking up the TXT record
// "_wirerift.<domain>" and comparing it with the domain's verification code.
// Only on a match is the domain marked verified.
func (m *DomainManager) CheckDNS(ctx context.Context, domain string) error {
	domain = normalizeDomain(domain)
	m.mu.RLock()
	v, ok := m.domains.Load(domain)
	lookup := m.lookupTXT
	m.mu.RUnlock()
	if !ok {
		return ErrDomainNotFound
	}
	if lookup == nil {
		lookup = net.DefaultResolver.LookupTXT
	}

	want := "wirerift-verification=" + v.(*CustomDomain).VerifyCode
	records, err := lookup(ctx, "_wirerift."+domain)
	if err != nil {
		return ErrDNSVerification
	}
	for _, rec := range records {
		if subtle.ConstantTimeCompare([]byte(strings.TrimSpace(rec)), []byte(want)) == 1 {
			return m.VerifyDomain(domain, nil, nil)
		}
	}
	return ErrDNSVerification
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
	domain = normalizeDomain(domain)
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
		Domain:     domain,
		AccountID:  accountID,
		Verified:   false,
		CreatedAt:  time.Now(),
		UpdatedAt:  time.Now(),
		VerifyCode: generateVerificationCode(domain),
	}

	m.domains.Store(domain, custom)
	return custom, nil
}

// RemoveDomain removes a custom domain.
func (m *DomainManager) RemoveDomain(domain string) error {
	domain = normalizeDomain(domain)
	m.mu.Lock()
	defer m.mu.Unlock()

	m.domains.Delete(domain)
	return nil
}

// GetDomain gets a custom domain.
func (m *DomainManager) GetDomain(domain string) (*CustomDomain, error) {
	domain = normalizeDomain(domain)
	m.mu.RLock()
	defer m.mu.RUnlock()
	if v, ok := m.domains.Load(domain); ok {
		return v.(*CustomDomain), nil
	}
	return nil, ErrDomainNotFound
}

// VerifyDomain marks a domain as verified.
func (m *DomainManager) VerifyDomain(domain string, cert, key []byte) error {
	domain = normalizeDomain(domain)
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
	domain = normalizeDomain(domain)
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
	domain = normalizeDomain(domain)
	// Use stored verify code if domain exists, fallback to random for unknown domains
	verifyCode := generateVerificationCode(domain)
	if v, ok := m.domains.Load(domain); ok {
		if cd := v.(*CustomDomain); cd.VerifyCode != "" {
			verifyCode = cd.VerifyCode
		}
	}

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
			Value: "wirerift-verification=" + verifyCode,
			TTL:   300,
		},
	}
	return records, nil
}

// ListDomains lists all domains for an account.
func (m *DomainManager) ListDomains(accountID string) []*CustomDomain {
	var domains []*CustomDomain
	m.domains.Range(func(_, value any) bool {
		d := value.(*CustomDomain)
		if d.AccountID == accountID {
			domains = append(domains, d)
		}
		return true
	})
	return domains
}

// ListAll lists every registered domain regardless of account.
func (m *DomainManager) ListAll() []*CustomDomain {
	var domains []*CustomDomain
	m.domains.Range(func(_, value any) bool {
		domains = append(domains, value.(*CustomDomain))
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
	// Each label: 1-63 chars, no leading/trailing hyphen
	for _, label := range strings.Split(domain, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			if !isValidDomainChar(c) {
				return false
			}
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
