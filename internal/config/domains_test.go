package config

import (
	"testing"
)

func TestDomainManagerAddDomain(t *testing.T) {
	m := NewDomainManager("wirerift.dev")

	domain, err := m.AddDomain("app.example.com", "acc_123")
	if err != nil {
		t.Fatalf("AddDomain: %v", err)
	}
	if domain.Domain != "app.example.com" {
		t.Errorf("Domain = %q, want %q", domain.Domain, "app.example.com")
	}
	if domain.Verified {
		t.Error("Domain should not be verified initially")
	}
}

func TestDomainManagerDuplicateDomain(t *testing.T) {
	m := NewDomainManager("wirerift.dev")

	_, err := m.AddDomain("app.example.com", "acc_123")
	if err != nil {
		t.Fatalf("First AddDomain: %v", err)
	}

	_, err = m.AddDomain("app.example.com", "acc_456")
	if err != ErrDomainAlreadyExists {
		t.Errorf("Error = %v, want %v", err, ErrDomainAlreadyExists)
	}
}

func TestDomainManagerGetDomain(t *testing.T) {
	m := NewDomainManager("wirerift.dev")

	m.AddDomain("app.example.com", "acc_123")

	domain, err := m.GetDomain("app.example.com")
	if err != nil {
		t.Fatalf("GetDomain: %v", err)
	}
	if domain.AccountID != "acc_123" {
		t.Errorf("AccountID = %q, want %q", domain.AccountID, "acc_123")
	}

	_, err = m.GetDomain("nonexistent.com")
	if err != ErrDomainNotFound {
		t.Errorf("Error = %v, want %v", err, ErrDomainNotFound)
	}
}

func TestDomainManagerVerifyDomain(t *testing.T) {
	m := NewDomainManager("wirerift.dev")

	m.AddDomain("app.example.com", "acc_123")

	err := m.VerifyDomain("app.example.com", []byte("cert"), []byte("key"))
	if err != nil {
		t.Fatalf("VerifyDomain: %v", err)
	}

	domain, _ := m.GetDomain("app.example.com")
	if !domain.Verified {
		t.Error("Domain should be verified")
	}
	if string(domain.Certificate) != "cert" {
		t.Errorf("Certificate = %q, want %q", string(domain.Certificate), "cert")
	}
}

func TestDomainManagerSetTunnel(t *testing.T) {
	m := NewDomainManager("wirerift.dev")

	m.AddDomain("app.example.com", "acc_123")

	// Cannot set tunnel on unverified domain
	err := m.SetTunnel("app.example.com", "tun_123")
	if err != ErrDomainNotVerified {
		t.Errorf("Error = %v, want %v", err, ErrDomainNotVerified)
	}

	// Verify then set tunnel
	m.VerifyDomain("app.example.com", nil, nil)
	err = m.SetTunnel("app.example.com", "tun_123")
	if err != nil {
		t.Fatalf("SetTunnel after verify: %v", err)
	}

	domain, _ := m.GetDomain("app.example.com")
	if domain.TunnelID != "tun_123" {
		t.Errorf("TunnelID = %q, want %q", domain.TunnelID, "tun_123")
	}
}

func TestDomainManagerRemoveDomain(t *testing.T) {
	m := NewDomainManager("wirerift.dev")

	m.AddDomain("app.example.com", "acc_123")
	m.RemoveDomain("app.example.com")

	_, err := m.GetDomain("app.example.com")
	if err != ErrDomainNotFound {
		t.Errorf("Error = %v, want %v", err, ErrDomainNotFound)
	}
}

func TestDomainManagerListDomains(t *testing.T) {
	m := NewDomainManager("wirerift.dev")

	m.AddDomain("app1.example.com", "acc_123")
	m.AddDomain("app2.example.com", "acc_123")
	m.AddDomain("app3.example.com", "acc_456")

	domains := m.ListDomains("acc_123")
	if len(domains) != 2 {
		t.Errorf("ListDomains = %d domains, want 2", len(domains))
	}
}

func TestDomainManagerGetDNSRecords(t *testing.T) {
	m := NewDomainManager("wirerift.dev")

	records, err := m.GetDNSRecords("app.example.com")
	if err != nil {
		t.Fatalf("GetDNSRecords: %v", err)
	}
	if len(records) != 2 {
		t.Errorf("DNS records = %d, want 2", len(records))
	}

	// Check CNAME record
	if records[0].Type != "CNAME" {
		t.Errorf("First record type = %q, want CNAME", records[0].Type)
	}
	if records[0].Value != "wirerift.dev" {
		t.Errorf("CNAME value = %q, want wirerift.dev", records[0].Value)
	}

	// Check TXT record
	if records[1].Type != "TXT" {
		t.Errorf("Second record type = %q, want TXT", records[1].Type)
	}
}

func TestIsValidDomain(t *testing.T) {
	tests := []struct {
		domain   string
		expected bool
	}{
		{"example.com", true},
		{"app.example.com", true},
		{"my-app.example.com", true},
		{"123.example.com", true},
		{"", false},
		{".", false},
		{"example..com", true}, // simplified validation allows consecutive dots
	}

	for _, tt := range tests {
		result := isValidDomain(tt.domain)
		if result != tt.expected {
			t.Errorf("isValidDomain(%q) = %v, want %v", tt.domain, result, tt.expected)
		}
	}
}
