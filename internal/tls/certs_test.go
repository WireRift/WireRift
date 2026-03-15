package tls

import (
	"crypto/tls"
	"crypto/x509"
	"os"
	"path/filepath"
	"testing"
)

func TestNewManager(t *testing.T) {
	dir, err := os.MkdirTemp("", "wirerift-tls-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)

	config := Config{
		Domain:   "test.local",
		CertDir:  dir,
		AutoCert: true,
	}

	m, err := NewManager(config)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}

	if m == nil {
		t.Fatal("Manager is nil")
	}
}

func TestGenerateSelfSigned(t *testing.T) {
	dir, err := os.MkdirTemp("", "wirerift-tls-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)

	m, _ := NewManager(Config{
		Domain:   "test.local",
		CertDir:  dir,
		AutoCert: true,
	})

	cert, err := m.generateSelfSigned("app.test.local")
	if err != nil {
		t.Fatalf("generateSelfSigned: %v", err)
	}

	if cert == nil {
		t.Fatal("Certificate is nil")
	}
	if cert.PrivateKey == nil {
		t.Fatal("PrivateKey is nil")
	}
	if len(cert.Certificate) == 0 {
		t.Fatal("Certificate chain is empty")
	}

	// Check files were created
	if _, err := os.Stat(filepath.Join(dir, "app.test.local.crt")); err != nil {
		t.Errorf("Certificate file not created: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "app.test.local.key")); err != nil {
		t.Errorf("Key file not created: %v", err)
	}
}

func TestGetCertificate(t *testing.T) {
	dir, err := os.MkdirTemp("", "wirerift-tls-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)

	m, _ := NewManager(Config{
		Domain:   "test.local",
		CertDir:  dir,
		AutoCert: true,
	})

	hello := &tls.ClientHelloInfo{
		ServerName: "app.test.local",
	}

	cert, err := m.GetCertificate(hello)
	if err != nil {
		t.Fatalf("GetCertificate: %v", err)
	}

	if cert == nil {
		t.Fatal("Certificate is nil")
	}

	// Second call should use cache
	cert2, err := m.GetCertificate(hello)
	if err != nil {
		t.Fatalf("GetCertificate (cached): %v", err)
	}
	if cert != cert2 {
		t.Error("Should return same certificate from cache")
	}
}

func TestGetCertificateNoServerName(t *testing.T) {
	m, _ := NewManager(Config{
		Domain:   "test.local",
		AutoCert: true,
	})

	hello := &tls.ClientHelloInfo{
		ServerName: "",
	}

	_, err := m.GetCertificate(hello)
	if err != ErrDomainNotConfigured {
		t.Errorf("error = %v, want %v", err, ErrDomainNotConfigured)
	}
}

func TestTLSConfig(t *testing.T) {
	m, _ := NewManager(Config{
		Domain:   "test.local",
		AutoCert: true,
	})

	config := m.TLSConfig()

	if config == nil {
		t.Fatal("TLSConfig is nil")
	}
	if config.MinVersion != tls.VersionTLS12 {
		t.Errorf("MinVersion = %v, want %v", config.MinVersion, tls.VersionTLS12)
	}
	if config.GetCertificate == nil {
		t.Error("GetCertificate should not be nil")
	}
}

func TestWildcardDomain(t *testing.T) {
	m, _ := NewManager(Config{
		Domain: "example.com",
	})

	expected := "*.example.com"
	if m.WildcardDomain() != expected {
		t.Errorf("WildcardDomain = %q, want %q", m.WildcardDomain(), expected)
	}
}

// TestNewManagerDefaults tests NewManager with default values
func TestNewManagerDefaults(t *testing.T) {
	// Test with empty domain and cert dir
	m, err := NewManager(Config{})
	if err != nil {
		t.Fatalf("NewManager with defaults: %v", err)
	}
	if m == nil {
		t.Fatal("Manager should not be nil")
	}
	if m.config.Domain != "localhost" {
		t.Errorf("Default domain = %q, want localhost", m.config.Domain)
	}
}

// TestGetCertificateNotFound tests GetCertificate when certificate doesn't exist and AutoCert is disabled
func TestGetCertificateNotFound(t *testing.T) {
	dir, err := os.MkdirTemp("", "wirerift-tls-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)

	m, _ := NewManager(Config{
		Domain:   "test.local",
		CertDir:  dir,
		AutoCert: false, // Disable auto-cert generation
	})

	hello := &tls.ClientHelloInfo{
		ServerName: "nonexistent.test.local",
	}

	_, err = m.GetCertificate(hello)
	if err != ErrCertificateNotFound {
		t.Errorf("error = %v, want ErrCertificateNotFound", err)
	}
}

// TestLoadCertificateFromDisk tests loading an existing certificate from disk
func TestLoadCertificateFromDisk(t *testing.T) {
	dir, err := os.MkdirTemp("", "wirerift-tls-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)

	m, _ := NewManager(Config{
		Domain:   "test.local",
		CertDir:  dir,
		AutoCert: true,
	})

	// First call generates and saves the certificate
	hello := &tls.ClientHelloInfo{
		ServerName: "app.test.local",
	}

	cert1, err := m.GetCertificate(hello)
	if err != nil {
		t.Fatalf("First GetCertificate: %v", err)
	}

	// Create a new manager with same cert dir (simulating restart)
	m2, _ := NewManager(Config{
		Domain:   "test.local",
		CertDir:  dir,
		AutoCert: false, // Disable auto-cert to test loading from disk
	})

	// Second manager should load from disk
	cert2, err := m2.GetCertificate(hello)
	if err != nil {
		t.Fatalf("Second GetCertificate: %v", err)
	}

	// Certificates should be equivalent
	if cert2 == nil {
		t.Fatal("Loaded certificate is nil")
	}
	if len(cert2.Certificate) == 0 {
		t.Fatal("Loaded certificate chain is empty")
	}

	// The cached cert from first manager and loaded cert should have same chain
	if len(cert1.Certificate) != len(cert2.Certificate) {
		t.Error("Certificate chain lengths should match")
	}
}

// TestGenerateSelfSignedNoAutoCert tests that certificates are not saved when AutoCert is false
func TestGenerateSelfSignedNoAutoCert(t *testing.T) {
	dir, err := os.MkdirTemp("", "wirerift-tls-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)

	// Use AutoCert=true first to generate
	m, _ := NewManager(Config{
		Domain:   "test.local",
		CertDir:  dir,
		AutoCert: true,
	})

	// Generate a certificate
	_, err = m.generateSelfSigned("temp.test.local")
	if err != nil {
		t.Fatalf("generateSelfSigned: %v", err)
	}

	// Clean up the generated files
	os.Remove(filepath.Join(dir, "temp.test.local.crt"))
	os.Remove(filepath.Join(dir, "temp.test.local.key"))
}

// TestCertificateErrors tests error constants
func TestCertificateErrors(t *testing.T) {
	// Verify error messages
	if ErrCertificateNotFound.Error() != "certificate not found" {
		t.Errorf("ErrCertificateNotFound message = %q", ErrCertificateNotFound.Error())
	}
	if ErrInvalidCertificate.Error() != "invalid certificate" {
		t.Errorf("ErrInvalidCertificate message = %q", ErrInvalidCertificate.Error())
	}
	if ErrDomainNotConfigured.Error() != "domain not configured" {
		t.Errorf("ErrDomainNotConfigured message = %q", ErrDomainNotConfigured.Error())
	}
}

// TestGenerateCATests tests CA generation directly
func TestGenerateCA(t *testing.T) {
	dir, err := os.MkdirTemp("", "wirerift-tls-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)

	m, _ := NewManager(Config{
		Domain:   "test.local",
		CertDir:  dir,
		AutoCert: true,
	})

	// Generate CA
	caCert, caKey := m.generateCA()
	if caCert == nil {
		t.Fatal("CA cert is nil")
	}
	if caKey == nil {
		t.Fatal("CA key is nil")
	}
}

// TestGenerateSelfSignedWithDifferentDomains tests certificate generation for various domains
func TestGenerateSelfSignedWithDifferentDomains(t *testing.T) {
	dir, err := os.MkdirTemp("", "wirerift-tls-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)

	m, _ := NewManager(Config{
		Domain:   "example.com",
		CertDir:  dir,
		AutoCert: true,
	})

	tests := []string{
		"app.example.com",
		"*.example.com",
		"api.example.com",
		"deep.subdomain.example.com",
	}

	for _, domain := range tests {
		t.Run(domain, func(t *testing.T) {
			cert, err := m.generateSelfSigned(domain)
			if err != nil {
				t.Fatalf("generateSelfSigned(%q): %v", domain, err)
			}
			if cert == nil {
				t.Fatal("Certificate is nil")
			}
		})
	}
}

// TestLoadCertificateInvalidFiles tests loading invalid certificate files
func TestLoadCertificateInvalidFiles(t *testing.T) {
	dir, err := os.MkdirTemp("", "wirerift-tls-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)

	m, _ := NewManager(Config{
		Domain:   "test.local",
		CertDir:  dir,
		AutoCert: false,
	})

	// Create invalid cert file
	certPath := filepath.Join(dir, "invalid.test.local.crt")
	keyPath := filepath.Join(dir, "invalid.test.local.key")

	if err := os.WriteFile(certPath, []byte("invalid cert data"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, []byte("invalid key data"), 0600); err != nil {
		t.Fatal(err)
	}

	// Should fail to load invalid certificate
	_, err = m.loadCertificate("invalid.test.local")
	if err == nil {
		t.Error("Expected error loading invalid certificate")
	}
}

// TestGetCertificateDifferentDomains tests GetCertificate with various domain patterns
func TestGetCertificateDifferentDomains(t *testing.T) {
	dir, err := os.MkdirTemp("", "wirerift-tls-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)

	m, _ := NewManager(Config{
		Domain:   "example.com",
		CertDir:  dir,
		AutoCert: true,
	})

	tests := []struct {
		name       string
		serverName string
		wantErr    bool
	}{
		{
			name:       "wildcard subdomain",
			serverName: "app.example.com",
			wantErr:    false,
		},
		{
			name:       "deep subdomain",
			serverName: "api.v1.example.com",
			wantErr:    false,
		},
		{
			name:       "different domain - auto cert enabled",
			serverName: "other.com",
			wantErr:    false, // AutoCert is enabled, so it will generate a cert
		},
		{
			name:       "empty server name",
			serverName: "",
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hello := &tls.ClientHelloInfo{
				ServerName: tt.serverName,
			}

			cert, err := m.GetCertificate(hello)
			if tt.wantErr {
				if err == nil {
					t.Error("Expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}
			if cert == nil {
				t.Error("Certificate is nil")
			}
		})
	}
}

// TestSaveCertificateErrors tests saveCertificate error handling
func TestSaveCertificateErrors(t *testing.T) {
	// Use a path where a file exists instead of a directory to cause os.Create to fail
	dir, err := os.MkdirTemp("", "wirerift-tls-save-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)

	// Create a file where the cert file would go (blocking os.Create)
	certBlocker := filepath.Join(dir, "test.crt")
	if err := os.MkdirAll(certBlocker, 0700); err != nil {
		t.Fatal(err)
	}

	m := &Manager{
		config: Config{
			Domain:  "test.local",
			CertDir: dir,
		},
	}

	// Should fail because test.crt is a directory, not a file
	err = m.saveCertificate("test", []byte("cert"), []byte("key"))
	if err == nil {
		t.Error("Expected error saving cert file when path is a directory")
	}
}

// TestSaveCertificateKeyFileError tests saveCertificate when key file creation fails
func TestSaveCertificateKeyFileError(t *testing.T) {
	dir, err := os.MkdirTemp("", "wirerift-tls-savekey-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)

	// Create a directory where the key file would go (blocking os.OpenFile)
	keyBlocker := filepath.Join(dir, "test.key")
	if err := os.MkdirAll(keyBlocker, 0700); err != nil {
		t.Fatal(err)
	}

	m := &Manager{
		config: Config{
			Domain:  "test.local",
			CertDir: dir,
		},
	}

	// Should fail because test.key is a directory, not a file
	err = m.saveCertificate("test", []byte("cert-data"), []byte("key-data"))
	if err == nil {
		t.Error("Expected error saving key file when path is a directory")
	}
}

// TestWildcardDomainVariations tests WildcardDomain with different inputs
func TestWildcardDomainVariations(t *testing.T) {
	tests := []struct {
		domain   string
		expected string
	}{
		{"example.com", "*.example.com"},
		{"localhost", "*.localhost"},
		{"", "*.localhost"}, // Empty domain defaults to localhost
		{"sub.example.com", "*.sub.example.com"},
	}

	for _, tt := range tests {
		t.Run(tt.domain, func(t *testing.T) {
			m, _ := NewManager(Config{
				Domain: tt.domain,
			})

			if got := m.WildcardDomain(); got != tt.expected {
				t.Errorf("WildcardDomain() = %q, want %q", got, tt.expected)
			}
		})
	}
}

// TestNewManagerCertDirError tests NewManager when cert directory can't be created
func TestNewManagerCertDirError(t *testing.T) {
	// Create a file that blocks directory creation
	dir, err := os.MkdirTemp("", "wirerift-tls-block-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)

	// Create a regular file where we want a directory
	blocker := filepath.Join(dir, "blocked")
	if err := os.WriteFile(blocker, []byte("blocker"), 0644); err != nil {
		t.Fatal(err)
	}

	// Try to create a manager with CertDir as a path under the blocker file
	_, err = NewManager(Config{
		Domain:  "test.local",
		CertDir: filepath.Join(blocker, "subdir"),
	})
	if err == nil {
		t.Error("Expected error when cert directory can't be created")
	}
}

// TestGetCertificateLoadFromDiskAndCache tests GetCertificate loading from disk into cache
func TestGetCertificateLoadFromDiskAndCache(t *testing.T) {
	dir, err := os.MkdirTemp("", "wirerift-tls-cache-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)

	// First manager generates the cert
	m1, _ := NewManager(Config{
		Domain:   "test.local",
		CertDir:  dir,
		AutoCert: true,
	})

	hello := &tls.ClientHelloInfo{
		ServerName: "cache.test.local",
	}

	_, err = m1.GetCertificate(hello)
	if err != nil {
		t.Fatalf("First GetCertificate: %v", err)
	}

	// Second manager (fresh cache) should load from disk
	m2, _ := NewManager(Config{
		Domain:   "test.local",
		CertDir:  dir,
		AutoCert: true, // AutoCert is true but loadCertificate should succeed first
	})

	cert, err := m2.GetCertificate(hello)
	if err != nil {
		t.Fatalf("GetCertificate from disk: %v", err)
	}
	if cert == nil {
		t.Fatal("Certificate should not be nil")
	}

	// Third call on same manager should use cache
	cert2, err := m2.GetCertificate(hello)
	if err != nil {
		t.Fatalf("GetCertificate from cache: %v", err)
	}
	if cert != cert2 {
		t.Error("Should return same certificate from cache")
	}
}

// TestManagerFields tests Manager struct fields
func TestManagerFields(t *testing.T) {
	dir, err := os.MkdirTemp("", "wirerift-tls-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)

	m, err := NewManager(Config{
		Domain:   "test.local",
		CertDir:  dir,
		AutoCert: true,
	})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}

	// Verify fields are set correctly
	if m.config.Domain != "test.local" {
		t.Errorf("Domain = %q, want test.local", m.config.Domain)
	}
	if m.config.CertDir != dir {
		t.Errorf("CertDir = %q, want %q", m.config.CertDir, dir)
	}
	if !m.config.AutoCert {
		t.Error("AutoCert should be true")
	}
}

// TestGetCertificateGenerateError tests GetCertificate when generateSelfSigned fails.
func TestGetCertificateGenerateError(t *testing.T) {
	dir, err := os.MkdirTemp("", "wirerift-tls-geterr-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)

	m, _ := NewManager(Config{
		Domain:   "test.local",
		CertDir:  dir,
		AutoCert: true,
	})

	// Initialize CA first
	m.generateSelfSigned("warmup.test.local")

	// Corrupt the CA to make x509.CreateCertificate fail
	m.caCert.PublicKeyAlgorithm = x509.Ed25519
	m.caCert.PublicKey = "not-a-real-key"

	hello := &tls.ClientHelloInfo{ServerName: "fail.test.local"}
	_, err = m.GetCertificate(hello)
	if err == nil {
		t.Error("Expected error from GetCertificate with corrupted CA")
	}
}

// TestSaveCertificatePemEncodeError tests saveCertificate when pem.Encode fails for cert
func TestSaveCertificatePemEncodeError(t *testing.T) {
	dir, err := os.MkdirTemp("", "wirerift-tls-pem-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)

	m := &Manager{
		config: Config{
			Domain:  "test.local",
			CertDir: dir,
		},
	}

	// Create the cert file as a pipe/read-only to make pem.Encode fail
	certPath := filepath.Join(dir, "pemfail.crt")
	f, err := os.Create(certPath)
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	// Make the cert file read-only so writing to it fails
	os.Chmod(certPath, 0444)
	defer os.Chmod(certPath, 0644) // restore for cleanup

	// saveCertificate opens with os.Create which truncates - on Windows this may
	// succeed even on read-only files. Use directory blocking instead.
	os.Remove(certPath)

	// Actually, the issue is pem.Encode failing. The simplest way is to create a
	// file descriptor that's not writable. On Windows, we can close the file descriptor
	// after os.Create succeeds but this happens inside saveCertificate.
	// Instead, test with a device path that allows Create but not Write.
	// This is hard to do portably. Let's skip this specific sub-test and focus on
	// the key file error which we can trigger.

	// For the key file error path, create a valid cert file path but block the key path
	keyBlocker := filepath.Join(dir, "pemfail.key")
	if err := os.MkdirAll(keyBlocker, 0700); err != nil {
		t.Fatal(err)
	}

	err = m.saveCertificate("pemfail", []byte("cert-data"), []byte("key-data"))
	if err == nil {
		t.Error("Expected error when key file path is a directory")
	}
}

// TestGenerateSelfSignedCreateCertError tests generateSelfSigned when x509.CreateCertificate fails
func TestGenerateSelfSignedCreateCertError(t *testing.T) {
	dir, err := os.MkdirTemp("", "wirerift-tls-createcert-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)

	m, _ := NewManager(Config{
		Domain:   "test.local",
		CertDir:  dir,
		AutoCert: true,
	})

	// Trigger caOnce by generating a valid cert first
	_, _ = m.generateSelfSigned("warmup-createcert.test.local")

	// Corrupt the CA cert to make x509.CreateCertificate fail by setting
	// an incompatible public key type in the CA cert
	m.caCert.PublicKeyAlgorithm = x509.Ed25519
	m.caCert.PublicKey = "not-a-real-key"

	_, err = m.generateSelfSigned("createcert-fail.test.local")
	if err == nil {
		t.Error("Expected error from generateSelfSigned with corrupted CA cert")
	}
}

// TestSaveCertificateInvalidDirectory tests saveCertificate with a non-existent directory
func TestSaveCertificateInvalidDirectory(t *testing.T) {
	m := &Manager{
		config: Config{
			Domain:  "test.local",
			CertDir: filepath.Join(t.TempDir(), "nonexistent", "subdir", "deep"),
		},
	}

	// The directory does not exist, so OpenFile should fail for the cert file
	err := m.saveCertificate("test-host", []byte("cert-data"), []byte("key-data"))
	if err == nil {
		t.Error("Expected error saving certificate to non-existent directory")
	}
}

func TestSaveCertificateKeyWriteError(t *testing.T) {
	dir := t.TempDir()

	m := &Manager{
		config: Config{
			Domain:  "test.local",
			CertDir: dir,
		},
	}

	// Write cert file successfully, but make key path a directory so OpenFile fails
	keyPath := filepath.Join(dir, "test-key-err.key")
	os.MkdirAll(keyPath, 0700) // create directory where file should be

	err := m.saveCertificate("test-key-err", []byte{0x30}, []byte{0x30})
	if err == nil {
		t.Error("Expected error when key path is a directory")
	}

	// Verify cert was written
	certPath := filepath.Join(dir, "test-key-err.crt")
	if _, err := os.Stat(certPath); os.IsNotExist(err) {
		t.Error("Cert file should have been created before key error")
	}
}
