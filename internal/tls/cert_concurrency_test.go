package tls

// Regression test for concurrent certificate issuance. A browser opens
// roughly six TLS connections in parallel, so the first contact with a fresh
// host hits GetCertificate concurrently. Without per-host coalescing every
// caller races the full issue path: with ACME that is one certificate order
// per connection (Let's Encrypt allows 5 duplicate certificates per exact
// hostname set per week, so the extras fail and fall back to an untrusted
// self-signed certificate served on a real connection), and in pure AutoCert
// mode every connection receives a different self-signed certificate. All
// concurrent callers for the same host must receive the SAME certificate.

import (
	"crypto/tls"
	"sync"
	"testing"
)

func TestGetCertificateConcurrentCallersShareOneCertificate(t *testing.T) {
	m := &Manager{
		config: Config{
			Domain:   "wirerift.com",
			CertDir:  t.TempDir(),
			AutoCert: true,
		},
	}

	const callers = 64
	host := "myapp.wirerift.com"

	results := make([]*tls.Certificate, callers)
	start := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(callers)
	for i := 0; i < callers; i++ {
		go func(i int) {
			defer wg.Done()
			<-start // release all callers at once; none can store before the others check the cache
			cert, err := m.GetCertificate(&tls.ClientHelloInfo{ServerName: host})
			if err != nil {
				t.Errorf("caller %d: GetCertificate: %v", i, err)
				return
			}
			results[i] = cert
		}(i)
	}
	close(start)
	wg.Wait()

	distinct := make(map[string]bool)
	for i, cert := range results {
		if cert == nil {
			t.Fatalf("caller %d: no certificate", i)
		}
		if len(cert.Certificate) == 0 {
			t.Fatalf("caller %d: empty certificate chain", i)
		}
		distinct[string(cert.Certificate[0])] = true
	}

	if len(distinct) != 1 {
		t.Fatalf("FAIL: %d concurrent GetCertificate calls for %q produced %d distinct certificates "+
			"(each caller ran its own issuance; with ACME this burns the duplicate-certificate "+
			"rate limit and can serve an untrusted fallback cert), want exactly 1",
			callers, host, len(distinct))
	}

	// Control: a later sequential call must be served from the cache and
	// match the shared certificate.
	again, err := m.GetCertificate(&tls.ClientHelloInfo{ServerName: host})
	if err != nil {
		t.Fatalf("sequential GetCertificate: %v", err)
	}
	if string(again.Certificate[0]) != string(results[0].Certificate[0]) {
		t.Errorf("cached certificate differs from the concurrently issued one")
	}
}
