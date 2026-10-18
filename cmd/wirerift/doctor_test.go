package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func doctorOutput(t *testing.T, server, token string) (string, int) {
	t.Helper()
	var out bytes.Buffer
	failures := runDoctor(context.Background(), &out, server, token)
	return out.String(), failures
}

func TestDoctorHealthyServer(t *testing.T) {
	defer lockGOMAXPROCS()()
	addr, cleanup := startMockTunnelServer(t)
	defer cleanup()

	out, failures := doctorOutput(t, addr, "secret-token")
	if failures != 0 || !strings.Contains(out, "All checks passed.") {
		t.Fatalf("failures=%d\n%s", failures, out)
	}
	for _, want := range []string{"Server address", "TCP connect", "Encryption", "Authentication", "logged in"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "secret-token") {
		t.Error("the token was printed")
	}
}

func TestDoctorStopsAtFirstBrokenStep(t *testing.T) {
	// Closed port: TCP fails, so no TLS/auth steps run.
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	addr := ln.Addr().String()
	ln.Close()
	out, failures := doctorOutput(t, addr, "x")
	if failures != 1 || !strings.Contains(out, "✗  TCP connect") || strings.Contains(out, "Authentication") {
		t.Errorf("failures=%d\n%s", failures, out)
	}

	out, failures = doctorOutput(t, "nonexistent.invalid:4443", "x")
	if failures != 1 || !strings.Contains(out, "✗  DNS") || strings.Contains(out, "TCP connect") {
		t.Errorf("DNS: failures=%d\n%s", failures, out)
	}

	out, failures = doctorOutput(t, "no-port-here", "x")
	if failures != 1 || !strings.Contains(out, "is not host:port") {
		t.Errorf("address: failures=%d\n%s", failures, out)
	}
}

func TestDoctorWithoutToken(t *testing.T) {
	defer lockGOMAXPROCS()()
	addr, cleanup := startMockTunnelServer(t)
	defer cleanup()
	out, failures := doctorOutput(t, addr, "")
	if failures != 0 || !strings.Contains(out, "!  Authentication") || !strings.Contains(out, "1 warning") {
		t.Errorf("failures=%d\n%s", failures, out)
	}
}

func TestDoctorWarnsAboutCleartextOnRemoteHosts(t *testing.T) {
	var out bytes.Buffer
	d := &doctor{out: &out}
	if !d.checkTransport(context.Background(), "203.0.113.7:4443", "203.0.113.7", false) {
		t.Fatal("cleartext must warn, not stop")
	}
	if d.warnings != 1 || !strings.Contains(out.String(), "cleartext") || !strings.Contains(out.String(), "tls://203.0.113.7:4443") {
		t.Errorf("warnings=%d\n%s", d.warnings, out.String())
	}
	out.Reset()
	d = &doctor{out: &out}
	d.checkTransport(context.Background(), "127.0.0.1:4443", "127.0.0.1", false)
	if d.warnings != 0 {
		t.Errorf("loopback should not warn:\n%s", out.String())
	}
}

func tlsListener(t *testing.T, notAfter time.Time) (addr, caFile string) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: "localhost"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: notAfter,
		DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { _ = c.(*tls.Conn).Handshake(); c.Close() }()
		}
	}()
	caFile = filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	return ln.Addr().String(), caFile
}

func TestDoctorTLS(t *testing.T) {
	addr, caFile := tlsListener(t, time.Now().Add(90*24*time.Hour))

	// Untrusted certificate: fails with a hint about WIRERIFT_TLS_CA.
	t.Setenv("WIRERIFT_TLS_CA", "")
	out, failures := doctorOutput(t, "tls://"+addr, "")
	if failures != 1 || !strings.Contains(out, "✗  TLS") || !strings.Contains(out, "WIRERIFT_TLS_CA") {
		t.Errorf("untrusted: failures=%d\n%s", failures, out)
	}

	// Trusted through WIRERIFT_TLS_CA.
	t.Setenv("WIRERIFT_TLS_CA", caFile)
	out, failures = doctorOutput(t, "tls://"+addr, "")
	if failures != 0 || !strings.Contains(out, "✓  TLS") || !strings.Contains(out, "expires in") {
		t.Errorf("trusted: failures=%d\n%s", failures, out)
	}

	// Unreadable CA file.
	t.Setenv("WIRERIFT_TLS_CA", filepath.Join(t.TempDir(), "missing.pem"))
	out, failures = doctorOutput(t, "tls://"+addr, "")
	if failures != 1 || !strings.Contains(out, "WIRERIFT_TLS_CA") {
		t.Errorf("bad CA file: failures=%d\n%s", failures, out)
	}
}

func TestDoctorWarnsWhenCertificateExpiresSoon(t *testing.T) {
	addr, caFile := tlsListener(t, time.Now().Add(3*24*time.Hour))
	t.Setenv("WIRERIFT_TLS_CA", caFile)
	out, failures := doctorOutput(t, "tls://"+addr, "")
	if failures != 0 || !strings.Contains(out, "!  TLS") || !strings.Contains(out, "expires soon") {
		t.Errorf("failures=%d\n%s", failures, out)
	}
}

func TestDoctorTLSToPlainServerFails(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler()) // speaks plain HTTP, not TLS
	defer srv.Close()
	out, failures := doctorOutput(t, "tls://"+strings.TrimPrefix(srv.URL, "http://"), "")
	if failures != 1 || !strings.Contains(out, "handshake failed") {
		t.Errorf("failures=%d\n%s", failures, out)
	}
}

func TestDoctorSilentServerTimesOutAuthentication(t *testing.T) {
	old := doctorAuthTimeout
	doctorAuthTimeout = 300 * time.Millisecond
	defer func() { doctorAuthTimeout = old }()
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			defer c.Close() // accept and say nothing
		}
	}()
	out, failures := doctorOutput(t, ln.Addr().String(), "tok")
	if failures != 1 || !strings.Contains(out, "no answer from the server") {
		t.Errorf("failures=%d\n%s", failures, out)
	}
}

func TestDoDoctorExitStatusAndFlags(t *testing.T) {
	defer lockGOMAXPROCS()()
	addr, cleanup := startMockTunnelServer(t)
	defer cleanup()
	if err := doDoctor(context.Background(), []string{"wirerift", "doctor", "-server", addr, "-token", "t"}); err != nil {
		t.Errorf("healthy: %v", err)
	}
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	dead := ln.Addr().String()
	ln.Close()
	assertErrContains(t, doDoctor(context.Background(), []string{"wirerift", "doctor", "-server", dead}), "problem")
	assertErrContains(t, doDoctor(context.Background(), []string{"wirerift", "doctor", "-bogus"}), "")
	assertNoErr(t, run([]string{"wirerift", "help"}))
	if err := run([]string{"wirerift", "doctor", "-server", dead}); err == nil {
		t.Error("run(doctor) must fail for an unreachable server")
	}
}

func TestIsLoopbackAndTLSVersionName(t *testing.T) {
	for host, want := range map[string]bool{"localhost": true, "app.localhost": true, "127.0.0.1": true, "::1": true, "example.com": false, "10.0.0.1": false} {
		if isLoopback(host) != want {
			t.Errorf("isLoopback(%q) != %v", host, want)
		}
	}
	if tlsVersionName(tls.VersionTLS13) != "TLS 1.3" || tlsVersionName(tls.VersionTLS12) != "TLS 1.2" || !strings.HasPrefix(tlsVersionName(0x0301), "TLS 0x") {
		t.Error("tlsVersionName")
	}
}
