package integration

import (
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

	"github.com/wirerift/wirerift/internal/auth"
	"github.com/wirerift/wirerift/internal/client"
	"github.com/wirerift/wirerift/internal/server"
)

// selfSigned returns a localhost key pair and its PEM-encoded certificate.
func selfSigned(t *testing.T) (tls.Certificate, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		IsCA:         true, BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key},
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func TestControlPlaneTLS(t *testing.T) {
	cert, certPEM := selfSigned(t)
	caFile := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caFile, certPEM, 0600); err != nil {
		t.Fatal(err)
	}

	authMgr := auth.NewManager()
	cfg := server.DefaultConfig()
	cfg.ControlAddr = "127.0.0.1:0"
	cfg.HTTPAddr = "127.0.0.1:0"
	cfg.AuthManager = authMgr
	cfg.ControlTLSConfig = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	srv := server.New(cfg, nil)
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	defer srv.Stop()

	local := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	}))
	defer local.Close()

	dial := func(addr string) (*client.Client, error) {
		cc := client.DefaultConfig()
		cc.ServerAddr = addr
		cc.Token = authMgr.DevToken()
		cc.Reconnect = false
		c := client.New(cc, nil)
		return c, c.Connect()
	}

	// Trusted CA + tls:// works and can create a tunnel.
	t.Setenv("WIRERIFT_TLS_CA", caFile)
	c, err := dial(client.TLSScheme + srv.ControlAddr())
	if err != nil {
		t.Fatalf("TLS connect: %v", err)
	}
	if _, err := c.HTTP(strings.TrimPrefix(local.URL, "http://"), client.WithSubdomain("tlsok")); err != nil {
		t.Errorf("tunnel over TLS control plane: %v", err)
	}
	c.Close()

	// Without the CA the self-signed certificate must be rejected.
	t.Setenv("WIRERIFT_TLS_CA", "")
	if c, err := dial(client.TLSScheme + srv.ControlAddr()); err == nil {
		c.Close()
		t.Error("untrusted certificate was accepted")
	}

	// A plaintext client cannot talk to a TLS control plane.
	if c, err := dial(srv.ControlAddr()); err == nil {
		c.Close()
		t.Error("plaintext client connected to TLS control plane")
	}
}
