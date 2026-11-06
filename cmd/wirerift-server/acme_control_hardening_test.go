package main

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/wirerift/wirerift/internal/client"
)

type acmeRoundTripper func(*http.Request) (*http.Response, error)

func (f acmeRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func fakeACMEResponse(status int, body string, headers map[string]string) *http.Response {
	h := make(http.Header)
	for k, v := range headers {
		h.Set(k, v)
	}
	return &http.Response{StatusCode: status, Header: h, Body: io.NopCloser(bytes.NewBufferString(body))}
}

func TestACMEEnabledServerRejectsPlaintextControlConnections(t *testing.T) {
	oldTransport := http.DefaultTransport
	http.DefaultTransport = acmeRoundTripper(func(r *http.Request) (*http.Response, error) {
		switch {
		case r.Method == http.MethodGet && strings.Contains(r.URL.Host, "letsencrypt.org"):
			return fakeACMEResponse(200, `{"newNonce":"https://acme.invalid/nonce","newAccount":"https://acme.invalid/account","newOrder":"https://acme.invalid/order"}`, nil), nil
		case r.Method == http.MethodHead:
			return fakeACMEResponse(200, "", map[string]string{"Replay-Nonce": "nonce"}), nil
		case r.Method == http.MethodPost && r.URL.Path == "/account":
			return fakeACMEResponse(201, `{}`, map[string]string{"Location": "https://acme.invalid/acct/1"}), nil
		default:
			return fakeACMEResponse(500, `{}`, nil), nil
		}
	})
	defer func() { http.DefaultTransport = oldTransport }()

	freeAddr := func() string {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		addr := ln.Addr().String()
		_ = ln.Close()
		return addr
	}
	controlAddr, httpAddr := freeAddr(), freeAddr()
	httpsAddr := freeAddr() // -https must not hit the privileged :443 default: ACME enables the TLS edge, and binding :443 fails for unprivileged runners (CI)
	certDir := t.TempDir()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- run(ctx, []string{
			"-control", controlAddr, "-http", httpAddr, "-https", httpsAddr, "-dashboard-port", "0",
			"-tcp-ports", "49200-49210", "-cert-dir", certDir,
			"-domain", "tunnel.example.com", "-token", "proof-token",
			"-acme-email", "ops@example.com", "-acme-staging",
		})
	}()

	deadline := time.Now().Add(3 * time.Second)
	for {
		conn, err := net.DialTimeout("tcp", controlAddr, 50*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			break
		}
		if time.Now().After(deadline) {
			cancel()
			t.Fatalf("control listener did not start: %v", err)
		}
		time.Sleep(20 * time.Millisecond)
	}

	cfg := client.DefaultConfig()
	cfg.ServerAddr = controlAddr // deliberately no tls:// scheme
	cfg.Token = "proof-token"
	cfg.Reconnect = false
	c := client.New(cfg, nil)
	if err := c.Connect(); err == nil {
		c.Close()
		cancel()
		<-done
		t.Fatal("plaintext client connected while ACME was enabled")
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("server shutdown: %v", err)
	}
}
