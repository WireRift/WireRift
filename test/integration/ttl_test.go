package integration

import (
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/wirerift/wirerift/internal/auth"
	"github.com/wirerift/wirerift/internal/client"
	"github.com/wirerift/wirerift/internal/server"
)

func ttlEnv(t *testing.T) (*server.Server, *client.Client, string) {
	t.Helper()
	authMgr := auth.NewManager()
	cfg := server.DefaultConfig()
	cfg.ControlAddr, cfg.HTTPAddr, cfg.AuthManager = "127.0.0.1:0", "127.0.0.1:0", authMgr
	cfg.TCPAddrRange = "31000-31050"
	srv := server.New(cfg, nil)
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { srv.Stop() })

	cc := client.DefaultConfig()
	cc.ServerAddr, cc.Token, cc.Reconnect = srv.ControlAddr(), authMgr.DevToken(), false
	c := client.New(cc, nil)
	if err := c.Connect(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return srv, c, cfg.Domain
}

func edgeStatus(t *testing.T, srv *server.Server, host string) int {
	t.Helper()
	req, _ := http.NewRequest("GET", "http://"+srv.HTTPAddr()+"/", nil)
	req.Host = host
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
	return resp.StatusCode
}

func TestHTTPTunnelExpiresAfterTTL(t *testing.T) {
	srv, c, domain := ttlEnv(t)
	local := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok")) }))
	defer local.Close()

	tun, err := c.HTTP(strings.TrimPrefix(local.URL, "http://"), client.WithSubdomain("ttl"), client.WithTTL(1500*time.Millisecond))
	if err != nil {
		t.Fatal(err)
	}
	if tun.ExpiresAt.IsZero() || time.Until(tun.ExpiresAt) > 3*time.Second {
		t.Fatalf("ExpiresAt = %v", tun.ExpiresAt)
	}
	host := "ttl." + domain
	if got := edgeStatus(t, srv, host); got != 200 {
		t.Fatalf("before expiry: status %d", got)
	}

	// The dashboard/API listing shows the deadline.
	var listed bool
	for _, ti := range srv.ListTunnels() {
		if ti.ID == tun.ID && ti.ExpiresAt != nil {
			listed = true
		}
	}
	if !listed {
		t.Error("ListTunnels does not expose expires_at")
	}

	deadline := time.Now().Add(6 * time.Second)
	for time.Now().Before(deadline) && edgeStatus(t, srv, host) == 200 {
		time.Sleep(100 * time.Millisecond)
	}
	if got := edgeStatus(t, srv, host); got != 502 {
		t.Fatalf("after expiry: status %d, want 502 (tunnel gone)", got)
	}

	// The subdomain is free again.
	if _, err := c.HTTP(strings.TrimPrefix(local.URL, "http://"), client.WithSubdomain("ttl")); err != nil {
		t.Errorf("subdomain not released after expiry: %v", err)
	}
}

func TestTunnelWithoutTTLDoesNotExpire(t *testing.T) {
	srv, c, domain := ttlEnv(t)
	local := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer local.Close()
	tun, err := c.HTTP(strings.TrimPrefix(local.URL, "http://"), client.WithSubdomain("forever"))
	if err != nil {
		t.Fatal(err)
	}
	if !tun.ExpiresAt.IsZero() {
		t.Errorf("ExpiresAt = %v for a tunnel without TTL", tun.ExpiresAt)
	}
	time.Sleep(1800 * time.Millisecond)
	if got := edgeStatus(t, srv, "forever."+domain); got != 200 {
		t.Errorf("status %d", got)
	}
}

func TestTCPTunnelExpiresAndFreesPort(t *testing.T) {
	_, c, _ := ttlEnv(t)
	echo, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()

	tun, err := c.TCP(echo.Addr().String(), 0, client.WithTTL(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(tun.Port))
	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatalf("tunnel not reachable before expiry: %v", err)
	}
	conn.Close()

	deadline := time.Now().Add(6 * time.Second)
	for time.Now().Before(deadline) {
		if conn, err := net.DialTimeout("tcp", addr, 500*time.Millisecond); err != nil {
			return // listener closed
		} else {
			conn.Close()
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Error("TCP port still accepts connections after the TTL")
}

func TestInvalidTTLRejected(t *testing.T) {
	_, c, _ := ttlEnv(t)
	for _, d := range []time.Duration{-time.Second, 400 * 24 * time.Hour} {
		if _, err := c.HTTP("localhost:1", client.WithTTL(d)); err == nil || !strings.Contains(err.Error(), "invalid ttl") {
			t.Errorf("ttl %v: err = %v, want invalid ttl", d, err)
		}
	}
}
