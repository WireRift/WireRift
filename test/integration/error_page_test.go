package integration

import (
	"io"
	"net"
	"net/http"
	"strings"
	"testing"

	"github.com/wirerift/wirerift/internal/auth"
	"github.com/wirerift/wirerift/internal/client"
	"github.com/wirerift/wirerift/internal/server"
)

// A tunnel whose local app is down must answer with a helpful page for
// browsers and a short plain-text 502 for everything else, without exposing
// the local port to the public visitor.
func TestLocalAppDownErrorPage(t *testing.T) {
	// Reserve a port and close it so nothing listens there.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	deadAddr := ln.Addr().String()
	_, deadPort, _ := net.SplitHostPort(deadAddr)
	ln.Close()

	authMgr := auth.NewManager()
	cfg := server.DefaultConfig()
	cfg.ControlAddr, cfg.HTTPAddr, cfg.AuthManager = "127.0.0.1:0", "127.0.0.1:0", authMgr
	srv := server.New(cfg, nil)
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	defer srv.Stop()

	cc := client.DefaultConfig()
	cc.ServerAddr, cc.Token, cc.Reconnect = srv.ControlAddr(), authMgr.DevToken(), false
	c := client.New(cc, nil)
	if err := c.Connect(); err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := c.HTTP(deadAddr, client.WithSubdomain("down")); err != nil {
		t.Fatal(err)
	}

	get := func(accept string) (*http.Response, string) {
		req, _ := http.NewRequest("GET", "http://"+srv.HTTPAddr()+"/", nil)
		req.Host = "down." + cfg.Domain
		if accept != "" {
			req.Header.Set("Accept", accept)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp, string(b)
	}

	resp, body := get("text/html")
	if resp.StatusCode != 502 || !strings.HasPrefix(resp.Header.Get("Content-Type"), "text/html") ||
		!strings.Contains(body, "not responding") {
		t.Errorf("browser: %d %q\n%s", resp.StatusCode, resp.Header.Get("Content-Type"), body)
	}
	if strings.Contains(body, deadPort) || strings.Contains(body, "127.0.0.1") {
		t.Error("the local address leaked to the public visitor")
	}

	resp, body = get("")
	if resp.StatusCode != 502 || !strings.HasPrefix(resp.Header.Get("Content-Type"), "text/plain") ||
		!strings.Contains(body, "Local service unreachable") {
		t.Errorf("api client: %d %q %q", resp.StatusCode, resp.Header.Get("Content-Type"), body)
	}
	if resp.Header.Get("X-WireRift-Error") != "local-service-unreachable" {
		t.Errorf("missing X-WireRift-Error header: %v", resp.Header)
	}
}
