package integration

// A client that loses its connection keeps its URL: the server holds the
// subdomain for its account, visitors see 503 meanwhile, other accounts cannot
// take it, and the reconnecting client gets the same name back.

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/wirerift/wirerift/internal/auth"
	"github.com/wirerift/wirerift/internal/client"
	"github.com/wirerift/wirerift/internal/server"
)

// cutter forwards TCP to target and can sever every connection and refuse new
// ones, which is how a network drop looks to both ends.
type cutter struct {
	ln      net.Listener
	target  string
	mu      sync.Mutex
	blocked bool
	conns   []net.Conn
}

func newCutter(t *testing.T, target string) *cutter {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	c := &cutter{ln: ln, target: target}
	go func() {
		for {
			in, err := ln.Accept()
			if err != nil {
				return
			}
			c.mu.Lock()
			if c.blocked {
				c.mu.Unlock()
				in.Close()
				continue
			}
			out, err := net.Dial("tcp", target)
			if err != nil {
				c.mu.Unlock()
				in.Close()
				continue
			}
			c.conns = append(c.conns, in, out)
			c.mu.Unlock()
			go func() { io.Copy(out, in); out.Close() }()
			go func() { io.Copy(in, out); in.Close() }()
		}
	}()
	t.Cleanup(func() { ln.Close(); c.cut(false) })
	return c
}

func (c *cutter) cut(block bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.blocked = block
	for _, cn := range c.conns {
		cn.Close()
	}
	c.conns = nil
}

func (c *cutter) unblock() { c.mu.Lock(); c.blocked = false; c.mu.Unlock() }

func TestDroppedClientKeepsItsURLAndNobodyElseCanTakeIt(t *testing.T) {
	local := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "ok") }))
	defer local.Close()
	localAddr := strings.TrimPrefix(local.URL, "http://")

	tf := &auth.TokenFile{}
	secrets := map[string]string{}
	for _, name := range []string{"alice", "bob"} {
		s, _, err := tf.CreateToken(auth.CreateOptions{Account: name, Name: "t"})
		if err != nil {
			t.Fatal(err)
		}
		secrets[name] = s
	}
	authMgr := auth.NewManager()
	authMgr.ApplyTokenFile(tf)

	cfg := server.DefaultConfig()
	cfg.ControlAddr = "127.0.0.1:0"
	cfg.HTTPAddr = "127.0.0.1:0"
	cfg.AuthManager = authMgr
	srv := server.New(cfg, nil)
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	defer srv.Stop()

	proxy := newCutter(t, srv.ControlAddr())
	cc := client.DefaultConfig()
	cc.ServerAddr = proxy.ln.Addr().String()
	cc.Token = secrets["alice"]
	cc.ReconnectInterval = 200 * time.Millisecond
	alice := client.New(cc, nil)
	if err := alice.Connect(); err != nil {
		t.Fatal(err)
	}
	defer alice.Close()
	tun, err := alice.HTTP(localAddr) // random subdomain
	if err != nil {
		t.Fatal(err)
	}
	sub := tun.Subdomain
	if sub == "" {
		t.Fatal("client did not learn the assigned subdomain")
	}

	get := func() int {
		req, _ := http.NewRequest("GET", "http://"+srv.HTTPAddr()+"/", nil)
		req.Host = sub + "." + cfg.Domain
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	if got := get(); got != 200 {
		t.Fatalf("before the drop: %d", got)
	}

	proxy.cut(true)
	waitFor(t, func() bool { return get() == http.StatusServiceUnavailable }, "503 while the client is offline")

	// Another account cannot take the name.
	bc := client.DefaultConfig()
	bc.ServerAddr = srv.ControlAddr()
	bc.Token = secrets["bob"]
	bc.Reconnect = false
	bob := client.New(bc, nil)
	if err := bob.Connect(); err != nil {
		t.Fatal(err)
	}
	defer bob.Close()
	if _, err := bob.HTTP(localAddr, client.WithSubdomain(sub)); err == nil {
		t.Fatal("another account took a subdomain that is on hold")
	}

	proxy.unblock()
	waitFor(t, func() bool { return get() == 200 }, "the tunnel to come back")
}
