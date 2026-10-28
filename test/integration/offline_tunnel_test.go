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
	"path/filepath"
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
	cfg.HeldFile = filepath.Join(t.TempDir(), "held.json")
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

type offlineEnv struct {
	srv     *server.Server
	cfg     server.Config
	secrets map[string]string
	local   string
}

func newOfflineEnv(t *testing.T, maxTunnels map[string]int) *offlineEnv {
	t.Helper()
	ls := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "ok") }))
	t.Cleanup(ls.Close)
	tf := &auth.TokenFile{}
	secrets := map[string]string{}
	for _, name := range []string{"alice", "bob"} {
		s, _, err := tf.CreateToken(auth.CreateOptions{Account: name, Name: "t", MaxTunnels: maxTunnels[name]})
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
	cfg.HeldFile = filepath.Join(t.TempDir(), "held.json")
	srv := server.New(cfg, nil)
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { srv.Stop() })
	return &offlineEnv{srv: srv, cfg: cfg, secrets: secrets, local: strings.TrimPrefix(ls.URL, "http://")}
}

func (e *offlineEnv) connect(t *testing.T, account, addr string, reconnect bool) *client.Client {
	t.Helper()
	cc := client.DefaultConfig()
	cc.ServerAddr = addr
	cc.Token = e.secrets[account]
	cc.Reconnect = reconnect
	cc.ReconnectInterval = 200 * time.Millisecond
	c := client.New(cc, nil)
	if err := c.Connect(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

// A client that exits on purpose says so, and its names are free at once
// instead of showing visitors "reconnecting" for the whole grace period.
func TestClientThatClosesOnPurposeReleasesItsSubdomain(t *testing.T) {
	e := newOfflineEnv(t, nil)
	alice := e.connect(t, "alice", e.srv.ControlAddr(), false)
	if _, err := alice.HTTP(e.local, client.WithSubdomain("goodbye")); err != nil {
		t.Fatal(err)
	}
	alice.Close()

	req, _ := http.NewRequest("GET", "http://"+e.srv.HTTPAddr()+"/", nil)
	req.Host = "goodbye." + e.cfg.Domain
	waitFor(t, func() bool {
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return false
		}
		resp.Body.Close()
		return resp.StatusCode == http.StatusBadGateway // not 503: nothing is held
	}, "the name to be released")

	bob := e.connect(t, "bob", e.srv.ControlAddr(), false)
	if _, err := bob.HTTP(e.local, client.WithSubdomain("goodbye")); err != nil {
		t.Fatalf("bob could not take a name its owner released: %v", err)
	}
}

// A restart of the server must not open a window in which someone else takes
// the name of a client that was connected when it stopped.
func TestRestartKeepsConnectedClientsNames(t *testing.T) {
	e := newOfflineEnv(t, nil)
	alice := e.connect(t, "alice", e.srv.ControlAddr(), false)
	if _, err := alice.HTTP(e.local, client.WithSubdomain("keepme")); err != nil {
		t.Fatal(err)
	}
	if err := e.srv.Stop(); err != nil {
		t.Fatal(err)
	}

	next := server.New(e.cfg, nil)
	if err := next.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { next.Stop() })

	bob := e.connect(t, "bob", next.ControlAddr(), false)
	if _, err := bob.HTTP(e.local, client.WithSubdomain("keepme")); err == nil {
		t.Fatal("bob took a name that alice held across the restart")
	}
	alice2 := e.connect(t, "alice", next.ControlAddr(), false)
	if _, err := alice2.HTTP(e.local, client.WithSubdomain("keepme")); err != nil {
		t.Fatalf("alice could not reclaim her name after the restart: %v", err)
	}
}
