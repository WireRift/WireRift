package client_test

import (
	"bufio"
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

// obsEnv is a real server and a connected client that reports every exchange.
type obsEnv struct {
	srv    *server.Server
	c      *client.Client
	domain string
	mu     sync.Mutex
	seen   []client.Exchange
}

func newObsEnv(t *testing.T, capture int) *obsEnv {
	t.Helper()
	mgr := auth.NewManager()
	cfg := server.DefaultConfig()
	cfg.ControlAddr, cfg.HTTPAddr, cfg.AuthManager = "127.0.0.1:0", "127.0.0.1:0", mgr
	srv := server.New(cfg, nil)
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { srv.Stop() })
	e := &obsEnv{srv: srv, domain: cfg.Domain}
	ccfg := client.DefaultConfig()
	ccfg.ServerAddr, ccfg.Token, ccfg.Reconnect = srv.ControlAddr(), mgr.DevToken(), false
	ccfg.OnExchange, ccfg.CaptureBody = func(x client.Exchange) { e.mu.Lock(); e.seen = append(e.seen, x); e.mu.Unlock() }, capture
	e.c = client.New(ccfg, nil)
	if err := e.c.Connect(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { e.c.Close() })
	return e
}

func (e *obsEnv) wait(t *testing.T, n int) []client.Exchange {
	t.Helper()
	for i := 0; i < 200; i++ {
		e.mu.Lock()
		got := append([]client.Exchange(nil), e.seen...)
		e.mu.Unlock()
		if len(got) >= n {
			return got
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("expected %d exchanges", n)
	return nil
}

func (e *obsEnv) visit(t *testing.T, sub, method, path, body string, hdr map[string]string) (status int, answer string) {
	t.Helper()
	req, _ := http.NewRequest(method, "http://"+e.srv.HTTPAddr()+path, strings.NewReader(body))
	req.Host = sub + "." + e.domain
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func TestExchangeReportsHTTPRequestAndResponse(t *testing.T) {
	local := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		w.Header().Set("X-Local", "yes")
		w.WriteHeader(201)
		fmt.Fprintf(w, "got %d bytes", len(b))
	}))
	defer local.Close()
	e := newObsEnv(t, 1024)
	tun, err := e.c.HTTP(strings.TrimPrefix(local.URL, "http://"), client.WithSubdomain("obs"))
	if err != nil {
		t.Fatal(err)
	}
	status, body := e.visit(t, "obs", "POST", "/items?x=1", "hello world", map[string]string{"Content-Type": "text/plain"})
	if status != 201 || body != "got 11 bytes" {
		t.Fatalf("relay broke: %d %q", status, body)
	}
	x := e.wait(t, 1)[0]
	if x.Kind != "http" || x.Method != "POST" || x.Path != "/items?x=1" || x.Status != 201 || x.TunnelID != tun.ID {
		t.Errorf("exchange: %+v", x)
	}
	if string(x.ReqBody) != "hello world" || string(x.RespBody) != "got 11 bytes" || x.BytesIn != 11 || x.BytesOut != 12 {
		t.Errorf("bodies: in=%q out=%q (%d/%d)", x.ReqBody, x.RespBody, x.BytesIn, x.BytesOut)
	}
	if x.RespHeader.Get("X-Local") != "yes" || x.ReqHeader.Get("Content-Type") != "text/plain" || x.Duration <= 0 || x.ID == 0 {
		t.Errorf("headers/time: %+v", x)
	}
	if x.Remote == "" {
		t.Error("the visitor address the server forwards is missing")
	}
	if x.LocalAddr != tun.LocalAddr || x.TunnelURL != tun.PublicURL {
		t.Errorf("tunnel fields: %q %q", x.LocalAddr, x.TunnelURL)
	}
}

func TestExchangeKeepsOnlyTheCaptureLimitButCountsEverything(t *testing.T) {
	local := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		fmt.Fprint(w, strings.Repeat("z", 500))
	}))
	defer local.Close()
	e := newObsEnv(t, 16)
	if _, err := e.c.HTTP(strings.TrimPrefix(local.URL, "http://"), client.WithSubdomain("cap")); err != nil {
		t.Fatal(err)
	}
	e.visit(t, "cap", "PUT", "/", strings.Repeat("a", 300), nil)
	x := e.wait(t, 1)[0]
	if len(x.ReqBody) != 16 || !x.ReqTruncated || x.BytesIn != 300 {
		t.Errorf("request: kept %d truncated=%v counted %d", len(x.ReqBody), x.ReqTruncated, x.BytesIn)
	}
	if len(x.RespBody) != 16 || !x.RespTruncated || x.BytesOut != 500 {
		t.Errorf("response: kept %d truncated=%v counted %d", len(x.RespBody), x.RespTruncated, x.BytesOut)
	}
}

func TestExchangeReportsAnUnreachableLocalService(t *testing.T) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	dead := ln.Addr().String()
	ln.Close()
	e := newObsEnv(t, 0)
	if _, err := e.c.HTTP(dead, client.WithSubdomain("dead")); err != nil {
		t.Fatal(err)
	}
	status, _ := e.visit(t, "dead", "GET", "/", "", nil)
	if status != 502 {
		t.Fatalf("visitor got %d", status)
	}
	x := e.wait(t, 1)[0]
	if x.Status != 502 || x.Error == "" || len(x.RespBody) != 0 {
		t.Errorf("unreachable exchange: %+v", x)
	}
}

func TestExchangeCoversWebSocketAndTCP(t *testing.T) {
	ws, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ws.Close()
	go func() {
		for {
			c, err := ws.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				r := bufio.NewReader(c)
				for {
					line, err := r.ReadString('\n')
					if err != nil || line == "\r\n" {
						break
					}
				}
				fmt.Fprint(c, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\nhi")
			}()
		}
	}()
	e := newObsEnv(t, 0)
	if _, err := e.c.HTTP(ws.Addr().String(), client.WithSubdomain("sock")); err != nil {
		t.Fatal(err)
	}
	conn, err := net.Dial("tcp", e.srv.HTTPAddr())
	if err != nil {
		t.Fatal(err)
	}
	fmt.Fprintf(conn, "GET /chat HTTP/1.1\r\nHost: sock.%s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: x\r\n\r\n", e.domain)
	io.ReadAll(conn)
	conn.Close()
	x := e.wait(t, 1)[0]
	if x.Kind != "websocket" || x.Path != "/chat" || x.BytesOut == 0 {
		t.Errorf("websocket exchange: %+v", x)
	}

	echo, _ := net.Listen("tcp", "127.0.0.1:0")
	defer echo.Close()
	go func() {
		c, err := echo.Accept()
		if err == nil {
			io.Copy(c, c)
			c.Close()
		}
	}()
	tt, err := e.c.TCP(echo.Addr().String(), 0)
	if err != nil {
		t.Fatal(err)
	}
	pc, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", tt.Port))
	if err != nil {
		t.Fatal(err)
	}
	fmt.Fprint(pc, "ping")
	buf := make([]byte, 4)
	io.ReadFull(pc, buf)
	pc.Close()
	var tcp client.Exchange
	for _, x := range e.wait(t, 2) {
		if x.Kind == "tcp" {
			tcp = x
		}
	}
	if tcp.BytesIn != 4 || tcp.BytesOut != 4 || tcp.TunnelID != tt.ID {
		t.Errorf("tcp exchange: %+v", tcp)
	}
}

func TestExchangeReportsFailedUpgradeAndTCPDial(t *testing.T) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	dead := ln.Addr().String()
	ln.Close()
	e := newObsEnv(t, 0)
	if _, err := e.c.HTTP(dead, client.WithSubdomain("nows")); err != nil {
		t.Fatal(err)
	}
	conn, _ := net.Dial("tcp", e.srv.HTTPAddr())
	fmt.Fprintf(conn, "GET / HTTP/1.1\r\nHost: nows.%s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n", e.domain)
	io.ReadAll(conn)
	conn.Close()
	tt, err := e.c.TCP(dead, 0)
	if err != nil {
		t.Fatal(err)
	}
	pc, _ := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", tt.Port))
	io.ReadAll(pc)
	pc.Close()
	kinds := map[string]string{}
	for _, x := range e.wait(t, 2) {
		kinds[x.Kind] = x.Error
	}
	if kinds["websocket"] == "" || kinds["tcp"] == "" {
		t.Errorf("both failures should carry the dial error: %v", kinds)
	}
}

func TestTunnelsSnapshot(t *testing.T) {
	e := newObsEnv(t, 0)
	local := httptest.NewServer(http.NotFoundHandler())
	defer local.Close()
	la := strings.TrimPrefix(local.URL, "http://")
	a, _ := e.c.HTTP(la, client.WithSubdomain("bbb"), client.WithTTL(time.Hour))
	b, _ := e.c.HTTP(la, client.WithSubdomain("aaa"))
	tc, _ := e.c.TCP(la, 0)
	got := e.c.Tunnels()
	if len(got) != 3 {
		t.Fatalf("want 3 tunnels, got %+v", got)
	}
	if got[0].Type != "http" || !strings.Contains(got[0].PublicURL, "aaa.") || !strings.Contains(got[1].PublicURL, "bbb.") || got[2].Type != "tcp" || got[2].Port == 0 {
		t.Errorf("order or fields: %+v", got)
	}
	if got[1].ExpiresAt.IsZero() || !got[0].ExpiresAt.IsZero() {
		t.Error("only the tunnel with a TTL has an expiry")
	}
	_ = a
	_ = tc
	if err := b.Close(); err != nil {
		t.Fatal(err)
	}
	if n := len(e.c.Tunnels()); n != 2 {
		t.Errorf("a closed tunnel must leave the snapshot, have %d", n)
	}
}
