package integration

import (
	"io"
	"net"
	"net/url"
	"testing"
	"time"

	"github.com/wirerift/wirerift/internal/auth"
	"github.com/wirerift/wirerift/internal/client"
	"github.com/wirerift/wirerift/internal/server"
)

// -tcp-idle-timeout cuts a TCP tunnel connection that moved nothing, and only
// that one: a connection that keeps trading data stays up.
func TestTCPIdleTimeoutClosesOnlyTheQuietConnection(t *testing.T) {
	local, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer local.Close()
	go func() { // echo
		for {
			c, err := local.Accept()
			if err != nil {
				return
			}
			go func() { io.Copy(c, c); c.Close() }()
		}
	}()

	authMgr := auth.NewManager()
	cfg := server.DefaultConfig()
	cfg.TCPAddrRange = "33100-33150" // distinct range: packages run in parallel
	cfg.ControlAddr = "127.0.0.1:0"
	cfg.HTTPAddr = "127.0.0.1:0"
	cfg.AuthManager = authMgr
	cfg.TCPIdleTimeout = 400 * time.Millisecond
	srv := server.New(cfg, nil)
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	defer srv.Stop()

	cc := client.DefaultConfig()
	cc.ServerAddr = srv.ControlAddr()
	cc.Token = authMgr.DevToken()
	cc.Reconnect = false
	c := client.New(cc, nil)
	if err := c.Connect(); err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	tun, err := c.TCP(local.Addr().String(), 0)
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(tun.PublicURL)
	addr := net.JoinHostPort("127.0.0.1", u.Port())

	quiet, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer quiet.Close()
	busy, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer busy.Close()

	// busy keeps exchanging data for well over the timeout.
	buf := make([]byte, 1)
	for i := 0; i < 12; i++ {
		if _, err := busy.Write([]byte("x")); err != nil {
			t.Fatalf("busy connection write %d: %v", i, err)
		}
		busy.SetReadDeadline(time.Now().Add(2 * time.Second))
		if _, err := io.ReadFull(busy, buf); err != nil {
			t.Fatalf("busy connection was cut at round %d: %v", i, err)
		}
		time.Sleep(100 * time.Millisecond)
	}

	quiet.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := quiet.Read(buf); err != io.EOF && !isReset(err) {
		t.Fatalf("quiet connection should have been closed by the server, got %v", err)
	}
}

func isReset(err error) bool {
	ne, ok := err.(net.Error)
	return err != nil && !(ok && ne.Timeout())
}
