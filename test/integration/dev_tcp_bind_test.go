package integration

import (
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/wirerift/wirerift/internal/auth"
	"github.com/wirerift/wirerift/internal/client"
	"github.com/wirerift/wirerift/internal/server"
)

// With TCPBindHost set (what -dev does) a TCP tunnel's public port must not be
// reachable through the machine's other network addresses.
func TestTCPTunnelHonoursBindHost(t *testing.T) {
	var external string
	addrs, _ := net.InterfaceAddrs()
	for _, a := range addrs {
		if ipn, ok := a.(*net.IPNet); ok && ipn.IP.To4() != nil && !ipn.IP.IsLoopback() {
			external = ipn.IP.String()
			break
		}
	}
	if external == "" {
		t.Skip("no non-loopback IPv4 address to probe")
	}

	authMgr := auth.NewManager()
	cfg := server.DefaultConfig()
	cfg.ControlAddr, cfg.HTTPAddr, cfg.AuthManager = "127.0.0.1:0", "127.0.0.1:0", authMgr
	cfg.TCPAddrRange = "34000-34050"
	cfg.TCPBindHost = "127.0.0.1"
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
	echo, _ := net.Listen("tcp", "127.0.0.1:0")
	defer echo.Close()
	tun, err := c.TCP(echo.Addr().String(), 0)
	if err != nil {
		t.Fatal(err)
	}

	port := strconv.Itoa(tun.Port)
	if conn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", port), 2*time.Second); err != nil {
		t.Fatalf("loopback unreachable: %v", err)
	} else {
		conn.Close()
	}
	if conn, err := net.DialTimeout("tcp", net.JoinHostPort(external, port), 2*time.Second); err == nil {
		conn.Close()
		t.Errorf("the tunnel port is reachable on %s although TCPBindHost is loopback", external)
	}
}
