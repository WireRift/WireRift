package integration

import (
	"net"
	"net/url"
	"strconv"
	"testing"
	"time"

	"github.com/wirerift/wirerift/internal/auth"
	"github.com/wirerift/wirerift/internal/client"
	"github.com/wirerift/wirerift/internal/server"
)

// TestTCPTunnelPortReportedToClient verifies that a client creating a TCP
// tunnel learns the server-assigned public port. The server does not put the
// port in TunnelResponse, only in PublicURL ("tcp://domain:port"), so the
// client must derive Tunnel.Port from it; the CLI prints this port for
// `wirerift tcp` and `wirerift start`.
func TestTCPTunnelPortReportedToClient(t *testing.T) {
	// Local service the tunnel points at (accepted connections prove the
	// parsed port is the live public listener).
	local, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("local listen: %v", err)
	}
	defer local.Close()
	go func() {
		for {
			conn, err := local.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()

	authMgr := auth.NewManager()
	srvCfg := server.DefaultConfig()
	srvCfg.TCPAddrRange = "33000-33050" // distinct range: packages run in parallel
	srvCfg.ControlAddr = "127.0.0.1:0"
	srvCfg.HTTPAddr = "127.0.0.1:0"
	srvCfg.AuthManager = authMgr

	srv := server.New(srvCfg, nil)
	if err := srv.Start(); err != nil {
		t.Fatalf("Server start: %v", err)
	}
	defer srv.Stop()

	clientCfg := client.DefaultConfig()
	clientCfg.ServerAddr = srv.ControlAddr()
	clientCfg.Token = authMgr.DevToken()
	clientCfg.Reconnect = false

	c := client.New(clientCfg, nil)
	if err := c.Connect(); err != nil {
		t.Fatalf("Client connect: %v", err)
	}
	defer c.Close()

	tunnel, err := c.TCP(local.Addr().String(), 0)
	if err != nil {
		t.Fatalf("Create TCP tunnel: %v", err)
	}

	// Control (must hold before and after the fix): the server-assigned port
	// is present in PublicURL and the listener at that port is live.
	u, err := url.Parse(tunnel.PublicURL)
	if err != nil {
		t.Fatalf("control: parse PublicURL %q: %v", tunnel.PublicURL, err)
	}
	assigned, err := strconv.Atoi(u.Port())
	if err != nil || assigned == 0 {
		t.Fatalf("control: PublicURL %q carries no usable port (harness broken)", tunnel.PublicURL)
	}
	conn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", u.Port()), 5*time.Second)
	if err != nil {
		t.Fatalf("control: assigned port %d not reachable: %v", assigned, err)
	}
	conn.Close()

	// Defect assertion: the client must report the assigned port, not echo
	// the requested one (0). Pre-fix, Tunnel.Port is req.RemotePort == 0.
	if tunnel.Port == 0 {
		t.Fatalf("FAIL: Tunnel.Port = 0 for created TCP tunnel; client must report the assigned public port %d (PublicURL %q)", assigned, tunnel.PublicURL)
	}
	if tunnel.Port != assigned {
		t.Fatalf("FAIL: Tunnel.Port = %d, want assigned public port %d (PublicURL %q)", tunnel.Port, assigned, tunnel.PublicURL)
	}
}
