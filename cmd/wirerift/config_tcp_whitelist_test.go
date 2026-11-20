package main

// Regression test: a "whitelist:" in the config file must reach the server for
// a TCP tunnel as well as for an HTTP one.
//
// The server enforces the whitelist on TCP tunnels too (it stores the allowed
// IPs and drops connections from other addresses), but the CLI used to open a
// config-file TCP tunnel without passing the option along. The whitelist was
// therefore silently discarded and the tunnel was open to every address, while
// the config file said it was restricted.

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/wirerift/wirerift/internal/proto"
)

// tunnelRequests collects the tunnel requests the mock server receives.
type tunnelRequests struct {
	ch chan proto.TunnelRequest
}

func (t *tunnelRequests) await(t2 *testing.T, typ proto.TunnelType) proto.TunnelRequest {
	t2.Helper()
	deadline := time.After(15 * time.Second)
	for {
		select {
		case req := <-t.ch:
			if req.Type == typ {
				return req
			}
		case <-deadline:
			t2.Fatalf("timed out waiting for a %s tunnel request", typ)
		}
	}
}

// startConfigFileServer runs the CLI's config-file path against a mock control
// plane that records the tunnel requests.
func startConfigFileServer(t *testing.T, configTunnels string) (*tunnelRequests, func()) {
	t.Helper()

	got := &tunnelRequests{ch: make(chan proto.TunnelRequest, 8)}
	addr, cleanup := startMockTunnelServerCapturing(t, func(req proto.TunnelRequest) {
		got.ch <- req
	})

	dir := t.TempDir()
	configFile := filepath.Join(dir, "wirerift.yaml")
	config := fmt.Sprintf("server: %s\ntoken: test\n\ntunnels:\n%s", addr, configTunnels)
	if err := os.WriteFile(configFile, []byte(config), 0o644); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- doStart(ctx, []string{"wirerift", "start", configFile})
	}()

	// doStart keeps running until the context is cancelled.
	stop := func() {
		cancel()
		<-done
		cleanup()
	}
	return got, stop
}

func TestConfigFileWhitelistReachesServerForBothTunnelTypes(t *testing.T) {
	defer lockGOMAXPROCS()()

	got, stop := startConfigFileServer(t, ""+
		"  - type: http\n    local_port: 8080\n    subdomain: test\n    whitelist: \"192.0.2.0/24\"\n"+
		"  - type: tcp\n    local_port: 9090\n    whitelist: \"10.0.0.0/8\"\n")
	defer stop()

	httpReq := got.await(t, proto.TunnelTypeHTTP)
	tcpReq := got.await(t, proto.TunnelTypeTCP)

	if len(httpReq.AllowedIPs) != 1 || httpReq.AllowedIPs[0] != "192.0.2.0/24" {
		t.Errorf("HTTP tunnel AllowedIPs = %v, want [192.0.2.0/24]", httpReq.AllowedIPs)
	}
	if len(tcpReq.AllowedIPs) != 1 || tcpReq.AllowedIPs[0] != "10.0.0.0/8" {
		t.Errorf("TCP tunnel AllowedIPs = %v, want [10.0.0.0/8] — the config file's "+
			"whitelist must be sent for TCP tunnels too", tcpReq.AllowedIPs)
	}
}

func TestConfigFileWhitelistWithSeveralAddresses(t *testing.T) {
	defer lockGOMAXPROCS()()

	got, stop := startConfigFileServer(t, ""+
		"  - type: tcp\n    local_port: 9090\n    whitelist: \"10.0.0.0/8, 203.0.113.7\"\n")
	defer stop()

	tcpReq := got.await(t, proto.TunnelTypeTCP)
	want := []string{"10.0.0.0/8", "203.0.113.7"}
	if len(tcpReq.AllowedIPs) != len(want) {
		t.Fatalf("TCP tunnel AllowedIPs = %v, want %v", tcpReq.AllowedIPs, want)
	}
	for i := range want {
		if tcpReq.AllowedIPs[i] != want[i] {
			t.Fatalf("TCP tunnel AllowedIPs = %v, want %v", tcpReq.AllowedIPs, want)
		}
	}
}

func TestConfigFileTCPWithoutWhitelistSendsNoRestriction(t *testing.T) {
	defer lockGOMAXPROCS()()

	got, stop := startConfigFileServer(t, ""+
		"  - type: tcp\n    local_port: 9090\n")
	defer stop()

	tcpReq := got.await(t, proto.TunnelTypeTCP)
	if len(tcpReq.AllowedIPs) != 0 {
		t.Errorf("TCP tunnel without a whitelist sent AllowedIPs = %v, want none", tcpReq.AllowedIPs)
	}
}

func TestParseWhitelist(t *testing.T) {
	cases := []struct {
		raw  string
		want []string
	}{
		{"10.0.0.0/8", []string{"10.0.0.0/8"}},
		{"10.0.0.0/8,192.168.1.0/24", []string{"10.0.0.0/8", "192.168.1.0/24"}},
		{" 203.0.113.7 , 10.0.0.0/8 ", []string{"203.0.113.7", "10.0.0.0/8"}},
	}
	for _, c := range cases {
		got := parseWhitelist(c.raw)
		if len(got) != len(c.want) {
			t.Errorf("parseWhitelist(%q) = %v, want %v", c.raw, got, c.want)
			continue
		}
		for i := range c.want {
			if got[i] != c.want[i] {
				t.Errorf("parseWhitelist(%q) = %v, want %v", c.raw, got, c.want)
				break
			}
		}
	}
}
