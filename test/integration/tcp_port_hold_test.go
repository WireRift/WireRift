package integration

import (
	"bufio"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/wirerift/wirerift/internal/client"
)

// echoServer answers each line with "echo:<line>" and returns its address.
func echoServer(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				sc := bufio.NewScanner(c)
				for sc.Scan() {
					fmt.Fprintf(c, "echo:%s\n", sc.Text())
				}
			}()
		}
	}()
	return ln.Addr().String()
}

// echoVia dials the tunnel's public port and returns the echoed answer.
func echoVia(port int) (string, error) {
	c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 2*time.Second)
	if err != nil {
		return "", err
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := fmt.Fprint(c, "ping\n"); err != nil {
		return "", err
	}
	line, err := bufio.NewReader(c).ReadString('\n')
	return strings.TrimSpace(line), err
}

func tcpPortOf(t *testing.T, tun *client.Tunnel) int {
	t.Helper()
	if tun.Port == 0 {
		t.Fatal("the client did not learn the assigned TCP port")
	}
	return tun.Port
}

func TestDroppedClientKeepsItsTCPPortAndNobodyElseCanTakeIt(t *testing.T) {
	e := newOfflineEnv(t, nil)
	echo := echoServer(t)
	proxy := newCutter(t, e.srv.ControlAddr())
	alice := e.connect(t, "alice", proxy.ln.Addr().String(), true)
	tun, err := alice.TCP(echo, 0)
	if err != nil {
		t.Fatal(err)
	}
	port := tcpPortOf(t, tun)
	if got, err := echoVia(port); err != nil || got != "echo:ping" {
		t.Fatalf("before the drop: %q %v", got, err)
	}

	proxy.cut(true)
	waitFor(t, func() bool { _, err := echoVia(port); return err != nil }, "the tunnel to go away while the client is offline")

	// Another account can neither ask for the port nor be handed it by chance.
	bob := e.connect(t, "bob", e.srv.ControlAddr(), false)
	if _, err := bob.TCP(echo, port); err == nil || !strings.Contains(err.Error(), "taken") {
		t.Fatalf("another account took a reserved port: %v", err)
	}
	for i := 0; i < 6; i++ {
		other, err := bob.TCP(echo, 0)
		if err != nil {
			t.Fatal(err)
		}
		if other.Port == port {
			t.Fatalf("a free-port request was given the reserved port %d", port)
		}
	}

	proxy.unblock()
	waitFor(t, func() bool { got, err := echoVia(port); return err == nil && got == "echo:ping" }, "the tunnel to come back on the same port")
	if tun.Port != port {
		t.Errorf("tunnel handle reports port %d after the reconnect, want %d", tun.Port, port)
	}
}

func TestReconnectTakesOverItsOwnStaleTCPPort(t *testing.T) {
	e := newOfflineEnv(t, nil)
	echo := echoServer(t)
	proxy := newCutter(t, e.srv.ControlAddr())
	alice := e.connect(t, "alice", proxy.ln.Addr().String(), true)
	tun, err := alice.TCP(echo, 0)
	if err != nil {
		t.Fatal(err)
	}
	port := tcpPortOf(t, tun)

	// The old session stays registered on the server while the client reconnects.
	proxy.strand()
	proxy.unblock()
	waitFor(t, func() bool { got, err := echoVia(port); return err == nil && got == "echo:ping" }, "the tunnel to come back on the same port")
	if tun.Port != port {
		t.Errorf("port changed from %d to %d", port, tun.Port)
	}
}

func TestExplicitTCPPortRequests(t *testing.T) {
	e := newOfflineEnv(t, nil)
	echo := echoServer(t)
	alice := e.connect(t, "alice", e.srv.ControlAddr(), false)
	bob := e.connect(t, "bob", e.srv.ControlAddr(), false)

	first, err := alice.TCP(echo, 0)
	if err != nil {
		t.Fatal(err)
	}
	port := tcpPortOf(t, first)

	// In use by a live tunnel: refused, also for its owner without Reconnect.
	for name, c := range map[string]*client.Client{"owner": alice, "other": bob} {
		if _, err := c.TCP(echo, port); err == nil || !strings.Contains(err.Error(), "taken") {
			t.Errorf("%s: asking for a port in use gave %v", name, err)
		}
	}
	// Outside the range.
	if _, err := bob.TCP(echo, 80); err == nil || !strings.Contains(err.Error(), "range") {
		t.Errorf("port outside the range: %v", err)
	}
	// A free port inside the range can be asked for.
	free := port + 7
	want, err := bob.TCP(echo, free)
	if err != nil {
		t.Fatalf("asking for the free port %d: %v", free, err)
	}
	if want.Port != free {
		t.Errorf("got port %d, want %d", want.Port, free)
	}
	if got, err := echoVia(free); err != nil || got != "echo:ping" {
		t.Errorf("echo via the requested port: %q %v", got, err)
	}

	// Closing on purpose frees the port at once (no reservation).
	if err := bob.CloseTunnel(want.ID); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool { _, err := echoVia(free); return err != nil }, "the closed tunnel's port to stop answering")
	again, err := alice.TCP(echo, free)
	if err != nil {
		t.Fatalf("a port freed on purpose should be available at once: %v", err)
	}
	if again.Port != free {
		t.Errorf("got %d, want %d", again.Port, free)
	}
}
