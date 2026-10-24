package server

import (
	"fmt"
	"net"
	"testing"
)

func TestPendingConnsLimits(t *testing.T) {
	var p pendingConns
	a := &net.TCPAddr{IP: net.ParseIP("10.0.0.1"), Port: 1}
	b := &net.TCPAddr{IP: net.ParseIP("10.0.0.2"), Port: 1}

	var releases []func()
	for i := 0; i < maxPendingControlConnsPerIP; i++ {
		r, ok := p.acquire(a)
		if !ok {
			t.Fatalf("connection %d from one IP refused", i)
		}
		releases = append(releases, r)
	}
	if _, ok := p.acquire(a); ok {
		t.Fatal("per-IP limit not enforced")
	}
	if r, ok := p.acquire(b); !ok {
		t.Fatal("another IP must not be affected")
	} else {
		r()
	}

	releases[0]()
	releases[0]() // releasing twice must not free a second slot
	if _, ok := p.acquire(a); !ok {
		t.Fatal("slot not freed")
	}
	if _, ok := p.acquire(a); ok {
		t.Fatal("double release freed an extra slot")
	}
}

func TestPendingConnsTotalLimit(t *testing.T) {
	var p pendingConns
	for i := 0; i < maxPendingControlConns; i++ {
		addr := &net.TCPAddr{IP: net.IPv4(10, byte(i>>16), byte(i>>8), byte(i)), Port: 1}
		if _, ok := p.acquire(addr); !ok {
			t.Fatalf("connection %d refused below the total limit", i)
		}
	}
	if _, ok := p.acquire(&net.TCPAddr{IP: net.ParseIP("192.168.0.1"), Port: 1}); ok {
		t.Fatal("total limit not enforced")
	}
}

// A port of the range that another program already listens on is skipped; the
// tunnel only fails when none can be bound.
func TestListenTunnelPortSkipsBusyPorts(t *testing.T) {
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skip(err)
	}
	base := probe.Addr().(*net.TCPAddr).Port
	probe.Close()

	cfg := DefaultConfig()
	cfg.TCPAddrRange = fmt.Sprintf("%d-%d", base, base+2)
	cfg.TCPBindHost = "127.0.0.1"
	s := New(cfg, nil)

	for _, p := range []int{base, base + 1} {
		l, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", p))
		if err != nil {
			t.Skipf("port %d not free: %v", p, err)
		}
		defer l.Close()
	}

	l, port, err := s.listenTunnelPort()
	if err != nil {
		t.Fatalf("a free port was left: %v", err)
	}
	defer l.Close()
	if port != base+2 {
		t.Errorf("got port %d, want the only free one %d", port, base+2)
	}

	l2, _, err := s.listenTunnelPort()
	if err == nil {
		l2.Close()
		t.Fatal("expected an error when every port is taken")
	}
}
