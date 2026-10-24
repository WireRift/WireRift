package server

import (
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
