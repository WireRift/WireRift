package client

import (
	"net"
	"strings"
	"testing"
	"time"
)

// A TLS-only server drops a plaintext client; the error must say to use tls://.
func TestPlaintextToTLSServerHint(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			time.Sleep(50 * time.Millisecond)
			c.Close()
		}
	}()

	cfg := DefaultConfig()
	cfg.ServerAddr = ln.Addr().String()
	cfg.Token = "x"
	cfg.Reconnect = false
	c := New(cfg, nil)
	defer c.Close()
	err = c.Connect()
	if err == nil || !strings.Contains(err.Error(), "tls://"+cfg.ServerAddr) {
		t.Fatalf("error = %v, want a tls:// hint", err)
	}
}
