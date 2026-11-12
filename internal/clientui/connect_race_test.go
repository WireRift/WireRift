package clientui

import (
	"fmt"
	"io"
	"net"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/wirerift/wirerift/internal/auth"
	"github.com/wirerift/wirerift/internal/client"
	"github.com/wirerift/wirerift/internal/server"
)

const loopbackAny = "127.0.0.1:0"

// A second Connect while the first is still in its handshake must be refused:
// otherwise both succeed and the first client is orphaned (F401).
func TestConnectWhileConnectingIsRefused(t *testing.T) {
	am := auth.NewManager()
	cfg := server.DefaultConfig()
	cfg.ControlAddr, cfg.HTTPAddr, cfg.AuthManager = loopbackAny, loopbackAny, am
	srv := server.New(cfg, nil)
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = srv.Stop() })

	release, entered := make(chan struct{}), make(chan struct{}, 1)
	l, err := net.Listen("tcp", loopbackAny)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				entered <- struct{}{}
				<-release
				u, err := net.Dial("tcp", srv.ControlAddr())
				if err != nil {
					c.Close()
					return
				}
				go func() { _, _ = io.Copy(u, c) }()
				_, _ = io.Copy(c, u)
			}()
		}
	}()

	m := NewManager(client.DefaultConfig(), nil, nil)
	t.Cleanup(m.Disconnect)
	first := make(chan error, 1)
	go func() { first <- m.Connect(l.Addr().String(), am.DevToken(), false) }()
	<-entered
	if err := m.Connect(srv.ControlAddr(), am.DevToken(), false); err != ErrBusy {
		t.Fatalf("second Connect during handshake = %v, want ErrBusy", err)
	}
	close(release)
	if err := <-first; err != nil {
		t.Fatal(err)
	}
	m.Disconnect()
	deadline := time.Now().Add(3 * time.Second)
	for srv.Stats()["active_sessions"] != 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if n := srv.Stats()["active_sessions"]; n != 0 {
		t.Fatalf("sessions left after Disconnect: %v", n)
	}
}

// Concurrent preset saves must not overwrite each other (F402).
func TestConcurrentSavePresetKeepsAll(t *testing.T) {
	m := NewManager(client.DefaultConfig(), NewSettings(filepath.Join(t.TempDir(), "ui.json")), nil)
	const n = 30
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if err := m.SavePreset(Preset{Name: fmt.Sprint("p", i), TunnelSpec: TunnelSpec{Type: "http", Local: "3000"}}); err != nil {
				t.Error(err)
			}
		}(i)
	}
	wg.Wait()
	if got := len(m.Presets()); got != n {
		t.Fatalf("presets = %d, want %d", got, n)
	}
}

func TestLocalAddressRejectsSignedPort(t *testing.T) {
	if got, err := LocalAddress("+80"); err == nil && got != "localhost:80" {
		t.Fatalf("LocalAddress(+80) = %q", got)
	}
	if got, _ := LocalAddress("host:080"); got != "host:80" {
		t.Fatalf("LocalAddress(host:080) = %q", got)
	}
}
