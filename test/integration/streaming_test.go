package integration

import (
	"bufio"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/wirerift/wirerift/internal/auth"
	"github.com/wirerift/wirerift/internal/client"
	"github.com/wirerift/wirerift/internal/server"
)

// startTunnel runs a server + client and exposes local under subdomain,
// returning the edge address and Host header to use.
func startTunnel(t *testing.T, local http.Handler, subdomain string) (edgeAddr, host string) {
	t.Helper()
	return startTunnelIdle(t, local, subdomain, 0)
}

// startTunnelIdle is startTunnel with a custom edge idle timeout (0 = default).
func startTunnelIdle(t *testing.T, local http.Handler, subdomain string, idle time.Duration) (edgeAddr, host string) {
	t.Helper()
	svc := httptest.NewServer(local)
	t.Cleanup(svc.Close)

	authMgr := auth.NewManager()
	cfg := server.DefaultConfig()
	cfg.ControlAddr = "127.0.0.1:0"
	cfg.HTTPAddr = "127.0.0.1:0"
	cfg.AuthManager = authMgr
	cfg.EdgeIdleTimeout = idle
	srv := server.New(cfg, nil)
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { srv.Stop() })

	cc := client.DefaultConfig()
	cc.ServerAddr = srv.ControlAddr()
	cc.Token = authMgr.DevToken()
	cc.Reconnect = false
	c := client.New(cc, nil)
	if err := c.Connect(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	if _, err := c.HTTP(strings.TrimPrefix(svc.URL, "http://"), client.WithSubdomain(subdomain)); err != nil {
		t.Fatal(err)
	}
	return srv.HTTPAddr(), subdomain + "." + cfg.Domain
}

// TestSSEIsStreamedNotBuffered proves events reach the visitor while the
// local app is still holding the response open.
func TestSSEIsStreamedNotBuffered(t *testing.T) {
	release := make(chan struct{})
	edge, host := startTunnel(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		fmt.Fprint(w, "data: one\n\n")
		w.(http.Flusher).Flush()
		<-release // second event only after the test saw the first
		fmt.Fprint(w, "data: two\n\n")
	}), "sse")

	req, _ := http.NewRequest("GET", "http://"+edge+"/events", nil)
	req.Host = host
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	lines := make(chan string, 8)
	go func() {
		sc := bufio.NewScanner(resp.Body)
		for sc.Scan() {
			lines <- sc.Text()
		}
		close(lines)
	}()

	select {
	case l := <-lines:
		if l != "data: one" {
			t.Fatalf("first line = %q", l)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("first event not delivered while response still open: response is being buffered")
	}
	close(release)
	deadline := time.After(5 * time.Second)
	for {
		select {
		case l, ok := <-lines:
			if !ok {
				t.Fatal("stream ended before second event")
			}
			if l == "data: two" {
				return
			}
		case <-deadline:
			t.Fatal("second event not delivered")
		}
	}
}

// TestLargeResponseNotCapped streams more than the old 64 MB buffering limit.
func TestLargeResponseNotCapped(t *testing.T) {
	const size = 80 << 20
	edge, host := startTunnel(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", fmt.Sprint(size))
		chunk := make([]byte, 64<<10)
		for sent := 0; sent < size; sent += len(chunk) {
			w.Write(chunk)
		}
	}), "big")

	req, _ := http.NewRequest("GET", "http://"+edge+"/big", nil)
	req.Host = host
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	n, err := io.Copy(io.Discard, resp.Body)
	if err != nil || n != size {
		t.Errorf("received %d bytes, err=%v; want %d", n, err, size)
	}
}
