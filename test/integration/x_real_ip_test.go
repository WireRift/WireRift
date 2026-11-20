package integration

// Regression test for the X-Real-IP header on tunneled requests.
//
// The edge is the trust boundary for the client address: it re-emits
// X-Forwarded-For itself and drops the visitor's copy, so a direct visitor
// cannot choose the address the tunneled application sees. X-Real-IP is the
// other widely used convention for the same value (nginx $http_x_real_ip,
// Express req.ip behind a proxy) and SPEC §8.2 lists it among the headers the
// server adds, but it was neither emitted nor stripped: a visitor-supplied
// X-Real-Ip reached the local application verbatim, so a visitor could make
// the local app believe it came from any address it liked.
//
// This test drives the whole path — visitor -> edge -> mux -> client relay ->
// local application — and checks the headers the local application actually
// receives.

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/wirerift/wirerift/internal/auth"
	"github.com/wirerift/wirerift/internal/client"
	"github.com/wirerift/wirerift/internal/server"
)

// TestTunneledRequestCarriesTrustedRealIP verifies that the tunneled request
// carries the real client IP in X-Real-IP and that a visitor cannot choose it.
func TestTunneledRequestCarriesTrustedRealIP(t *testing.T) {
	const subdomain = "r2realip"

	var mu sync.Mutex
	var got http.Header
	local := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		got = r.Header.Clone()
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "ok")
	}))
	defer local.Close()

	authMgr := auth.NewManager()
	srvCfg := server.DefaultConfig()
	srvCfg.ControlAddr = "127.0.0.1:0"
	srvCfg.HTTPAddr = "127.0.0.1:0"
	srvCfg.AuthManager = authMgr
	srv := server.New(srvCfg, nil)
	if err := srv.Start(); err != nil {
		t.Fatalf("Server start: %v", err)
	}
	defer srv.Stop()

	cc := client.DefaultConfig()
	cc.ServerAddr = srv.ControlAddr()
	cc.Token = authMgr.DevToken()
	cc.Reconnect = false
	c := client.New(cc, nil)
	if err := c.Connect(); err != nil {
		t.Fatalf("Client connect: %v", err)
	}
	defer c.Close()

	localAddr := strings.TrimPrefix(local.URL, "http://")
	if _, err := c.HTTP(localAddr, client.WithSubdomain(subdomain)); err != nil {
		t.Fatalf("Create HTTP tunnel: %v", err)
	}

	req, err := http.NewRequest("GET", fmt.Sprintf("http://%s/", srv.HTTPAddr()), nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Host = subdomain + "." + srvCfg.Domain
	// The visitor tries to choose the client address the local app reads.
	req.Header.Set("X-Real-Ip", "198.51.100.99")
	// Control: an ordinary visitor header must still be forwarded verbatim.
	req.Header.Set("X-Custom-Probe", "keep-me")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Edge HTTP request: %v", err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Edge status = %d, want 200", resp.StatusCode)
	}

	mu.Lock()
	hdr := got
	mu.Unlock()
	if hdr == nil {
		t.Fatal("local application never received the request")
	}

	// Control: the unaffected forwarding header keeps its trusted value.
	if v := hdr.Get("X-Forwarded-For"); v != "127.0.0.1" {
		t.Errorf("X-Forwarded-For = %q, want 127.0.0.1", v)
	}
	if v := hdr.Get("X-Custom-Probe"); v != "keep-me" {
		t.Errorf("X-Custom-Probe = %q, want keep-me", v)
	}

	vals := hdr.Values("X-Real-Ip")
	if len(vals) != 1 {
		t.Fatalf("local app saw X-Real-Ip %d times (%v), want exactly 1", len(vals), vals)
	}
	if vals[0] != "127.0.0.1" {
		t.Errorf("local app saw X-Real-Ip = %q, want the real client IP 127.0.0.1", vals[0])
	}
	if strings.Contains(strings.Join(vals, ","), "198.51.100.99") {
		t.Error("visitor-supplied X-Real-Ip 198.51.100.99 reached the tunneled application")
	}
}
