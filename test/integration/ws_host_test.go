package integration

// Regression test for Host header preservation across the tunnel. RFC 9112
// Section 3.2 requires every HTTP/1.1 request on the wire to carry a Host
// header. The edge's SerializeRequest re-emits the visitor's host only as
// X-Forwarded-Host, so the request the client relay receives has no Host at
// all; handleUpgradeStream then writes the upgrade verbatim with an empty
// Host. Real HTTP/1.1 servers — including Go's own net/http server — reject
// such a request with 400 "missing required Host header", so every tunneled
// WebSocket handshake against a Go-based local service fails. The lenient
// http.ReadRequest echo peer in ws_relay_test.go cannot see this defect, so
// this test uses a real net/http server as the local endpoint.

import (
	"net"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/wirerift/wirerift/internal/auth"
	"github.com/wirerift/wirerift/internal/client"
	"github.com/wirerift/wirerift/internal/server"
)

// startWSStrictEchoServer runs a local WebSocket endpoint on a real
// net/http server, which enforces the HTTP/1.1 Host requirement before the
// handler runs. It performs the RFC 6455 handshake via Hijack, echoes
// client frames unmasked until the connection closes, and records the Host
// it observed for the contract assertion.
func startWSStrictEchoServer(t *testing.T, wantHost string, observedHost *atomic.Value) string {
	t.Helper()

	mux := http.NewServeMux()
	mux.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) {
		observedHost.Store(r.Host)
		if r.Host != wantHost {
			http.Error(w, "wrong host", http.StatusBadRequest)
			return
		}
		if !server.IsWebSocketRequest(r) {
			http.Error(w, "not a websocket upgrade", http.StatusBadRequest)
			return
		}
		hijacker, ok := w.(http.Hijacker)
		if !ok {
			http.Error(w, "hijack unsupported", http.StatusInternalServerError)
			return
		}
		conn, rw, err := hijacker.Hijack()
		if err != nil {
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(30 * time.Second))

		resp := "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: " + wsAccept(r.Header.Get("Sec-WebSocket-Key")) + "\r\n\r\n"
		if _, err := conn.Write([]byte(resp)); err != nil {
			return
		}

		// If the request reader buffered any frame bytes, they belong to
		// the stream before anything the visitor sends next.
		if n := rw.Reader.Buffered(); n > 0 {
			buffered := make([]byte, n)
			rw.Read(buffered)
			conn.Write(buffered)
		}

		for {
			hdr, err := readWSN(conn, 2)
			if err != nil {
				return
			}
			op := hdr[0] & 0x0F
			masked := hdr[1]&0x80 != 0
			ln := int(hdr[1] & 0x7F)
			if ln == 126 {
				ext, err := readWSN(conn, 2)
				if err != nil {
					return
				}
				ln = int(ext[0])<<8 | int(ext[1])
			} else if ln == 127 {
				return // 64-bit echo not needed for this test
			}
			var mask []byte
			if masked {
				if mask, err = readWSN(conn, 4); err != nil {
					return
				}
			}
			payload, err := readWSN(conn, ln)
			if err != nil {
				return
			}
			if masked {
				for i := range payload {
					payload[i] ^= mask[i%4]
				}
			}
			if op == 0x8 { // close
				return
			}
			conn.Write(append([]byte{0x80 | (op & 0x0F), byte(len(payload))}, payload...))
		}
	})

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("strict ws echo listen: %v", err)
	}
	srv := &http.Server{Handler: mux}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	return ln.Addr().String()
}

// TestWebSocketRelayToStrictLocalServer verifies that a tunneled WebSocket
// upgrade carries the visitor's public Host header to the local service and
// completes a full handshake + frame echo against a server that enforces
// RFC 9112's Host requirement.
func TestWebSocketRelayToStrictLocalServer(t *testing.T) {
	const subdomain = "r10host"
	var observedHost atomic.Value

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

	local := startWSStrictEchoServer(t, subdomain+"."+srvCfg.Domain, &observedHost)

	cc := client.DefaultConfig()
	cc.ServerAddr = srv.ControlAddr()
	cc.Token = authMgr.DevToken()
	cc.Reconnect = false
	c := client.New(cc, nil)
	if err := c.Connect(); err != nil {
		t.Fatalf("Client connect: %v", err)
	}
	defer c.Close()

	if _, err := c.HTTP(local, client.WithSubdomain(subdomain)); err != nil {
		t.Fatalf("Create HTTP tunnel: %v", err)
	}

	wsClient(t, srv.HTTPAddr(), subdomain, subdomain, srvCfg.Domain)

	got, _ := observedHost.Load().(string)
	if got != subdomain+"."+srvCfg.Domain {
		t.Fatalf("local service Host = %q, want %q (public host must reach the local service)", got, subdomain+"."+srvCfg.Domain)
	}
	if got == "" {
		t.Fatalf("local service never ran: request was rejected before the handler (check for a 400 missing-Host rejection)")
	}
}
