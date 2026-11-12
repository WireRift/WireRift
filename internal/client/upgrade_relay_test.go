package client

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/wirerift/wirerift/internal/mux"
	"github.com/wirerift/wirerift/internal/proto"
)

// relayUpgrade sends raw through a client relay stream to a local TCP service
// and returns what the service received once it has seen want (or timed out).
func relayUpgrade(t *testing.T, raw, want string) string {
	t.Helper()
	local, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer local.Close()
	got := make(chan string, 1)
	go func() {
		c, err := local.Accept()
		if err != nil {
			got <- ""
			return
		}
		defer c.Close()
		_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
		var sb strings.Builder
		buf := make([]byte, 4096)
		for !strings.Contains(sb.String(), want) {
			n, err := c.Read(buf)
			sb.Write(buf[:n])
			if err != nil {
				break
			}
		}
		got <- sb.String()
	}()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		c, _ := ln.Accept()
		accepted <- c
	}()
	cc, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	sc := <-accepted
	c := New(DefaultConfig(), nil)
	defer c.Close() // runs after the muxes close, which ends the relay
	clientMux, serverMux := mux.New(cc, mux.DefaultConfig()), mux.New(sc, mux.DefaultConfig())
	go clientMux.Run()
	go serverMux.Run()
	defer clientMux.Close()
	defer serverMux.Close()

	c.tunnels.Store("tun", &Tunnel{ID: "tun", LocalAddr: local.Addr().String(), Type: proto.TunnelTypeHTTP, client: c})
	go c.handleStreams(clientMux)

	st, err := serverMux.OpenStream()
	if err != nil {
		t.Fatal(err)
	}
	open, _ := proto.EncodeJSONPayload(proto.FrameStreamOpen, st.ID(), &proto.StreamOpen{TunnelID: "tun", RemoteAddr: "1.2.3.4:5", Protocol: "http"})
	if err := serverMux.GetFrameWriter().Write(open); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Write([]byte(raw)); err != nil {
		t.Fatal(err)
	}
	return <-got
}

// Bytes the visitor sends right behind the upgrade request are read into the
// request parser's buffer; the relay must still deliver them.
func TestUpgradeRelayForwardsBytesBufferedBehindRequest(t *testing.T) {
	const frame = "FIRST-WS-FRAME"
	got := relayUpgrade(t, "GET /ws HTTP/1.1\r\nHost: x\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n"+frame, frame)
	if !strings.HasSuffix(got, "\r\n\r\n"+frame) {
		t.Fatalf("local service got %q, want the request followed by %q", got, frame)
	}
}

// A visitor request without a User-Agent must not gain Go's default one.
func TestUpgradeRelayDoesNotInventUserAgent(t *testing.T) {
	got := relayUpgrade(t, "GET /ws HTTP/1.1\r\nHost: x\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n", "\r\n\r\n")
	req, err := http.ReadRequest(bufio.NewReader(strings.NewReader(got)))
	if err != nil {
		t.Fatalf("local service got %q: %v", got, err)
	}
	if ua := req.Header.Values("User-Agent"); len(ua) != 0 {
		t.Fatalf("User-Agent invented: %q", ua)
	}
}

func TestHTTPRelayDoesNotInventUserAgent(t *testing.T) {
	seen := make(chan []string, 1)
	srv := &http.Server{ReadHeaderTimeout: 5 * time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen <- r.Header.Values("User-Agent")
		_, _ = io.WriteString(w, "ok")
	})}
	local, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.Serve(local) }()
	defer srv.Close()

	a, b := net.Pipe()
	c := New(DefaultConfig(), nil)
	defer c.Close()
	clientMux, serverMux := mux.New(a, mux.DefaultConfig()), mux.New(b, mux.DefaultConfig())
	go clientMux.Run()
	go serverMux.Run()
	defer clientMux.Close()
	defer serverMux.Close()
	c.tunnels.Store("tun", &Tunnel{ID: "tun", LocalAddr: local.Addr().String(), Type: proto.TunnelTypeHTTP, client: c})
	go c.handleStreams(clientMux)

	st, _ := serverMux.OpenStream()
	open, _ := proto.EncodeJSONPayload(proto.FrameStreamOpen, st.ID(), &proto.StreamOpen{TunnelID: "tun", RemoteAddr: "1.2.3.4:5", Protocol: "http"})
	_ = serverMux.GetFrameWriter().Write(open)
	_, _ = st.Write([]byte("GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"))
	select {
	case ua := <-seen:
		if len(ua) != 0 {
			t.Fatalf("User-Agent invented: %q", ua)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("local service saw no request")
	}
}
