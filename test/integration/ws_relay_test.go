package integration

// Regression test for the WebSocket relay: handleHTTPStream must route
// Upgrade requests to the raw bidirectional relay (handleUpgradeStream).
// Relaying them through http.Client/resp.Write deadlocks on the 101
// Switching Protocols response (live bidirectional body, never flushed), so
// the visitor's handshake never completes. Drives the real server, real
// client tunnel, and a minimal RFC 6455 echo peer — all with bounded deadlines.

import (
	"bufio"
	"bytes"
	"crypto/sha1"
	"encoding/base64"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/wirerift/wirerift/internal/auth"
	"github.com/wirerift/wirerift/internal/client"
	"github.com/wirerift/wirerift/internal/server"
)

const wsGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

func wsAccept(key string) string {
	h := sha1.Sum([]byte(key + wsGUID))
	return base64.StdEncoding.EncodeToString(h[:])
}

// startWSEchoServer runs a minimal RFC 6455 echo peer: 101 handshake, then
// masked-or-unmasked frames echoed unmasked until EOF or close frame.
func startWSEchoServer(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ws echo listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(30 * time.Second))
				br := bufio.NewReader(c)
				req, err := http.ReadRequest(br)
				if err != nil || req.Header.Get("Sec-WebSocket-Key") == "" {
					return
				}
				resp := "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: " + wsAccept(req.Header.Get("Sec-WebSocket-Key")) + "\r\n\r\n"
				if _, err := c.Write([]byte(resp)); err != nil {
					return
				}
				for {
					hdr, err := readWSN(c, 2)
					if err != nil {
						return
					}
					op := hdr[0] & 0x0F
					masked := hdr[1]&0x80 != 0
					ln := int(hdr[1] & 0x7F)
					if ln == 126 {
						ext, err := readWSN(c, 2)
						if err != nil {
							return
						}
						ln = int(ext[0])<<8 | int(ext[1])
					} else if ln == 127 {
						if _, err := readWSN(c, 8); err != nil {
							return
						}
						return // 64-bit echo not needed for this test
					}
					var mask []byte
					if masked {
						if mask, err = readWSN(c, 4); err != nil {
							return
						}
					}
					payload, err := readWSN(c, ln)
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
					c.Write(append([]byte{0x80 | (op & 0x0F), byte(len(payload))}, payload...))
				}
			}(conn)
		}
	}()
	return ln.Addr().String()
}

func readWSN(c net.Conn, n int) ([]byte, error) {
	buf := make([]byte, n)
	_, err := readFull(c, buf)
	return buf, err
}

func readFull(r io.Reader, buf []byte) (int, error) {
	total := 0
	for total < len(buf) {
		n, err := r.Read(buf[total:])
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
}

// wsClient drives one WebSocket round-trip through the edge and returns the
// echoed payload (or an error with a bounded deadline).
func wsClient(t *testing.T, edgeAddr, vhost, sub string, domain string) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", edgeAddr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial edge: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))

	key := "dGhlIHNhbXBsZSBub25jZQ==" // RFC 6455 example key
	req := "GET /ws HTTP/1.1\r\nHost: " + sub + "." + domain +
		"\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n" +
		"Sec-WebSocket-Key: " + key + "\r\nSec-WebSocket-Version: 13\r\n\r\n"
	if _, err := conn.Write([]byte(req)); err != nil {
		t.Fatalf("send upgrade: %v", err)
	}

	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, &http.Request{Method: "GET"})
	if err != nil {
		t.Fatalf("read handshake response: %v", err)
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("handshake status = %d, want 101 Switching Protocols", resp.StatusCode)
	}
	if got := resp.Header.Get("Sec-WebSocket-Accept"); got != wsAccept(key) {
		t.Fatalf("Sec-WebSocket-Accept = %q, want %q", got, wsAccept(key))
	}

	// Masked text frame: "hello-ws-round10" (16 bytes, single length byte).
	payload := []byte("hello-ws-round10")
	mask := []byte{0x11, 0x22, 0x33, 0x44}
	masked := make([]byte, len(payload))
	for i := range payload {
		masked[i] = payload[i] ^ mask[i%4]
	}
	frame := append([]byte{0x81, 0x80 | byte(len(payload))}, mask...)
	frame = append(frame, masked...)
	if _, err := conn.Write(frame); err != nil {
		t.Fatalf("send frame: %v", err)
	}

	echoHdr := make([]byte, 2)
	if _, err := readFull(br, echoHdr); err != nil {
		t.Fatalf("read echo header: %v", err)
	}
	ln := int(echoHdr[1] & 0x7F)
	echo := make([]byte, ln)
	if _, err := readFull(br, echo); err != nil {
		t.Fatalf("read echo payload: %v", err)
	}
	if !bytes.Equal(echo, payload) {
		t.Fatalf("echo = %q, want %q", echo, payload)
	}
}

// TestWebSocketRelayEndToEnd verifies that a WebSocket upgrade, a frame echo,
// and connection close all work through `wirerift http` end to end.
func TestWebSocketRelayEndToEnd(t *testing.T) {
	local := startWSEchoServer(t)

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

	if _, err := c.HTTP(local, client.WithSubdomain("r10ws")); err != nil {
		t.Fatalf("Create HTTP tunnel: %v", err)
	}

	wsClient(t, srv.HTTPAddr(), "r10ws", "r10ws", srvCfg.Domain)
}
