package server

import (
	"errors"
	"io"
	"net"
	"sync"
	"time"

	"github.com/wirerift/wirerift/internal/proto"
)

// TCPProxy handles TCP connection proxying through tunnels.
type TCPProxy struct {
	server     *Server
	bufferSize int
	timeout    time.Duration
}

// NewTCPProxy creates a new TCP proxy.
func NewTCPProxy(server *Server, bufferSize int, timeout time.Duration) *TCPProxy {
	if bufferSize <= 0 {
		bufferSize = 32 * 1024
	}
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	return &TCPProxy{
		server:     server,
		bufferSize: bufferSize,
		timeout:    timeout,
	}
}

// ProxyConnection proxies a TCP connection through a tunnel.
func (p *TCPProxy) ProxyConnection(conn net.Conn, tunnel *Tunnel, session *Session) error {
	defer conn.Close()

	// This is a placeholder - in the full implementation:
	// 1. Create a new stream through the mux
	// 2. Send STREAM_OPEN with metadata
	// 3. Bidirectional copy between conn and stream

	return errors.New("not implemented")
}

// TCPTunnel represents an active TCP tunnel.
type TCPTunnel struct {
	ID        string
	TunnelID  string
	Port      int
	Listener  net.Listener
	Active    int32
	CreatedAt time.Time

	mu     sync.Mutex
	conns  map[string]net.Conn
	closed bool
}

// NewTCPTunnel creates a new TCP tunnel.
func NewTCPTunnel(id, tunnelID string, port int) *TCPTunnel {
	return &TCPTunnel{
		ID:        id,
		TunnelID:  tunnelID,
		Port:      port,
		conns:     make(map[string]net.Conn),
		CreatedAt: time.Now(),
	}
}

// AddConnection adds a connection to the tunnel.
func (t *TCPTunnel) AddConnection(conn net.Conn) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.closed {
		conn.Close()
		return
	}

	t.conns[conn.RemoteAddr().String()] = conn
}

// RemoveConnection removes a connection from the tunnel.
func (t *TCPTunnel) RemoveConnection(addr string) {
	t.mu.Lock()
	defer t.mu.Unlock()

	delete(t.conns, addr)
}

// Close closes the TCP tunnel and all connections.
func (t *TCPTunnel) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.closed {
		return nil
	}
	t.closed = true

	// Close all connections
	for _, conn := range t.conns {
		conn.Close()
	}
	t.conns = nil

	// Close listener
	if t.Listener != nil {
		return t.Listener.Close()
	}

	return nil
}

// ConnectionCount returns the number of active connections.
func (t *TCPTunnel) ConnectionCount() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.conns)
}

// Copy bidirectionally between two connections.
func bidiCopy(dst net.Conn, src net.Conn, bufSize int) (int64, int64, error) {
	var written int64
	var read int64
	var err error
	var wg sync.WaitGroup

	// Copy src -> dst
	wg.Add(1)
	go func() {
		defer wg.Done()
		read, err = io.CopyBuffer(dst, src, make([]byte, bufSize))
		dst.Close()
	}()

	// Copy dst -> src
	wg.Add(1)
	go func() {
		defer wg.Done()
		written, _ = io.CopyBuffer(src, dst, make([]byte, bufSize))
		src.Close()
	}()

	wg.Wait()
	return written, read, err
}

// TCPTunnelRequest represents a TCP tunnel request.
type TCPTunnelRequest struct {
	TunnelID   string `json:"tunnel_id"`
	StreamID   uint32 `json:"stream_id"`
	RemoteAddr string `json:"remote_addr"`
}

// TCPTunnelResponse represents a TCP tunnel response.
type TCPTunnelResponse struct {
	OK      bool   `json:"ok"`
	Port    int    `json:"port,omitempty"`
	Error   string `json:"error,omitempty"`
}

// TCPConnection represents metadata about a TCP connection being tunneled.
type TCPConnection struct {
	TunnelID   string
	StreamID   uint32
	RemoteAddr string
	LocalAddr  string
	StartTime  time.Time
	BytesIn    int64
	BytesOut   int64
	Proto      string
}

// StreamOpenForTCP creates a STREAM_OPEN frame for a TCP connection.
func StreamOpenForTCP(tunnelID string, streamID uint32, remoteAddr string) (*proto.Frame, error) {
	msg := &proto.StreamOpen{
		TunnelID:   tunnelID,
		StreamID:   streamID,
		RemoteAddr: remoteAddr,
		Protocol:   "tcp",
	}
	return proto.EncodeJSONPayload(proto.FrameStreamOpen, streamID, msg)
}

// StreamOpenForHTTP creates a STREAM_OPEN frame for an HTTP connection.
func StreamOpenForHTTP(tunnelID string, streamID uint32, remoteAddr string) (*proto.Frame, error) {
	msg := &proto.StreamOpen{
		TunnelID:   tunnelID,
		StreamID:   streamID,
		RemoteAddr: remoteAddr,
		Protocol:   "http",
	}
	return proto.EncodeJSONPayload(proto.FrameStreamOpen, streamID, msg)
}
