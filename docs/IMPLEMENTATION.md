# WireRift — Implementation Guide

> **Companion to:** SPECIFICATION.md v1.0.0-draft  
> **Purpose:** Defines build order, code patterns, implementation strategies, and technical recipes  
> **Go Version:** 1.23+  
> **Constraint:** Zero external dependencies (stdlib only)

---

## Table of Contents

1. [Build Philosophy](#1-build-philosophy)
2. [Build Order (Phases)](#2-build-order-phases)
3. [Phase 1: Wire Protocol](#3-phase-1-wire-protocol)
4. [Phase 2: Stream Multiplexer](#4-phase-2-stream-multiplexer)
5. [Phase 3: Server Core](#5-phase-3-server-core)
6. [Phase 4: Client Core](#6-phase-4-client-core)
7. [Phase 5: HTTP Tunneling](#7-phase-5-http-tunneling)
8. [Phase 6: TCP Tunneling](#8-phase-6-tcp-tunneling)
9. [Phase 7: TLS & Certificates](#9-phase-7-tls--certificates)
10. [Phase 8: Authentication](#10-phase-8-authentication)
11. [Phase 9: Custom Domains](#11-phase-9-custom-domains)
12. [Phase 10: Dashboard & Inspector](#12-phase-10-dashboard--inspector)
13. [Phase 11: CLI](#13-phase-11-cli)
14. [Phase 12: Configuration](#14-phase-12-configuration)
15. [Phase 13: Observability](#15-phase-13-observability)
16. [Phase 14: Hardening](#16-phase-14-hardening)
17. [Code Patterns & Conventions](#17-code-patterns--conventions)
18. [Error Handling Strategy](#18-error-handling-strategy)
19. [Testing Strategy](#19-testing-strategy)
20. [Build & Release](#20-build--release)
21. [Critical Implementation Recipes](#21-critical-implementation-recipes)

---

## 1. Build Philosophy

### 1.1 Guiding Principles

1. **Bottom-up construction:** Build foundational layers first (protocol, mux), then compose into higher-level features.
2. **Test at every layer:** Each phase produces a testable, runnable artifact before proceeding.
3. **Integration checkpoints:** After every 2 phases, run a full integration test.
4. **No premature abstraction:** Start concrete, extract interfaces only when a second consumer appears.
5. **Fail loudly:** Prefer panics in development, graceful errors in production. Use build tags to control.
6. **Benchmark early:** Write benchmarks alongside unit tests for hot-path code (frame encoding, mux, ring buffer).

### 1.2 Dependency Rule

```
                    cmd/
                     │
                  internal/
                /    |    \
           server  client  cli
            / \      |
      proto  mux   auth  tls  config  ratelimit
```

- `proto` depends on nothing.
- `mux` depends on `proto`.
- `server` depends on `proto`, `mux`, `auth`, `tls`, `config`, `ratelimit`.
- `client` depends on `proto`, `mux`, `config`.
- `cli` depends on `config`.
- **No circular dependencies. No package imports upward.**

### 1.3 Interface Boundaries

Define interfaces at consumption points, not at implementation points:

```go
// BAD: interface in the implementing package
// internal/auth/auth.go
type Authenticator interface { ... }
type FileAuthenticator struct { ... }

// GOOD: interface where it's consumed
// internal/server/control.go
type Authenticator interface {
    Validate(token string) (*Account, error)
}
// internal/auth/store.go — just the concrete type
type FileStore struct { ... }
func (fs *FileStore) Validate(token string) (*Account, error) { ... }
```

---

## 2. Build Order (Phases)

```
Phase  1: Wire Protocol          ██░░░░░░░░░░░░  Foundation
Phase  2: Stream Multiplexer     ████░░░░░░░░░░  Foundation
          ── Integration Test A: mux over loopback ──
Phase  3: Server Core            ██████░░░░░░░░  Core
Phase  4: Client Core            ████████░░░░░░  Core
          ── Integration Test B: client ↔ server tunnel ──
Phase  5: HTTP Tunneling         ██████████░░░░  Features
Phase  6: TCP Tunneling          ██████████░░░░  Features
          ── Integration Test C: end-to-end HTTP + TCP ──
Phase  7: TLS & Certificates     ████████████░░  Security
Phase  8: Authentication         ████████████░░  Security
          ── Integration Test D: TLS + auth e2e ──
Phase  9: Custom Domains         ██████████████  Features
Phase 10: Dashboard & Inspector  ██████████████  Features
Phase 11: CLI                    ██████████████  UX
Phase 12: Configuration          ██████████████  UX
Phase 13: Observability          ██████████████  Ops
Phase 14: Hardening              ██████████████  Polish
          ── Full System Test ──
```

**Estimated LOC by phase:**

| Phase | Estimated LOC | Test LOC | Cumulative |
|-------|--------------|----------|------------|
| 1. Wire Protocol | ~400 | ~300 | 700 |
| 2. Multiplexer | ~600 | ~400 | 1,700 |
| 3. Server Core | ~500 | ~200 | 2,400 |
| 4. Client Core | ~400 | ~200 | 3,000 |
| 5. HTTP Tunneling | ~500 | ~300 | 3,800 |
| 6. TCP Tunneling | ~200 | ~150 | 4,150 |
| 7. TLS | ~600 | ~200 | 4,950 |
| 8. Auth | ~300 | ~200 | 5,450 |
| 9. Custom Domains | ~200 | ~100 | 5,750 |
| 10. Dashboard | ~800 | ~200 | 6,750 |
| 11. CLI | ~400 | ~200 | 7,350 |
| 12. Config | ~400 | ~300 | 8,050 |
| 13. Observability | ~300 | ~100 | 8,450 |
| 14. Hardening | ~300 | ~200 | 8,950 |
| **Total** | **~5,900** | **~3,050** | **~8,950** |

---

## 3. Phase 1: Wire Protocol

### 3.1 Goal

Implement frame encoding/decoding that is the foundation of all communication.

### 3.2 Files to Create

```
internal/proto/
├── constants.go      # Magic bytes, frame types, limits
├── frame.go          # Frame struct, Encode, Decode
├── frame_test.go     # Unit tests + benchmarks
├── message.go        # Control message types (JSON payloads)
└── message_test.go   # Message serialization tests
```

### 3.3 Implementation: constants.go

```go
package proto

const (
    // Magic bytes for protocol identification
    MagicByte0 byte = 0x57 // 'W'
    MagicByte1 byte = 0x52 // 'R'
    MagicByte2 byte = 0x46 // 'F'

    // Protocol version
    Version1 byte = 0x01

    // Frame header size
    HeaderSize = 9

    // Maximum payload size (16 MB)
    MaxPayloadSize = 1 << 24 // 16,777,216

    // Maximum stream ID (3 bytes)
    MaxStreamID = (1 << 24) - 1 // 16,777,215

    // Control stream (stream ID 0)
    ControlStream uint32 = 0

    // Default flow control window
    DefaultWindowSize = 256 * 1024 // 256 KB
)

// Frame types
const (
    FrameAuthReq      byte = 0x01
    FrameAuthRes      byte = 0x02
    FrameTunnelReq    byte = 0x03
    FrameTunnelRes    byte = 0x04
    FrameTunnelClose  byte = 0x05

    FrameStreamOpen   byte = 0x10
    FrameStreamData   byte = 0x11
    FrameStreamClose  byte = 0x12
    FrameStreamRst    byte = 0x13
    FrameStreamWindow byte = 0x14

    FrameHeartbeat    byte = 0x20
    FrameHeartbeatAck byte = 0x21

    FrameGoAway       byte = 0xFE
    FrameError        byte = 0xFF
)
```

### 3.4 Implementation: frame.go

```go
package proto

import (
    "encoding/binary"
    "fmt"
    "io"
    "sync"
)

// Frame represents a single protocol frame.
type Frame struct {
    Version  byte
    Type     byte
    StreamID uint32   // only lower 24 bits used
    Payload  []byte
}

// Header buffer pool to avoid allocations
var headerPool = sync.Pool{
    New: func() any {
        b := make([]byte, HeaderSize)
        return &b
    },
}

// Encode writes the frame to a writer.
// Wire format: [version:1][type:1][stream_id:3][length:4][payload:N]
func (f *Frame) Encode(w io.Writer) error {
    if len(f.Payload) > MaxPayloadSize {
        return fmt.Errorf("payload size %d exceeds max %d", len(f.Payload), MaxPayloadSize)
    }
    if f.StreamID > MaxStreamID {
        return fmt.Errorf("stream ID %d exceeds max %d", f.StreamID, MaxStreamID)
    }

    bufPtr := headerPool.Get().(*[]byte)
    buf := *bufPtr
    defer headerPool.Put(bufPtr)

    buf[0] = f.Version
    buf[1] = f.Type

    // Stream ID: 3 bytes, big-endian
    buf[2] = byte(f.StreamID >> 16)
    buf[3] = byte(f.StreamID >> 8)
    buf[4] = byte(f.StreamID)

    // Payload length: 4 bytes, big-endian
    binary.BigEndian.PutUint32(buf[5:9], uint32(len(f.Payload)))

    // Write header
    if _, err := w.Write(buf); err != nil {
        return fmt.Errorf("write header: %w", err)
    }

    // Write payload
    if len(f.Payload) > 0 {
        if _, err := w.Write(f.Payload); err != nil {
            return fmt.Errorf("write payload: %w", err)
        }
    }

    return nil
}

// ReadFrame reads a single frame from a reader.
func ReadFrame(r io.Reader) (*Frame, error) {
    // Read header
    var header [HeaderSize]byte
    if _, err := io.ReadFull(r, header[:]); err != nil {
        return nil, fmt.Errorf("read header: %w", err)
    }

    f := &Frame{
        Version: header[0],
        Type:    header[1],
    }

    // Decode stream ID (3 bytes big-endian)
    f.StreamID = uint32(header[2])<<16 | uint32(header[3])<<8 | uint32(header[4])

    // Decode payload length
    payloadLen := binary.BigEndian.Uint32(header[5:9])
    if payloadLen > MaxPayloadSize {
        return nil, fmt.Errorf("payload length %d exceeds max %d", payloadLen, MaxPayloadSize)
    }

    // Read payload
    if payloadLen > 0 {
        f.Payload = make([]byte, payloadLen)
        if _, err := io.ReadFull(r, f.Payload); err != nil {
            return nil, fmt.Errorf("read payload: %w", err)
        }
    }

    return f, nil
}

// FrameReader wraps a reader and provides buffered frame reading.
type FrameReader struct {
    r io.Reader
}

func NewFrameReader(r io.Reader) *FrameReader {
    return &FrameReader{r: r}
}

func (fr *FrameReader) Read() (*Frame, error) {
    return ReadFrame(fr.r)
}

// FrameWriter wraps a writer and provides synchronized frame writing.
type FrameWriter struct {
    w  io.Writer
    mu sync.Mutex
}

func NewFrameWriter(w io.Writer) *FrameWriter {
    return &FrameWriter{w: w}
}

func (fw *FrameWriter) Write(f *Frame) error {
    fw.mu.Lock()
    defer fw.mu.Unlock()
    return f.Encode(fw.w)
}
```

### 3.5 Implementation: message.go

```go
package proto

import (
    "encoding/json"
    "fmt"
    "time"
)

// --- Authentication ---

type AuthReq struct {
    Token    string `json:"token"`
    ClientID string `json:"client_id"`
    Version  string `json:"version"`
    OS       string `json:"os"`
    Arch     string `json:"arch"`
    Hostname string `json:"hostname"`
    // For reconnection:
    SessionID string `json:"session_id,omitempty"`
}

type AuthRes struct {
    OK                 bool   `json:"ok"`
    SessionID          string `json:"session_id,omitempty"`
    ServerVersion      string `json:"server_version"`
    HeartbeatIntervalMs int   `json:"heartbeat_interval_ms"`
    MaxTunnels         int    `json:"max_tunnels"`
    MaxStreamsPerTunnel int    `json:"max_streams_per_tunnel"`
    Error              string `json:"error,omitempty"`
}

// --- Tunnel Management ---

type TunnelType string

const (
    TunnelHTTP TunnelType = "http"
    TunnelTCP  TunnelType = "tcp"
)

type TunnelAuth struct {
    Type     string `json:"type"`               // "basic" or "bearer"
    Username string `json:"username,omitempty"`
    Password string `json:"password,omitempty"`
    Token    string `json:"token,omitempty"`
}

type TunnelReq struct {
    Type       TunnelType        `json:"type"`
    Name       string            `json:"name,omitempty"`
    Subdomain  string            `json:"subdomain,omitempty"`   // HTTP only
    Hostname   string            `json:"hostname,omitempty"`    // Custom domain
    RemotePort int               `json:"remote_port,omitempty"` // TCP only, 0 = auto
    LocalAddr  string            `json:"local_addr"`
    Inspect    bool              `json:"inspect"`
    Auth       *TunnelAuth       `json:"auth,omitempty"`
    Headers    map[string]string `json:"headers,omitempty"`
}

type TunnelRes struct {
    OK        bool       `json:"ok"`
    TunnelID  string     `json:"tunnel_id,omitempty"`
    Type      TunnelType `json:"type"`
    PublicURL string     `json:"public_url,omitempty"`
    Error     string     `json:"error,omitempty"`
    Metadata  struct {
        RemotePort int    `json:"remote_port,omitempty"`
        Subdomain  string `json:"subdomain,omitempty"`
    } `json:"metadata"`
}

type TunnelClose struct {
    TunnelID string `json:"tunnel_id"`
    Reason   string `json:"reason,omitempty"`
}

// --- Stream Management ---

type StreamOpen struct {
    TunnelID   string `json:"tunnel_id"`
    StreamID   uint32 `json:"stream_id"`
    RemoteAddr string `json:"remote_addr"`
    Protocol   string `json:"protocol"` // "http" or "tcp"
}

// --- Connection Management ---

type GoAway struct {
    Reason          string `json:"reason"`
    Message         string `json:"message"`
    ReconnectAfterMs int   `json:"reconnect_after_ms,omitempty"`
}

type ProtoError struct {
    Code    int    `json:"code"`
    Message string `json:"message"`
}

// --- Encoding Helpers ---

// MarshalFrame creates a Frame from a typed message.
func MarshalFrame(frameType byte, streamID uint32, msg any) (*Frame, error) {
    var payload []byte
    if msg != nil {
        var err error
        payload, err = json.Marshal(msg)
        if err != nil {
            return nil, fmt.Errorf("marshal message: %w", err)
        }
    }
    return &Frame{
        Version:  Version1,
        Type:     frameType,
        StreamID: streamID,
        Payload:  payload,
    }, nil
}

// UnmarshalPayload decodes a frame's JSON payload into a typed struct.
func UnmarshalPayload[T any](f *Frame) (*T, error) {
    var msg T
    if err := json.Unmarshal(f.Payload, &msg); err != nil {
        return nil, fmt.Errorf("unmarshal payload: %w", err)
    }
    return &msg, nil
}

// --- Heartbeat helpers ---

func NewHeartbeatFrame() *Frame {
    payload := make([]byte, 8)
    binary.BigEndian.PutUint64(payload, uint64(time.Now().UnixNano()))
    return &Frame{
        Version:  Version1,
        Type:     FrameHeartbeat,
        StreamID: ControlStream,
        Payload:  payload,
    }
}

func NewHeartbeatAckFrame(echoPayload []byte) *Frame {
    return &Frame{
        Version:  Version1,
        Type:     FrameHeartbeatAck,
        StreamID: ControlStream,
        Payload:  echoPayload,
    }
}

// HeartbeatTimestamp extracts the timestamp from a heartbeat frame.
func HeartbeatTimestamp(payload []byte) time.Time {
    if len(payload) < 8 {
        return time.Time{}
    }
    nanos := binary.BigEndian.Uint64(payload)
    return time.Unix(0, int64(nanos))
}

// --- Window update helper ---

func NewWindowUpdateFrame(streamID uint32, increment uint32) *Frame {
    payload := make([]byte, 4)
    binary.BigEndian.PutUint32(payload, increment)
    return &Frame{
        Version:  Version1,
        Type:     FrameStreamWindow,
        StreamID: streamID,
        Payload:  payload,
    }
}

func WindowIncrement(payload []byte) uint32 {
    if len(payload) < 4 {
        return 0
    }
    return binary.BigEndian.Uint32(payload)
}
```

### 3.6 Verification Criteria

- [ ] `Frame.Encode` + `ReadFrame` round-trip for all frame types.
- [ ] Payload boundary tests: 0 bytes, 1 byte, exactly MaxPayloadSize, MaxPayloadSize+1 (error).
- [ ] Stream ID boundary: 0, 1, MaxStreamID, MaxStreamID+1 (error).
- [ ] `MarshalFrame` + `UnmarshalPayload` for all message types.
- [ ] Heartbeat timestamp round-trip (encode time → decode time, delta < 1ms).
- [ ] Benchmark: `Encode` + `ReadFrame` should be < 500ns for 1 KB payload.
- [ ] `FrameWriter` concurrency: 100 goroutines writing simultaneously, no corruption.

---

## 4. Phase 2: Stream Multiplexer

### 4.1 Goal

Build the multiplexer that carries multiple logical streams over a single TCP connection. This is the most complex foundational component.

### 4.2 Files to Create

```
internal/mux/
├── mux.go            # Mux session manager
├── mux_test.go       # Integration tests
├── stream.go         # Stream implementation (io.ReadWriteCloser)
├── stream_test.go    # Stream unit tests
├── ringbuf.go        # Lock-free ring buffer
└── ringbuf_test.go   # Ring buffer tests + benchmarks
```

### 4.3 Implementation: ringbuf.go

```go
package mux

import (
    "errors"
    "sync"
)

var (
    ErrBufferFull  = errors.New("ring buffer is full")
    ErrBufferEmpty = errors.New("ring buffer is empty")
)

// RingBuffer is a fixed-size circular byte buffer with mutex protection.
type RingBuffer struct {
    buf  []byte
    size int
    r    int  // read position
    w    int  // write position
    full bool
    mu   sync.Mutex
}

func NewRingBuffer(size int) *RingBuffer {
    return &RingBuffer{
        buf:  make([]byte, size),
        size: size,
    }
}

// Write copies data into the buffer. Returns number of bytes written.
// Partial writes are allowed — writes as much as capacity permits.
func (rb *RingBuffer) Write(p []byte) (int, error) {
    rb.mu.Lock()
    defer rb.mu.Unlock()

    if rb.full {
        return 0, ErrBufferFull
    }

    avail := rb.available()
    if avail == 0 {
        return 0, ErrBufferFull
    }

    n := len(p)
    if n > avail {
        n = avail
    }

    // Write may wrap around
    if rb.w >= rb.r {
        // Write from w to end, then from start to r
        toEnd := rb.size - rb.w
        if n <= toEnd {
            copy(rb.buf[rb.w:], p[:n])
        } else {
            copy(rb.buf[rb.w:], p[:toEnd])
            copy(rb.buf[0:], p[toEnd:n])
        }
    } else {
        // Write from w to r
        copy(rb.buf[rb.w:], p[:n])
    }

    rb.w = (rb.w + n) % rb.size
    if rb.w == rb.r {
        rb.full = true
    }

    return n, nil
}

// Read copies data from the buffer into p. Returns number of bytes read.
func (rb *RingBuffer) Read(p []byte) (int, error) {
    rb.mu.Lock()
    defer rb.mu.Unlock()

    if rb.Len() == 0 {
        return 0, ErrBufferEmpty
    }

    n := len(p)
    buffered := rb.buffered()
    if n > buffered {
        n = buffered
    }

    // Read may wrap around
    if rb.r < rb.w || rb.full {
        if rb.full || rb.r >= rb.w {
            toEnd := rb.size - rb.r
            if n <= toEnd {
                copy(p, rb.buf[rb.r:rb.r+n])
            } else {
                copy(p, rb.buf[rb.r:])
                copy(p[toEnd:], rb.buf[:n-toEnd])
            }
        } else {
            copy(p, rb.buf[rb.r:rb.r+n])
        }
    } else {
        copy(p, rb.buf[rb.r:rb.r+n])
    }

    rb.r = (rb.r + n) % rb.size
    rb.full = false

    return n, nil
}

// Len returns the number of bytes currently buffered.
func (rb *RingBuffer) Len() int {
    rb.mu.Lock()
    defer rb.mu.Unlock()
    return rb.buffered()
}

func (rb *RingBuffer) buffered() int {
    if rb.full {
        return rb.size
    }
    if rb.w >= rb.r {
        return rb.w - rb.r
    }
    return rb.size - rb.r + rb.w
}

func (rb *RingBuffer) available() int {
    return rb.size - rb.buffered()
}

// Reset clears the buffer.
func (rb *RingBuffer) Reset() {
    rb.mu.Lock()
    defer rb.mu.Unlock()
    rb.r = 0
    rb.w = 0
    rb.full = false
}
```

### 4.4 Implementation: stream.go

```go
package mux

import (
    "errors"
    "io"
    "sync"
    "sync/atomic"
    "github.com/wirerift/wirerift/internal/proto"
)

// Stream states
const (
    stateOpen       uint32 = 0
    stateHalfLocal  uint32 = 1 // we sent close
    stateHalfRemote uint32 = 2 // they sent close
    stateClosed     uint32 = 3
    stateReset      uint32 = 4
)

var (
    ErrStreamClosed = errors.New("stream is closed")
    ErrStreamReset  = errors.New("stream was reset")
)

// Stream is a single logical bidirectional byte stream
// multiplexed over a shared TCP connection.
type Stream struct {
    id        uint32
    mux       *Mux
    readBuf   *RingBuffer
    readReady chan struct{}    // signaled when new data arrives in readBuf
    sendWin   atomic.Int32    // remaining send window (bytes)
    winNotify chan struct{}    // signaled on window update
    state     atomic.Uint32
    closeOnce sync.Once
    doneRead  chan struct{}    // closed when read side is done
}

func newStream(id uint32, m *Mux, bufSize int, initialWindow int32) *Stream {
    s := &Stream{
        id:        id,
        mux:       m,
        readBuf:   NewRingBuffer(bufSize),
        readReady: make(chan struct{}, 1),
        winNotify: make(chan struct{}, 1),
        doneRead:  make(chan struct{}),
    }
    s.sendWin.Store(initialWindow)
    return s
}

// ID returns the stream identifier.
func (s *Stream) ID() uint32 { return s.id }

// Read implements io.Reader. Blocks until data is available or stream closes.
func (s *Stream) Read(p []byte) (int, error) {
    for {
        state := s.state.Load()
        if state == stateReset {
            return 0, ErrStreamReset
        }

        // Try to read from buffer
        n, err := s.readBuf.Read(p)
        if n > 0 {
            // Send window update to remote
            s.mux.sendWindowUpdate(s.id, uint32(n))
            return n, nil
        }

        // Buffer empty — check if remote has closed
        if state == stateHalfRemote || state == stateClosed {
            return 0, io.EOF
        }

        if err == ErrBufferEmpty {
            // Wait for new data or state change
            select {
            case <-s.readReady:
                continue
            case <-s.doneRead:
                return 0, io.EOF
            }
        }

        return 0, err
    }
}

// Write implements io.Writer. Respects flow control window.
func (s *Stream) Write(p []byte) (int, error) {
    state := s.state.Load()
    if state >= stateHalfLocal {
        return 0, ErrStreamClosed
    }

    written := 0
    remaining := p

    for len(remaining) > 0 {
        // Wait for send window
        for s.sendWin.Load() <= 0 {
            select {
            case <-s.winNotify:
            case <-s.doneRead:
                return written, ErrStreamClosed
            }
        }

        // Calculate chunk size (min of remaining, window, max frame payload)
        win := int(s.sendWin.Load())
        chunk := len(remaining)
        if chunk > win {
            chunk = win
        }
        if chunk > proto.MaxPayloadSize {
            chunk = proto.MaxPayloadSize
        }

        // Send data frame
        err := s.mux.sendData(s.id, remaining[:chunk])
        if err != nil {
            return written, err
        }

        s.sendWin.Add(-int32(chunk))
        written += chunk
        remaining = remaining[chunk:]
    }

    return written, nil
}

// Close initiates stream close from our side.
func (s *Stream) Close() error {
    s.closeOnce.Do(func() {
        state := s.state.Load()
        switch state {
        case stateOpen:
            s.state.Store(stateHalfLocal)
            s.mux.sendStreamClose(s.id)
        case stateHalfRemote:
            s.state.Store(stateClosed)
            s.mux.sendStreamClose(s.id)
            s.cleanup()
        }
    })
    return nil
}

// remoteClose is called when the remote side closes.
func (s *Stream) remoteClose() {
    state := s.state.Load()
    switch state {
    case stateOpen:
        s.state.Store(stateHalfRemote)
        close(s.doneRead)
        s.notifyRead() // wake up blocked readers
    case stateHalfLocal:
        s.state.Store(stateClosed)
        close(s.doneRead)
        s.cleanup()
    }
}

// reset forcefully terminates the stream.
func (s *Stream) reset() {
    s.state.Store(stateReset)
    select {
    case <-s.doneRead:
    default:
        close(s.doneRead)
    }
    s.cleanup()
}

// receiveData is called by mux when data arrives for this stream.
func (s *Stream) receiveData(data []byte) error {
    _, err := s.readBuf.Write(data)
    if err != nil {
        return err
    }
    s.notifyRead()
    return nil
}

// addWindow is called when we receive a window update from remote.
func (s *Stream) addWindow(increment uint32) {
    s.sendWin.Add(int32(increment))
    select {
    case s.winNotify <- struct{}{}:
    default:
    }
}

func (s *Stream) notifyRead() {
    select {
    case s.readReady <- struct{}{}:
    default:
    }
}

func (s *Stream) cleanup() {
    s.mux.removeStream(s.id)
}
```

### 4.5 Implementation: mux.go

```go
package mux

import (
    "context"
    "fmt"
    "io"
    "log/slog"
    "net"
    "sync"
    "sync/atomic"
    "github.com/wirerift/wirerift/internal/proto"
)

// Config holds multiplexer configuration.
type Config struct {
    StreamBufSize  int   // per-stream read buffer (default: 64KB)
    WindowSize     int32 // initial flow control window (default: 256KB)
    MaxStreams      int   // max concurrent streams (default: 256)
}

func DefaultConfig() Config {
    return Config{
        StreamBufSize: 64 * 1024,
        WindowSize:    int32(proto.DefaultWindowSize),
        MaxStreams:     256,
    }
}

// Side indicates whether this is a client or server mux.
type Side int

const (
    SideClient Side = iota
    SideServer
)

// Mux multiplexes streams over a single net.Conn.
type Mux struct {
    conn    net.Conn
    side    Side
    config  Config
    writer  *proto.FrameWriter

    streams  sync.Map       // map[uint32]*Stream
    nextID   atomic.Uint32  // next stream ID to assign
    acceptCh chan *Stream    // incoming streams (for server side)

    ctx      context.Context
    cancel   context.CancelFunc
    closeCh  chan struct{}
    closeErr error
    once     sync.Once

    // Callbacks
    onHeartbeat    func(latency int64) // nanoseconds
    onGoAway       func(msg proto.GoAway)
    onStreamOpen   func(streamID uint32, payload []byte) // raw JSON for StreamOpen
}

// New creates a new multiplexer over the given connection.
func New(conn net.Conn, side Side, config Config) *Mux {
    ctx, cancel := context.WithCancel(context.Background())

    m := &Mux{
        conn:     conn,
        side:     side,
        config:   config,
        writer:   proto.NewFrameWriter(conn),
        acceptCh: make(chan *Stream, config.MaxStreams),
        ctx:      ctx,
        cancel:   cancel,
        closeCh:  make(chan struct{}),
    }

    // Client uses odd stream IDs, server uses even
    if side == SideClient {
        m.nextID.Store(1)
    } else {
        m.nextID.Store(2)
    }

    return m
}

// Start begins the frame reader loop. Must be called after New.
func (m *Mux) Start() {
    go m.readLoop()
}

// Accept returns the next incoming stream (server-side usage).
func (m *Mux) Accept() (*Stream, error) {
    select {
    case s := <-m.acceptCh:
        return s, nil
    case <-m.closeCh:
        return nil, fmt.Errorf("mux closed: %w", m.closeErr)
    }
}

// Open creates a new outgoing stream.
func (m *Mux) Open() (*Stream, error) {
    id := m.allocateID()
    s := newStream(id, m, m.config.StreamBufSize, m.config.WindowSize)
    m.streams.Store(id, s)
    return s, nil
}

// Close gracefully shuts down the multiplexer.
func (m *Mux) Close() error {
    m.once.Do(func() {
        m.cancel()
        close(m.closeCh)

        // Send GO_AWAY
        goAway := proto.GoAway{Reason: "normal_close", Message: "connection closing"}
        if f, err := proto.MarshalFrame(proto.FrameGoAway, proto.ControlStream, goAway); err == nil {
            m.writer.Write(f) // best-effort
        }

        // Close all streams
        m.streams.Range(func(key, value any) bool {
            if s, ok := value.(*Stream); ok {
                s.reset()
            }
            return true
        })

        m.conn.Close()
    })
    return nil
}

// readLoop is the main frame reading goroutine.
func (m *Mux) readLoop() {
    reader := proto.NewFrameReader(m.conn)
    defer m.Close()

    for {
        f, err := reader.Read()
        if err != nil {
            if err != io.EOF {
                slog.Debug("mux read error", "error", err)
                m.closeErr = err
            }
            return
        }

        if err := m.handleFrame(f); err != nil {
            slog.Error("handle frame error", "type", f.Type, "stream", f.StreamID, "error", err)
            m.closeErr = err
            return
        }
    }
}

func (m *Mux) handleFrame(f *proto.Frame) error {
    switch f.Type {

    case proto.FrameStreamOpen:
        return m.handleStreamOpen(f)

    case proto.FrameStreamData:
        return m.handleStreamData(f)

    case proto.FrameStreamClose:
        return m.handleStreamClose(f)

    case proto.FrameStreamRst:
        return m.handleStreamReset(f)

    case proto.FrameStreamWindow:
        return m.handleWindowUpdate(f)

    case proto.FrameHeartbeat:
        // Echo back as ACK
        ack := proto.NewHeartbeatAckFrame(f.Payload)
        return m.writer.Write(ack)

    case proto.FrameHeartbeatAck:
        if m.onHeartbeat != nil {
            sent := proto.HeartbeatTimestamp(f.Payload)
            latency := time.Now().Sub(sent).Nanoseconds()
            m.onHeartbeat(latency)
        }
        return nil

    case proto.FrameGoAway:
        goAway, err := proto.UnmarshalPayload[proto.GoAway](f)
        if err != nil {
            return err
        }
        if m.onGoAway != nil {
            m.onGoAway(*goAway)
        }
        return nil

    // Control frames (auth, tunnel) are handled by the layer above mux.
    // They arrive on ControlStream and are dispatched by the caller.
    default:
        if f.StreamID == proto.ControlStream {
            // Let the control handler deal with it
            // The mux exposes a method to read control frames
            return nil
        }
        return fmt.Errorf("unknown frame type: 0x%02x", f.Type)
    }
}

func (m *Mux) handleStreamOpen(f *proto.Frame) error {
    id := f.StreamID
    s := newStream(id, m, m.config.StreamBufSize, m.config.WindowSize)
    m.streams.Store(id, s)

    // Notify via callback and/or accept channel
    if m.onStreamOpen != nil {
        m.onStreamOpen(id, f.Payload)
    }

    select {
    case m.acceptCh <- s:
    default:
        // Accept channel full — reset stream
        s.reset()
        return m.sendStreamReset(id)
    }

    return nil
}

func (m *Mux) handleStreamData(f *proto.Frame) error {
    v, ok := m.streams.Load(f.StreamID)
    if !ok {
        // Unknown stream — send RST
        return m.sendStreamReset(f.StreamID)
    }
    s := v.(*Stream)
    return s.receiveData(f.Payload)
}

func (m *Mux) handleStreamClose(f *proto.Frame) error {
    v, ok := m.streams.Load(f.StreamID)
    if !ok {
        return nil // already cleaned up
    }
    s := v.(*Stream)
    s.remoteClose()
    return nil
}

func (m *Mux) handleStreamReset(f *proto.Frame) error {
    v, ok := m.streams.Load(f.StreamID)
    if !ok {
        return nil
    }
    s := v.(*Stream)
    s.reset()
    return nil
}

func (m *Mux) handleWindowUpdate(f *proto.Frame) error {
    v, ok := m.streams.Load(f.StreamID)
    if !ok {
        return nil
    }
    s := v.(*Stream)
    inc := proto.WindowIncrement(f.Payload)
    s.addWindow(inc)
    return nil
}

// --- Send helpers (called by Stream) ---

func (m *Mux) sendData(streamID uint32, data []byte) error {
    f := &proto.Frame{
        Version:  proto.Version1,
        Type:     proto.FrameStreamData,
        StreamID: streamID,
        Payload:  data,
    }
    return m.writer.Write(f)
}

func (m *Mux) sendStreamClose(streamID uint32) error {
    f := &proto.Frame{
        Version:  proto.Version1,
        Type:     proto.FrameStreamClose,
        StreamID: streamID,
    }
    return m.writer.Write(f)
}

func (m *Mux) sendStreamReset(streamID uint32) error {
    f := &proto.Frame{
        Version:  proto.Version1,
        Type:     proto.FrameStreamRst,
        StreamID: streamID,
    }
    return m.writer.Write(f)
}

func (m *Mux) sendWindowUpdate(streamID uint32, increment uint32) {
    f := proto.NewWindowUpdateFrame(streamID, increment)
    m.writer.Write(f) // best-effort
}

func (m *Mux) removeStream(id uint32) {
    m.streams.Delete(id)
}

func (m *Mux) allocateID() uint32 {
    // Client: odd IDs (1, 3, 5, ...), Server: even IDs (2, 4, 6, ...)
    return m.nextID.Add(2) - 2
}

// SendHeartbeat sends a heartbeat frame.
func (m *Mux) SendHeartbeat() error {
    return m.writer.Write(proto.NewHeartbeatFrame())
}

// SendControlFrame sends a control frame (used by server/client layers above).
func (m *Mux) SendControlFrame(frameType byte, msg any) error {
    f, err := proto.MarshalFrame(frameType, proto.ControlStream, msg)
    if err != nil {
        return err
    }
    return m.writer.Write(f)
}
```

### 4.6 Integration Test A: Mux Over Loopback

```go
func TestMuxRoundTrip(t *testing.T) {
    // Create pipe (simulates TCP connection)
    sConn, cConn := net.Pipe()

    serverMux := mux.New(sConn, mux.SideServer, mux.DefaultConfig())
    clientMux := mux.New(cConn, mux.SideClient, mux.DefaultConfig())

    serverMux.Start()
    clientMux.Start()

    // Client opens stream, writes data, reads response
    go func() {
        stream, _ := clientMux.Open()
        // Notify server about this stream (normally server opens via STREAM_OPEN)
        stream.Write([]byte("Hello from client"))
        
        buf := make([]byte, 1024)
        n, _ := stream.Read(buf)
        assert(string(buf[:n]) == "Hello from server")
        stream.Close()
    }()

    // Server accepts stream, reads, writes back
    stream, _ := serverMux.Accept()
    buf := make([]byte, 1024)
    n, _ := stream.Read(buf)
    assert(string(buf[:n]) == "Hello from client")
    stream.Write([]byte("Hello from server"))
    stream.Close()
}
```

### 4.7 Verification Criteria

- [ ] RingBuffer: write/read round-trip, wrap-around, full/empty states.
- [ ] Stream: Read blocks until data or close. Write respects window.
- [ ] Mux: Open/Accept works. Multiple concurrent streams.
- [ ] Flow control: sender blocks when window exhausted, resumes on update.
- [ ] Stream close: half-close state transitions.
- [ ] Stream reset: immediate cleanup.
- [ ] Heartbeat: round-trip latency measurement.
- [ ] Benchmark: 1000 concurrent streams, 1 MB each, throughput > 100 MB/s over loopback.

---

## 5. Phase 3: Server Core

### 5.1 Goal

Build the server skeleton: control plane listener, session management, and routing registry.

### 5.2 Files to Create

```
internal/server/
├── server.go        # Main server, wires everything together
├── control.go       # Control plane: accepts client connections
├── session.go       # Session + tunnel lifecycle
└── router.go        # Routing registry (subdomain → tunnel, port → tunnel)
```

### 5.3 Key Implementation: server.go

```go
package server

import (
    "context"
    "log/slog"
    "net"
    "sync"
)

type Server struct {
    config     *Config
    control    *ControlPlane
    httpEdge   *HTTPEdge
    tcpEdge    *TCPEdge
    router     *Router
    sessions   *SessionStore
    dashboard  *Dashboard
    
    ctx        context.Context
    cancel     context.CancelFunc
    wg         sync.WaitGroup
}

func New(config *Config) *Server {
    ctx, cancel := context.WithCancel(context.Background())
    
    router := NewRouter()
    sessions := NewSessionStore()
    
    s := &Server{
        config:   config,
        router:   router,
        sessions: sessions,
        ctx:      ctx,
        cancel:   cancel,
    }
    
    s.control = NewControlPlane(s)
    s.httpEdge = NewHTTPEdge(s)
    s.tcpEdge = NewTCPEdge(s)
    s.dashboard = NewDashboard(s)
    
    return s
}

func (s *Server) Start() error {
    slog.Info("starting tunnel server",
        "control", s.config.ControlAddr,
        "http", s.config.HTTPAddr,
        "dashboard", s.config.DashboardAddr,
    )

    // Start components
    if err := s.control.Start(); err != nil {
        return fmt.Errorf("control plane: %w", err)
    }
    if err := s.httpEdge.Start(); err != nil {
        return fmt.Errorf("http edge: %w", err)
    }
    if err := s.tcpEdge.Start(); err != nil {
        return fmt.Errorf("tcp edge: %w", err)
    }
    if err := s.dashboard.Start(); err != nil {
        return fmt.Errorf("dashboard: %w", err)
    }

    // Start session janitor (evicts expired sessions)
    s.wg.Add(1)
    go s.sessionJanitor()

    return nil
}

func (s *Server) Shutdown(ctx context.Context) error {
    slog.Info("shutting down server")
    s.cancel()

    // Send GO_AWAY to all sessions
    s.sessions.BroadcastGoAway("server_shutdown", "Server is shutting down")

    // Wait for in-flight requests to complete
    s.wg.Wait()

    return nil
}
```

### 5.4 Key Implementation: router.go

```go
package server

import "sync"

type Router struct {
    httpRoutes sync.Map  // map[string]*Tunnel   (hostname → tunnel)
    tcpRoutes  sync.Map  // map[int]*Tunnel      (port → tunnel)
    reserved   map[string]bool
}

func NewRouter() *Router {
    return &Router{
        reserved: map[string]bool{
            "www": true, "api": true, "admin": true,
            "dashboard": true, "status": true, "health": true,
            "metrics": true, "mail": true, "ftp": true,
            "ssh": true, "ns1": true, "ns2": true,
        },
    }
}

func (r *Router) RegisterHTTP(subdomain string, t *Tunnel) error {
    if r.reserved[subdomain] {
        return fmt.Errorf("subdomain %q is reserved", subdomain)
    }
    if _, loaded := r.httpRoutes.LoadOrStore(subdomain, t); loaded {
        return fmt.Errorf("subdomain %q already in use", subdomain)
    }
    return nil
}

func (r *Router) LookupHTTP(hostname string) (*Tunnel, bool) {
    // Extract subdomain from hostname
    subdomain := extractSubdomain(hostname, baseDomain)
    v, ok := r.httpRoutes.Load(subdomain)
    if !ok {
        // Try full hostname (custom domain)
        v, ok = r.httpRoutes.Load(hostname)
        if !ok {
            return nil, false
        }
    }
    return v.(*Tunnel), true
}

func (r *Router) RegisterTCP(port int, t *Tunnel) {
    r.tcpRoutes.Store(port, t)
}

func (r *Router) LookupTCP(port int) (*Tunnel, bool) {
    v, ok := r.tcpRoutes.Load(port)
    if !ok {
        return nil, false
    }
    return v.(*Tunnel), true
}

func (r *Router) Unregister(t *Tunnel) {
    if t.Subdomain != "" {
        r.httpRoutes.Delete(t.Subdomain)
    }
    if t.Hostname != "" {
        r.httpRoutes.Delete(t.Hostname)
    }
    if t.RemotePort != 0 {
        r.tcpRoutes.Delete(t.RemotePort)
    }
}
```

### 5.5 Verification Criteria

- [ ] Server starts and listens on control, HTTP, TCP ports.
- [ ] Client connects to control port → handshake completes.
- [ ] Session is created and tracked.
- [ ] Router registers/unregisters routes correctly.
- [ ] Subdomain conflict detection works.
- [ ] Reserved subdomain rejection works.
- [ ] Session janitor evicts expired sessions.

---

## 6. Phase 4: Client Core

### 6.1 Goal

Build the agent that connects to the server, requests tunnels, and manages streams.

### 6.2 Files to Create

```
internal/client/
├── agent.go         # Main agent controller
├── proxy.go         # Local service proxy (HTTP + TCP)
└── reconnect.go     # Reconnection with exponential backoff
```

### 6.3 Key Implementation: agent.go

```go
package client

import (
    "context"
    "crypto/tls"
    "fmt"
    "log/slog"
    "net"
    "os"
    "runtime"
    "github.com/wirerift/wirerift/internal/mux"
    "github.com/wirerift/wirerift/internal/proto"
)

type Agent struct {
    config    *Config
    muxConn   *mux.Mux
    tunnels   map[string]*TunnelInfo
    sessionID string
    ctx       context.Context
    cancel    context.CancelFunc
}

type TunnelInfo struct {
    Config    TunnelConfig
    ID        string
    PublicURL string
}

func NewAgent(config *Config) *Agent {
    ctx, cancel := context.WithCancel(context.Background())
    return &Agent{
        config:  config,
        tunnels: make(map[string]*TunnelInfo),
        ctx:     ctx,
        cancel:  cancel,
    }
}

func (a *Agent) Run() error {
    return RunWithReconnect(a.ctx, a.config.ServerAddr, func(conn net.Conn) error {
        return a.session(conn)
    })
}

func (a *Agent) session(conn net.Conn) error {
    // Create mux
    cfg := mux.DefaultConfig()
    m := mux.New(conn, mux.SideClient, cfg)
    a.muxConn = m
    m.Start()
    defer m.Close()

    // Authenticate
    if err := a.authenticate(m); err != nil {
        return fmt.Errorf("auth failed: %w", err)
    }

    // Request tunnels
    for _, tc := range a.config.Tunnels {
        if err := a.requestTunnel(m, tc); err != nil {
            slog.Error("tunnel request failed", "name", tc.Name, "error", err)
        }
    }

    // Print status
    a.printStatus()

    // Main loop: accept streams
    for {
        stream, err := m.Accept()
        if err != nil {
            return err
        }
        go a.handleStream(stream)
    }
}

func (a *Agent) authenticate(m *mux.Mux) error {
    hostname, _ := os.Hostname()
    req := proto.AuthReq{
        Token:     a.config.AuthToken,
        ClientID:  generateClientID(),
        Version:   Version,
        OS:        runtime.GOOS,
        Arch:      runtime.GOARCH,
        Hostname:  hostname,
        SessionID: a.sessionID, // for reconnection
    }
    return m.SendControlFrame(proto.FrameAuthReq, req)
    // Response handled in control frame reader
}

func (a *Agent) handleStream(stream *mux.Stream) {
    defer stream.Close()
    
    // Determine which tunnel this stream belongs to
    // (from STREAM_OPEN metadata stored by mux callback)
    
    // Proxy to local service
    localConn, err := net.Dial("tcp", tunnel.LocalAddr)
    if err != nil {
        slog.Error("local dial failed", "addr", tunnel.LocalAddr, "error", err)
        // Write error response if HTTP
        return
    }
    defer localConn.Close()

    // Bidirectional copy
    bridgeStreams(stream, localConn)
}
```

### 6.4 Key Implementation: reconnect.go

```go
package client

import (
    "context"
    "crypto/tls"
    "log/slog"
    "math"
    "net"
    "time"
)

const (
    initialBackoff = 500 * time.Millisecond
    maxBackoff     = 30 * time.Second
    backoffFactor  = 2.0
    stableAfter    = 60 * time.Second
)

// RunWithReconnect keeps reconnecting with exponential backoff.
func RunWithReconnect(ctx context.Context, addr string, sessionFn func(net.Conn) error) error {
    attempt := 0

    for {
        select {
        case <-ctx.Done():
            return ctx.Err()
        default:
        }

        conn, err := dialServer(ctx, addr)
        if err != nil {
            attempt++
            backoff := calcBackoff(attempt)
            slog.Warn("connection failed, retrying",
                "attempt", attempt,
                "backoff", backoff,
                "error", err,
            )
            select {
            case <-time.After(backoff):
                continue
            case <-ctx.Done():
                return ctx.Err()
            }
        }

        connectedAt := time.Now()
        slog.Info("connected to server", "addr", addr)

        err = sessionFn(conn)
        conn.Close()

        // If connection was stable, reset backoff
        if time.Since(connectedAt) > stableAfter {
            attempt = 0
        }

        if err != nil {
            slog.Warn("session ended", "error", err)
        }
    }
}

func calcBackoff(attempt int) time.Duration {
    backoff := float64(initialBackoff) * math.Pow(backoffFactor, float64(attempt-1))
    if backoff > float64(maxBackoff) {
        backoff = float64(maxBackoff)
    }
    return time.Duration(backoff)
}

func dialServer(ctx context.Context, addr string) (net.Conn, error) {
    dialer := &net.Dialer{Timeout: 10 * time.Second}
    
    // TLS connection
    tlsConfig := &tls.Config{
        MinVersion: tls.VersionTLS12,
        // ServerName is extracted from addr
    }

    conn, err := tls.DialWithDialer(dialer, "tcp", addr, tlsConfig)
    if err != nil {
        return nil, err
    }

    // Send magic bytes
    magic := []byte{proto.MagicByte0, proto.MagicByte1, proto.MagicByte2, proto.Version1}
    if _, err := conn.Write(magic); err != nil {
        conn.Close()
        return nil, err
    }

    return conn, nil
}
```

### 6.5 Integration Test B

```
Test: Client connects to server → authenticates → requests HTTP tunnel →
      server allocates subdomain → client receives TUNNEL_RES →
      verify tunnel appears in router.
```

---

## 7. Phase 5: HTTP Tunneling

### 7.1 Goal

End-to-end HTTP tunneling: public request → server → mux → client → local service → back.

### 7.2 Files to Create

```
internal/server/
└── edge_http.go     # HTTP edge listener + reverse proxy

internal/client/
└── proxy.go         # (extend) HTTP-aware local proxy
```

### 7.3 Key Implementation: edge_http.go

```go
package server

import (
    "fmt"
    "log/slog"
    "net"
    "net/http"
    "strings"
    "time"
    "github.com/wirerift/wirerift/internal/proto"
)

type HTTPEdge struct {
    server   *Server
    listener net.Listener
}

func (e *HTTPEdge) ServeHTTP(w http.ResponseWriter, r *http.Request) {
    // 1. Route lookup
    tunnel, ok := e.server.router.LookupHTTP(r.Host)
    if !ok {
        http.Error(w, "Tunnel not found", http.StatusBadGateway)
        return
    }

    // 2. Check tunnel-level auth if configured
    if tunnel.Auth != nil {
        if !checkTunnelAuth(r, tunnel.Auth) {
            w.Header().Set("WWW-Authenticate", `Basic realm="tunnel"`)
            http.Error(w, "Unauthorized", http.StatusUnauthorized)
            return
        }
    }

    // 3. Check for WebSocket upgrade
    if isWebSocketUpgrade(r) {
        e.handleWebSocket(w, r, tunnel)
        return
    }

    // 4. Open mux stream to client
    stream, err := e.openStream(tunnel, r.RemoteAddr)
    if err != nil {
        http.Error(w, "Tunnel offline", http.StatusServiceUnavailable)
        return
    }
    defer stream.Close()

    // 5. Add forwarding headers
    addForwardHeaders(r, tunnel)

    // 6. Write HTTP request to stream
    if err := r.Write(stream); err != nil {
        http.Error(w, "Failed to forward request", http.StatusBadGateway)
        return
    }

    // 7. Read HTTP response from stream
    resp, err := http.ReadResponse(bufio.NewReader(stream), r)
    if err != nil {
        http.Error(w, "Failed to read response", http.StatusBadGateway)
        return
    }
    defer resp.Body.Close()

    // 8. Copy response headers
    for k, vv := range resp.Header {
        for _, v := range vv {
            w.Header().Add(k, v)
        }
    }
    w.WriteHeader(resp.StatusCode)

    // 9. Copy response body (streaming)
    io.Copy(w, resp.Body)

    // 10. Record metrics
    tunnel.BytesIn.Add(r.ContentLength)
    tunnel.Connections.Add(1)
}

func (e *HTTPEdge) handleWebSocket(w http.ResponseWriter, r *http.Request, t *Tunnel) {
    // Hijack the HTTP connection
    hijacker, ok := w.(http.Hijacker)
    if !ok {
        http.Error(w, "WebSocket not supported", http.StatusInternalServerError)
        return
    }

    pubConn, _, err := hijacker.Hijack()
    if err != nil {
        return
    }
    defer pubConn.Close()

    // Open mux stream
    stream, err := e.openStream(t, r.RemoteAddr)
    if err != nil {
        return
    }
    defer stream.Close()

    // Forward the original upgrade request
    r.Write(stream)

    // Bridge raw connections
    bridgeStreams(pubConn, stream)
}

func addForwardHeaders(r *http.Request, t *Tunnel) {
    clientIP, _, _ := net.SplitHostPort(r.RemoteAddr)
    r.Header.Set("X-Forwarded-For", clientIP)
    r.Header.Set("X-Forwarded-Proto", "https")
    r.Header.Set("X-Forwarded-Host", r.Host)
    r.Header.Set("X-Real-IP", clientIP)

    // Apply custom headers from tunnel config
    for k, v := range t.CustomHeaders {
        r.Header.Set(k, v)
    }
}

func isWebSocketUpgrade(r *http.Request) bool {
    return strings.EqualFold(r.Header.Get("Upgrade"), "websocket") &&
        strings.Contains(strings.ToLower(r.Header.Get("Connection")), "upgrade")
}
```

### 7.4 Client-Side HTTP Proxy

```go
// In client/proxy.go
func (a *Agent) proxyHTTP(stream *mux.Stream, localAddr string) error {
    // Read HTTP request from stream
    req, err := http.ReadRequest(bufio.NewReader(stream))
    if err != nil {
        return err
    }

    // Rewrite for local service
    req.URL.Scheme = "http"
    req.URL.Host = localAddr
    req.RequestURI = "" // Required for http.Client

    // Forward to local service
    resp, err := http.DefaultTransport.RoundTrip(req)
    if err != nil {
        // Write error response back to stream
        writeErrorResponse(stream, http.StatusBadGateway,
            fmt.Sprintf("Local service error: %s", err))
        return err
    }
    defer resp.Body.Close()

    // Write response back to stream
    return resp.Write(stream)
}
```

---

## 8. Phase 6: TCP Tunneling

### 8.1 Goal

Raw TCP port forwarding through the tunnel.

### 8.2 Files to Create

```
internal/server/
├── edge_tcp.go      # TCP edge listener + port allocation
└── portalloc.go     # Port allocator
```

### 8.3 Key Implementation: portalloc.go

```go
package server

import (
    "fmt"
    "net"
    "sync"
)

type PortAllocator struct {
    min  int
    max  int
    used map[int]*Tunnel
    mu   sync.Mutex
}

func NewPortAllocator(min, max int) *PortAllocator {
    return &PortAllocator{
        min:  min,
        max:  max,
        used: make(map[int]*Tunnel),
    }
}

func (pa *PortAllocator) Allocate(requested int, tunnel *Tunnel) (int, error) {
    pa.mu.Lock()
    defer pa.mu.Unlock()

    if requested != 0 {
        if requested < pa.min || requested > pa.max {
            return 0, fmt.Errorf("port %d outside range [%d, %d]", requested, pa.min, pa.max)
        }
        if _, exists := pa.used[requested]; exists {
            return 0, fmt.Errorf("port %d already in use", requested)
        }
        // Verify port is actually available on the OS
        if err := probePort(requested); err != nil {
            return 0, fmt.Errorf("port %d not available: %w", requested, err)
        }
        pa.used[requested] = tunnel
        return requested, nil
    }

    // Auto-assign: find first available
    for port := pa.min; port <= pa.max; port++ {
        if _, exists := pa.used[port]; exists {
            continue
        }
        if err := probePort(port); err != nil {
            continue
        }
        pa.used[port] = tunnel
        return port, nil
    }

    return 0, fmt.Errorf("no available ports in range [%d, %d]", pa.min, pa.max)
}

func (pa *PortAllocator) Release(port int) {
    pa.mu.Lock()
    defer pa.mu.Unlock()
    delete(pa.used, port)
}

// probePort checks if a port is available by briefly listening.
func probePort(port int) error {
    ln, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
    if err != nil {
        return err
    }
    ln.Close()
    return nil
}
```

### 8.4 Key Implementation: edge_tcp.go

```go
package server

import (
    "log/slog"
    "net"
)

type TCPEdge struct {
    server    *Server
    allocator *PortAllocator
    listeners map[int]net.Listener
    mu        sync.Mutex
}

func (e *TCPEdge) OpenPort(tunnel *Tunnel, requestedPort int) (int, error) {
    port, err := e.allocator.Allocate(requestedPort, tunnel)
    if err != nil {
        return 0, err
    }

    ln, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
    if err != nil {
        e.allocator.Release(port)
        return 0, err
    }

    e.mu.Lock()
    e.listeners[port] = ln
    e.mu.Unlock()

    // Accept loop for this port
    go func() {
        defer ln.Close()
        defer e.allocator.Release(port)

        for {
            conn, err := ln.Accept()
            if err != nil {
                return
            }
            go e.handleTCPConn(conn, tunnel)
        }
    }()

    return port, nil
}

func (e *TCPEdge) handleTCPConn(conn net.Conn, tunnel *Tunnel) {
    defer conn.Close()

    // Open mux stream to client
    stream, err := e.server.openStreamForTunnel(tunnel, conn.RemoteAddr().String())
    if err != nil {
        slog.Error("failed to open stream for TCP", "error", err)
        return
    }
    defer stream.Close()

    // Bidirectional bridge
    bridgeStreams(conn, stream)
}
```

### 8.5 Integration Test C

```
Test: Full end-to-end flow:
1. Start local HTTP server on :9999
2. Start tunnel server
3. Start tunnel client → connects, requests HTTP tunnel "test"
4. Make HTTP request to test.tunnel.dev → response matches local server
5. Start local TCP server (echo) on :9998
6. Request TCP tunnel → get port 20001
7. Connect to :20001 → send data → verify echo
```

---

## 9. Phase 7: TLS & Certificates

### 9.1 Goal

Implement three TLS modes and the zero-dependency ACME client.

### 9.2 Files to Create

```
internal/tls/
├── manager.go       # Certificate manager with GetCertificate for SNI
├── acme.go          # Minimal ACME client (HTTP-01 challenge)
├── selfsigned.go    # Self-signed certificate generator
└── acme_test.go
```

### 9.3 Key Implementation: selfsigned.go

```go
package tlsutil

import (
    "crypto/ecdsa"
    "crypto/elliptic"
    "crypto/rand"
    "crypto/tls"
    "crypto/x509"
    "crypto/x509/pkix"
    "encoding/pem"
    "math/big"
    "time"
)

// GenerateSelfSigned creates a self-signed TLS certificate for the given hosts.
func GenerateSelfSigned(hosts []string, validDays int) (*tls.Certificate, error) {
    key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
    if err != nil {
        return nil, err
    }

    serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))

    tmpl := &x509.Certificate{
        SerialNumber: serial,
        Subject:      pkix.Name{Organization: []string{"Tunnel Dev"}},
        NotBefore:    time.Now(),
        NotAfter:     time.Now().Add(time.Duration(validDays) * 24 * time.Hour),
        KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
        ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
    }

    for _, h := range hosts {
        if ip := net.ParseIP(h); ip != nil {
            tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
        } else {
            tmpl.DNSNames = append(tmpl.DNSNames, h)
        }
    }

    certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
    if err != nil {
        return nil, err
    }

    certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
    keyDER, _ := x509.MarshalECPrivateKey(key)
    keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

    cert, err := tls.X509KeyPair(certPEM, keyPEM)
    return &cert, err
}
```

### 9.4 ACME Client Sketch

```go
// internal/tls/acme.go
// Minimal ACME client using only net/http + crypto stdlib

type ACMEClient struct {
    directory    string
    accountKey   *ecdsa.PrivateKey
    httpClient   *http.Client
    nonces       []string          // replay nonce pool
    mu           sync.Mutex
}

// Core ACME operations (all use JWS-signed POST):
// 1. newAccount() → register or fetch existing
// 2. newOrder(domain) → create certificate order
// 3. solveHTTP01(challenge) → serve /.well-known/acme-challenge/<token>
// 4. finalizeOrder(orderURL, csr) → submit CSR
// 5. downloadCert(certURL) → get certificate chain

// JWS signing using crypto/ecdsa + encoding/json + base64url
func (c *ACMEClient) signedPost(url string, payload any) (*http.Response, error) {
    // Build JWS with:
    // - Header: alg=ES256, nonce, url, kid (or jwk for new-account)
    // - Payload: JSON or "" for POST-as-GET
    // - Signature: ECDSA P-256
    // All using: crypto/ecdsa, crypto/sha256, encoding/json, encoding/base64
}
```

**Implementation note:** ACME is ~500-800 LOC. The key challenge is JWS (JSON Web Signature) construction. We need:
- `base64url` encoding (no padding) — trivial with `encoding/base64.RawURLEncoding`
- ECDSA signing — `crypto/ecdsa.Sign`
- SHA-256 — `crypto/sha256`
- HTTP-01 challenge serving — temporary handler on port 80

---

## 10. Phase 8: Authentication

### 10.1 Files to Create

```
internal/auth/
├── token.go         # Token generation + hashing
├── store.go         # File-based auth store
└── token_test.go
```

### 10.2 Key Implementation: token.go

```go
package auth

import (
    "crypto/rand"
    "crypto/sha256"
    "crypto/subtle"
    "encoding/base64"
    "fmt"
)

const tokenPrefix = "tk_"

// GenerateToken creates a cryptographically random auth token.
func GenerateToken() (string, error) {
    bytes := make([]byte, 32)
    if _, err := rand.Read(bytes); err != nil {
        return "", fmt.Errorf("generate random: %w", err)
    }
    return tokenPrefix + base64.RawURLEncoding.EncodeToString(bytes), nil
}

// HashToken returns SHA-256 hash of token for storage.
func HashToken(token string) string {
    h := sha256.Sum256([]byte(token))
    return base64.RawURLEncoding.EncodeToString(h[:])
}

// CompareTokenHash compares a plaintext token against a stored hash.
// Uses constant-time comparison to prevent timing attacks.
func CompareTokenHash(token, hash string) bool {
    computed := HashToken(token)
    return subtle.ConstantTimeCompare([]byte(computed), []byte(hash)) == 1
}
```

---

## 11. Phase 9: Custom Domains

### 11.1 Implementation Strategy

Custom domains integrate with the existing HTTP router:

```go
// In control.go, when handling TUNNEL_REQ with hostname:
func (cp *ControlPlane) handleCustomDomain(req *proto.TunnelReq, session *Session) error {
    // 1. Verify CNAME
    if err := verifyCNAME(req.Hostname, cp.server.config.Domain); err != nil {
        // Try TXT verification
        if err2 := verifyTXT(req.Hostname); err2 != nil {
            return fmt.Errorf("domain verification failed: CNAME: %v, TXT: %v", err, err2)
        }
    }

    // 2. Register route by full hostname
    tunnel := &Tunnel{Hostname: req.Hostname, ...}
    cp.server.router.RegisterHTTP(req.Hostname, tunnel)

    // 3. Request ACME cert (async)
    go cp.server.tls.ObtainCert(req.Hostname)

    return nil
}
```

---

## 12. Phase 10: Dashboard & Inspector

### 12.1 Inspector Architecture

```go
// internal/client/inspector.go
type Inspector struct {
    requests  []*CapturedRequest  // ring buffer (last N)
    maxItems  int
    idx       int
    mu        sync.RWMutex
    
    // SSE subscribers
    subscribers map[string]chan *CapturedRequest
    subMu       sync.RWMutex
}

func (i *Inspector) Capture(req *http.Request, resp *http.Response, duration time.Duration) {
    captured := &CapturedRequest{
        ID:         generateID(),
        Timestamp:  time.Now(),
        Duration:   duration,
        Method:     req.Method,
        URL:        req.URL.String(),
        StatusCode: resp.StatusCode,
        // ... headers, body (capped at 1MB)
    }

    i.mu.Lock()
    i.requests[i.idx%i.maxItems] = captured
    i.idx++
    i.mu.Unlock()

    // Notify SSE subscribers
    i.notify(captured)
}
```

### 12.2 Dashboard UI Approach

Single-file vanilla JS embedded via `go:embed`:

```
dashboard/dist/
├── index.html        # < 500 lines, all-in-one
├── app.js            # < 1000 lines, vanilla JS
└── style.css         # < 300 lines, minimal dark theme
```

No build tools, no npm, no framework. The UI is functional, not fancy. Key views:
- Tunnel list (cards showing URL, type, status)
- Request log (table with live updates via SSE)
- Request detail (expandable panel)
- Replay button (POSTs to `/api/requests/:id/replay`)

---

## 13. Phase 11: CLI

### 13.1 Key Implementation: cli.go

```go
package cli

import (
    "fmt"
    "os"
    "strings"
)

type App struct {
    Name     string
    Version  string
    Commands []*Command
    Flags    []*Flag
}

type Command struct {
    Name  string
    Desc  string
    Usage string
    Run   func(ctx *Context) error
    Sub   []*Command
    Flags []*Flag
}

type Flag struct {
    Name     string
    Short    string // single char
    Desc     string
    Default  string
    Required bool
}

type Context struct {
    Args  []string
    Flags map[string]string
}

func (a *App) Run(args []string) error {
    if len(args) < 2 {
        return a.printHelp()
    }

    cmdName := args[1]
    for _, cmd := range a.Commands {
        if cmd.Name == cmdName {
            ctx, err := parseFlags(args[2:], cmd.Flags)
            if err != nil {
                return err
            }
            return cmd.Run(ctx)
        }
    }

    return fmt.Errorf("unknown command: %s", cmdName)
}
```

---

## 14. Phase 12: Configuration

### 14.1 TOML-Subset Parser

```go
// Supports: strings, integers, booleans, arrays, sections, comments
// Does NOT support: inline tables, datetime, multiline strings, dotted keys

type Value struct {
    Str    string
    Int    int64
    Bool   bool
    Array  []Value
    Type   ValueType
}

type Section struct {
    Name   string
    Values map[string]Value
    Sub    map[string]*Section
}

func Parse(r io.Reader) (*Section, error) {
    // Line-by-line parsing:
    // - Skip empty lines and comments (#)
    // - [section] → push new section
    // - [section.sub] → nested section
    // - key = "string" | key = 123 | key = true | key = ["a", "b"]
}
```

Lines of code estimate: ~250 for a robust parser with error reporting.

---

## 15. Phase 13: Observability

### 15.1 Metrics Implementation

```go
package server

import (
    "fmt"
    "io"
    "sync/atomic"
)

type Metrics struct {
    ActiveSessions  atomic.Int64
    ActiveTunnels   [2]atomic.Int64  // [http, tcp]
    TotalRequests   [5]atomic.Int64  // [1xx, 2xx, 3xx, 4xx, 5xx]
    BytesIn         atomic.Int64
    BytesOut        atomic.Int64
    ConnErrors      [3]atomic.Int64  // [auth, refused, timeout]
}

func (m *Metrics) WritePrometheus(w io.Writer) {
    fmt.Fprintf(w, "# HELP tunnel_active_sessions Active sessions\n")
    fmt.Fprintf(w, "# TYPE tunnel_active_sessions gauge\n")
    fmt.Fprintf(w, "tunnel_active_sessions %d\n\n", m.ActiveSessions.Load())
    // ... etc
}
```

---

## 16. Phase 14: Hardening

### 16.1 Checklist

- [ ] Graceful shutdown: signal handling (SIGTERM, SIGINT), drain connections.
- [ ] Rate limiter integration at edge, control, and per-tunnel levels.
- [ ] Input validation: all user-supplied strings (subdomains, hostnames, headers).
- [ ] Memory limits: max request body, max buffer sizes, max streams.
- [ ] Timeouts: read/write timeouts on all connections.
- [ ] Panic recovery: `defer` recover in all goroutines.
- [ ] Connection draining: finish in-flight requests before shutdown.
- [ ] Log sanitization: no tokens or passwords in logs.
- [ ] Error pages: user-friendly HTML for 502, 503, 504.

### 16.2 Timeouts

```go
// Server-side timeouts
httpServer := &http.Server{
    ReadTimeout:       30 * time.Second,
    ReadHeaderTimeout: 10 * time.Second,
    WriteTimeout:      60 * time.Second,
    IdleTimeout:       120 * time.Second,
    MaxHeaderBytes:    1 << 20, // 1 MB
}

// Control connection timeouts
controlConn.SetDeadline(time.Now().Add(90 * time.Second)) // heartbeat timeout
```

---

## 17. Code Patterns & Conventions

### 17.1 Naming Conventions

```go
// Package names: lowercase, single word
package proto    // not "protocol"
package mux      // not "multiplexer"

// Types: PascalCase, descriptive
type FrameWriter struct {}
type SessionStore struct {}

// Interfaces: verb-based or -er suffix
type Authenticator interface {}
type StreamHandler interface {}

// Functions: action-first
func NewRouter() *Router {}
func (r *Router) RegisterHTTP() {}
func (r *Router) LookupHTTP() {}
func ParseConfig() {}

// Constants: grouped by purpose
const (
    FrameAuthReq byte = 0x01
    FrameAuthRes byte = 0x02
)

// Files: lowercase, underscore for multi-word
edge_http.go    // not edgeHttp.go
frame_test.go   // test companion
```

### 17.2 Context Propagation

```go
// Every long-running function accepts context as first param
func (s *Server) Start(ctx context.Context) error {}
func (a *Agent) Run(ctx context.Context) error {}
func (e *HTTPEdge) ServeHTTP(w http.ResponseWriter, r *http.Request) {
    ctx := r.Context()
    // Use ctx for timeouts and cancellation
}
```

### 17.3 Buffer Pooling

```go
// Global buffer pool for frame encoding/decoding
var bufPool = sync.Pool{
    New: func() any {
        buf := make([]byte, 32*1024) // 32 KB
        return &buf
    },
}

func getBuf() *[]byte { return bufPool.Get().(*[]byte) }
func putBuf(b *[]byte) { bufPool.Put(b) }
```

### 17.4 Goroutine Lifecycle

```go
// Pattern: every goroutine has clear shutdown
func (s *Server) sessionJanitor() {
    defer s.wg.Done()
    ticker := time.NewTicker(10 * time.Second)
    defer ticker.Stop()

    for {
        select {
        case <-ticker.C:
            s.sessions.EvictExpired()
        case <-s.ctx.Done():
            return
        }
    }
}
```

### 17.5 Functional Options (for configs)

```go
// Used sparingly — only for public API
type Option func(*Config)

func WithWindowSize(size int32) Option {
    return func(c *Config) { c.WindowSize = size }
}

func New(conn net.Conn, opts ...Option) *Mux {
    cfg := DefaultConfig()
    for _, opt := range opts {
        opt(&cfg)
    }
    // ...
}
```

---

## 18. Error Handling Strategy

### 18.1 Error Types

```go
// Sentinel errors (for errors.Is)
var (
    ErrStreamClosed   = errors.New("stream closed")
    ErrStreamReset    = errors.New("stream reset")
    ErrBufferFull     = errors.New("buffer full")
    ErrAuthFailed     = errors.New("authentication failed")
    ErrSubdomainTaken = errors.New("subdomain already in use")
    ErrPortUnavail    = errors.New("port unavailable")
)

// Wrapped errors (for errors.As and context)
func (cp *ControlPlane) handleAuth(f *proto.Frame) error {
    msg, err := proto.UnmarshalPayload[proto.AuthReq](f)
    if err != nil {
        return fmt.Errorf("unmarshal auth request: %w", err)
    }
    
    acct, err := cp.auth.Validate(msg.Token)
    if err != nil {
        return fmt.Errorf("%w: %s", ErrAuthFailed, err)
    }
    // ...
}
```

### 18.2 Error Propagation Rules

1. **Protocol errors:** Log + send ERROR frame + close connection.
2. **Tunnel errors:** Log + return HTTP error to public client.
3. **Stream errors:** Log + send STREAM_RST + cleanup stream only (not mux).
4. **Config errors:** Exit with clear message + non-zero exit code.
5. **Internal panics:** Recover, log, attempt graceful degradation.

### 18.3 Panic Recovery

```go
// Wrap every goroutine that handles external input
func safeGo(fn func()) {
    go func() {
        defer func() {
            if r := recover(); r != nil {
                slog.Error("panic recovered",
                    "panic", r,
                    "stack", string(debug.Stack()),
                )
            }
        }()
        fn()
    }()
}
```

---

## 19. Testing Strategy

### 19.1 Test Pyramid

```
           ┌──────────┐
           │  E2E (5) │    Full client-server over network
           ├──────────┤
           │ Integ    │    Component integration (mux+proto, server+client)
           │  (15)    │
           ├──────────┤
           │  Unit    │    Individual functions and types
           │  (50+)   │
           └──────────┘
```

### 19.2 Test Helpers

```go
// testutil.go — shared test utilities

// testPipe creates a connected pair of mux instances
func testPipe(t *testing.T) (*mux.Mux, *mux.Mux) {
    t.Helper()
    sConn, cConn := net.Pipe()
    t.Cleanup(func() { sConn.Close(); cConn.Close() })
    
    server := mux.New(sConn, mux.SideServer, mux.DefaultConfig())
    client := mux.New(cConn, mux.SideClient, mux.DefaultConfig())
    server.Start()
    client.Start()
    return server, client
}

// testHTTPServer starts a local HTTP server for testing
func testHTTPServer(t *testing.T, handler http.Handler) string {
    t.Helper()
    ln, _ := net.Listen("tcp", "127.0.0.1:0")
    t.Cleanup(func() { ln.Close() })
    go http.Serve(ln, handler)
    return ln.Addr().String()
}
```

### 19.3 Benchmark Targets

```go
func BenchmarkFrameEncode(b *testing.B)    {} // < 500ns/op
func BenchmarkFrameRead(b *testing.B)      {} // < 500ns/op
func BenchmarkRingBufWrite(b *testing.B)   {} // < 100ns/op
func BenchmarkMuxThroughput(b *testing.B)  {} // > 1 GB/s loopback
func BenchmarkRouterLookup(b *testing.B)   {} // < 50ns/op
```

---

## 20. Build & Release

### 20.1 Makefile

```makefile
BINARY_CLIENT = wirerift
BINARY_SERVER = wirerift-server
VERSION = $(shell git describe --tags --always --dirty)
LDFLAGS = -s -w -X main.Version=$(VERSION)
GOFLAGS = -trimpath

.PHONY: build test bench clean

build:
	CGO_ENABLED=0 go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o bin/$(BINARY_CLIENT) ./cmd/client
	CGO_ENABLED=0 go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o bin/$(BINARY_SERVER) ./cmd/server

test:
	go test -race -count=1 ./...

bench:
	go test -bench=. -benchmem ./internal/proto/ ./internal/mux/

# Cross-compilation
release:
	GOOS=linux   GOARCH=amd64 go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o dist/$(BINARY_CLIENT)-linux-amd64 ./cmd/client
	GOOS=linux   GOARCH=arm64 go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o dist/$(BINARY_CLIENT)-linux-arm64 ./cmd/client
	GOOS=darwin  GOARCH=amd64 go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o dist/$(BINARY_CLIENT)-darwin-amd64 ./cmd/client
	GOOS=darwin  GOARCH=arm64 go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o dist/$(BINARY_CLIENT)-darwin-arm64 ./cmd/client
	GOOS=windows GOARCH=amd64 go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o dist/$(BINARY_CLIENT)-windows-amd64.exe ./cmd/client
```

### 20.2 Dockerfile

```dockerfile
FROM golang:1.23-alpine AS builder
RUN apk add --no-cache git
WORKDIR /src
COPY go.mod ./
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /wirerift-server ./cmd/server

FROM scratch
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /wirerift-server /wirerift-server
EXPOSE 443 4443 8080
ENTRYPOINT ["/wirerift-server"]
```

Target image size: **~8 MB** (static binary from scratch).

---

## 21. Critical Implementation Recipes

### 21.1 Bidirectional Stream Bridge

The most performance-critical function in the entire project:

```go
func bridgeStreams(a, b io.ReadWriteCloser) {
    done := make(chan struct{}, 2)

    transfer := func(dst io.Writer, src io.Reader) {
        buf := getBuf()
        defer putBuf(buf)
        io.CopyBuffer(dst, src, *buf)
        done <- struct{}{}
    }

    go transfer(a, b)
    go transfer(b, a)

    <-done

    // One direction finished — close both sides
    // to unblock the other goroutine
    a.Close()
    b.Close()

    <-done
}
```

### 21.2 ID Generation

```go
import (
    "crypto/rand"
    "encoding/base32"
    "strings"
)

// generateID creates a short, URL-safe random ID.
// Format: "tun_xxxx" / "sess_xxxx" / "req_xxxx"
func generateID(prefix string) string {
    b := make([]byte, 10) // 80 bits of randomness
    rand.Read(b)
    encoded := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b)
    return prefix + strings.ToLower(encoded)
}
```

### 21.3 Subdomain Extraction

```go
func extractSubdomain(hostname, baseDomain string) string {
    // hostname: "myapp.tunnel.dev:443"
    // baseDomain: "tunnel.dev"
    
    // Strip port
    host := hostname
    if idx := strings.LastIndex(host, ":"); idx != -1 {
        host = host[:idx]
    }
    
    // Strip base domain
    suffix := "." + baseDomain
    if !strings.HasSuffix(host, suffix) {
        return "" // not a subdomain of our base
    }
    
    sub := strings.TrimSuffix(host, suffix)
    // "myapp" or "deep.sub.myapp" — we only care about leftmost
    if idx := strings.LastIndex(sub, "."); idx != -1 {
        sub = sub[idx+1:]
    }
    return sub
}
```

### 21.4 ANSI Terminal Status Display

```go
func (a *Agent) printStatus() {
    // Clear screen and move cursor to top
    fmt.Print("\033[2J\033[H")
    
    // Box drawing
    fmt.Println("┌──────────────────────────────────────────────────────┐")
    fmt.Printf("│  WireRift v%s%s│\n", Version, pad(44-len(Version)))
    fmt.Println("│                                                      │")
    fmt.Printf("│  Session:    %-40s│\n", a.sessionID)
    fmt.Printf("│  Dashboard:  %-40s│\n", "http://127.0.0.1:4040")
    fmt.Println("│                                                      │")
    fmt.Println("│  Tunnel      Public URL                     Local    │")
    fmt.Println("│  ─────────── ───────────────────────────── ────────  │")
    
    for _, t := range a.tunnels {
        fmt.Printf("│  %-10s  %-30s  %-7s │\n",
            t.Config.Type, t.PublicURL, t.Config.LocalAddr)
    }
    
    fmt.Println("│                                                      │")
    fmt.Println("└──────────────────────────────────────────────────────┘")
}
```

### 21.5 Graceful Shutdown

```go
func main() {
    srv := server.New(config)
    if err := srv.Start(); err != nil {
        slog.Error("failed to start", "error", err)
        os.Exit(1)
    }

    // Wait for interrupt
    sigCh := make(chan os.Signal, 1)
    signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
    <-sigCh

    slog.Info("shutting down...")
    ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
    defer cancel()

    if err := srv.Shutdown(ctx); err != nil {
        slog.Error("shutdown error", "error", err)
        os.Exit(1)
    }
}
```

---

> **Next:** Create TASKS.md with granular, executable task items per phase.
