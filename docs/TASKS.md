# WireRift — Task Breakdown

> **Companion to:** SPECIFICATION.md + IMPLEMENTATION.md  
> **Format:** Granular, executable tasks grouped by phase  
> **Convention:** Each task is a single commit-worthy unit of work  
> **Estimates:** S (< 1h), M (1-3h), L (3-6h), XL (6-12h)

---

## Legend

```
[ ] = Not started
[~] = In progress
[x] = Complete
[!] = Blocked
[-] = Skipped / Deferred
```

---

## Phase 0: Project Scaffolding ✅

### 0.1 Repository Setup

- [x] **T-001** (S) Create Go module: `go mod init github.com/wirerift/wirerift`
- [x] **T-002** (S) Create directory structure:
  ```
  cmd/wirerift-server/main.go
  cmd/wirerift/main.go
  internal/proto/
  internal/mux/
  internal/server/
  internal/client/
  internal/auth/
  internal/tls/
  internal/config/
  internal/ratelimit/
  internal/cli/
  dashboard/dist/
  ```
- [x] **T-003** (S) Create placeholder `main.go` files with `package main` and empty `func main()`
- [x] **T-004** (S) Create `Makefile` with targets: `build`, `test`, `bench`, `clean`, `lint`, `release`
- [x] **T-005** (S) Create `.gitignore` (bin/, dist/, *.exe, .env, certs/)
- [x] **T-006** (S) Create `Dockerfile` (multi-stage, scratch-based)
- [x] **T-007** (S) Create `.github/workflows/ci.yml` (build + test + lint on push/PR)
- [x] **T-008** (S) Create `README.md` skeleton (project name TBD, badges, quick start placeholder)
- [x] **T-009** (S) Create `CHANGELOG.md` with `## [Unreleased]` section
- [x] **T-010** (S) Create `LICENSE` file (MIT)
- [x] **T-011** (S) Verify `go.sum` is empty after `go mod tidy` (zero deps confirmation)
- [x] **T-012** (S) Add `internal/version.go` with `var Version = "dev"` (injected via ldflags)

### 0.2 Development Tooling

- [x] **T-013** (S) Configure `golangci-lint` config (`.golangci.yml`) with strict rules
- [x] **T-014** (S) Create `scripts/check-deps.sh` — fails CI if `go.sum` has entries
- [x] **T-015** (S) Create `scripts/test-coverage.sh` — runs tests with coverage, fails if < 70%

---

## Phase 1: Wire Protocol ✅

> **Dependency:** None
> **Output:** `internal/proto/` package — fully tested frame encoding/decoding

### 1.1 Constants & Types

- [x] **T-100** (S) Create `internal/proto/constants.go`:
  - Magic bytes: `0x57 0x52 0x46 0x01` (WRF\x01)
  - Protocol version: `0x01`
  - Header size: `9`
  - Max payload size: `16 MB`
  - Max stream ID: `16,777,215` (3 bytes)
  - Control stream ID: `0`
  - Default window size: `256 KB`
  - All frame type constants (`0x01` through `0xFF`)

### 1.2 Frame Encoding/Decoding

- [x] **T-101** (M) Create `internal/proto/frame.go`:
  - `Frame` struct: Version, Type, StreamID, Payload
  - `Frame.Encode(w io.Writer) error` — writes header + payload
  - `ReadFrame(r io.Reader) (*Frame, error)` — reads header + payload
  - Header buffer pool (`sync.Pool`) to avoid allocs
  - Validation: payload size, stream ID range

- [x] **T-102** (S) Create `FrameReader` wrapper:
  - `NewFrameReader(r io.Reader) *FrameReader`
  - `Read() (*Frame, error)`

- [x] **T-103** (S) Create `FrameWriter` wrapper with mutex:
  - `NewFrameWriter(w io.Writer) *FrameWriter`
  - `Write(f *Frame) error` — thread-safe

### 1.3 Frame Tests

- [x] **T-104** (M) Create `internal/proto/frame_test.go`:
  - Test: Encode → Decode round-trip for each frame type
  - Test: Empty payload (0 bytes)
  - Test: 1-byte payload
  - Test: Large payload (64 KB)
  - Test: Over-max payload (16 MB + 1) — verify error
  - Test: Stream ID = 0 (control stream)
  - Test: Stream ID = MaxStreamID — verify no error
  - Test: Stream ID > MaxStreamID — verify error

- [x] **T-105** (S) Create `internal/proto/frame_bench_test.go`:
  - Benchmark: `Encode` with 1 KB payload (~252 ns/op)
  - Benchmark: `ReadFrame` with 1 KB payload (~229 ns/op)
  - Target: < 500ns/op for 1 KB ✅

### 1.4 Control Messages

- [x] **T-106** (M) Create `internal/proto/messages.go`:
  - `AuthRequest` struct (Token, ClientID, Version, OS, Arch, Hostname)
  - `AuthResponse` struct (OK, SessionID, ServerVersion, HeartbeatInterval, MaxTunnels, MaxStreamsPerTunnel, Error)
  - `TunnelType` (http, tcp)
  - `TunnelAuth` struct (Type, Username, Password)
  - `TunnelRequest` struct (Type, Subdomain, RemotePort, LocalAddr, Inspect, Auth, Headers)
  - `TunnelResponse` struct (OK, TunnelID, Type, PublicURL, Error, Metadata)
  - `TunnelClose` struct (TunnelID)
  - `StreamOpen` struct (TunnelID, StreamID, RemoteAddr, Protocol)
  - `StreamWindow` struct (StreamID, Delta)
  - `GoAway` struct (Reason, Message, ReconnectAfter)
  - `ErrorFrame` struct (Code, Message)

- [x] **T-107** (S) Create marshal/unmarshal helpers:
  - `EncodeJSONPayload(frameType, streamID, v) (*Frame, error)`
  - `DecodeJSONPayload(f *Frame, v any) error`

- [x] **T-108** (S) Create heartbeat helpers:
  - `HeartbeatPayload() []byte` — timestamp = current UnixNano
  - `ParseHeartbeat(payload) time.Time`

- [ ] **T-109** (S) Create window update helpers:
  - `NewWindowUpdateFrame(streamID, increment) *Frame`
  - `WindowIncrement(payload) uint32`

### 1.5 Message Tests

- [ ] **T-110** (M) Create `internal/proto/message_test.go`:
  - Test: MarshalFrame → UnmarshalPayload round-trip for each message type
  - Test: AuthReq with all fields populated
  - Test: AuthReq with optional SessionID empty
  - Test: TunnelReq for HTTP type
  - Test: TunnelReq for TCP type
  - Test: TunnelReq with auth and headers
  - Test: Heartbeat timestamp round-trip (delta < 1ms)
  - Test: WindowIncrement encode/decode
  - Test: Invalid JSON payload → error

### 1.6 Protocol Magic

- [ ] **T-111** (S) Create magic bytes validation helper:
  - `WriteMagic(w io.Writer) error` — writes 4 bytes: T, N, L, Version
  - `ReadMagic(r io.Reader) (version byte, err error)` — reads + validates magic
  - Error on wrong magic bytes
  - Error on unsupported version

- [ ] **T-112** (S) Test magic bytes:
  - Test: Write → Read round-trip
  - Test: Wrong magic → error with descriptive message
  - Test: Wrong version → error with version mismatch info
  - Test: Truncated read → error

---

## Phase 2: Stream Multiplexer ✅

> **Dependency:** Phase 1 (proto)
> **Output:** `internal/mux/` package — multiplexer with flow control

### 2.1 Ring Buffer

- [x] **T-200** (M) Create `internal/mux/ringbuffer.go`:
  - `ringBuffer` struct (buf, size, r, w, full, mu)
  - `newRingBuffer(size int) *ringBuffer`
  - `Write(p []byte) (int, error)` — auto-grows buffer
  - `Read(p []byte) (int, error)` — reads available data
  - `Len() int` — bytes currently buffered
  - `Reset()` — clear buffer
  - Handle wrap-around correctly for both read and write

- [x] **T-201** (M) Create `internal/mux/ringbuffer_test.go`:
  - Test: Write then read — data matches
  - Test: Write wrap-around
  - Test: Buffer grow when needed
  - Test: Empty buffer → Read returns 0
  - Test: Partial reads
  - Test: Concurrent read/write safety
  - Benchmark: Write/Read 1 KB

### 2.2 Stream

- [x] **T-202** (L) Create `internal/mux/stream.go`:
  - Stream states: `streamStateActive`, `streamStateHalfClosedLocal`, `streamStateHalfClosedRemote`, `streamStateClosed`, `streamStateReset`
  - `Stream` struct (id, mux, readBuf, readCh, window, windowCh, state, closeOnce)
  - `newStream(id, mux, windowSize) *Stream`
  - `ID() uint32`
  - `Read(p []byte) (int, error)` — blocks until data, EOF on remote close, error on reset
  - `Write(p []byte) (int, error)` — respects flow control window
  - `Close() error` — initiates half-close
  - `Reset() error` — forceful termination
  - Implements io.ReadWriteCloser

- [x] **T-203** (M) Stream tests integrated in mux_test.go

### 2.3 Multiplexer

- [x] **T-204** (L) Create `internal/mux/mux.go`:
  - `Config` struct (MaxStreams, WindowSize, MaxFrameSize, HeartbeatInterval, HeartbeatTimeout)
  - `DefaultConfig() Config`
  - `DefaultConfig() Config`
  - `Side` type (SideClient, SideServer)
  - `Mux` struct (conn, side, config, writer, streams, nextID, acceptCh, ctx, cancel, closeCh, closeErr, once, callbacks)
  - `New(conn, side, config) *Mux`
  - `Start()` — starts readLoop goroutine
  - `Accept() (*Stream, error)` — blocks until incoming stream
  - `Open() (*Stream, error)` — creates outgoing stream
  - `Close() error` — sends GO_AWAY, resets all streams, closes conn
  - `SendHeartbeat() error`
  - `SendControlFrame(frameType, msg) error`

- [ ] **T-205** (L) Implement `readLoop()` and frame handlers in `mux.go`:
  - `readLoop()` — reads frames, dispatches to handlers, closes mux on error
  - `handleFrame(f *Frame) error` — switch on frame type
  - `handleStreamOpen(f)` — create stream, push to acceptCh
  - `handleStreamData(f)` — find stream, call receiveData
  - `handleStreamClose(f)` — find stream, call remoteClose
  - `handleStreamReset(f)` — find stream, call reset
  - `handleWindowUpdate(f)` — find stream, call addWindow
  - Heartbeat: echo back as HeartbeatAck
  - HeartbeatAck: call onHeartbeat callback with latency
  - GoAway: call onGoAway callback

- [ ] **T-206** (M) Implement send helpers in `mux.go`:
  - `sendData(streamID, data) error`
  - `sendStreamClose(streamID) error`
  - `sendStreamReset(streamID) error`
  - `sendWindowUpdate(streamID, increment)` — best-effort (no error return)
  - `removeStream(id)` — delete from map
  - `allocateID() uint32` — odd for client, even for server

- [ ] **T-207** (S) Add callback setters:
  - `OnHeartbeat(fn func(latencyNanos int64))`
  - `OnGoAway(fn func(GoAway))`
  - `OnStreamOpen(fn func(streamID uint32, payload []byte))`

### 2.4 Mux Tests

- [ ] **T-208** (L) Create `internal/mux/mux_test.go`:
  - Test: Client Open → Server Accept → bidirectional data exchange
  - Test: Server opens stream (STREAM_OPEN) → Client accepts
  - Test: 10 concurrent streams, each exchanging 1 MB of data
  - Test: Flow control — sender blocks when window full, resumes on update
  - Test: Stream close — half-close from client side
  - Test: Stream close — half-close from server side
  - Test: Stream reset — immediate cleanup
  - Test: Heartbeat round-trip — latency callback fires
  - Test: GoAway — callback fires with correct payload
  - Test: Mux.Close() — all streams receive reset, Accept returns error
  - Test: Connection drops (close underlying conn) — mux detects and cleans up
  - Test: Max streams exceeded — STREAM_OPEN returns RST
  - Test: Odd/even stream ID assignment (client=odd, server=even)

- [ ] **T-209** (M) Create `internal/mux/mux_bench_test.go`:
  - Benchmark: Single stream, 1 MB transfer, measure throughput
  - Benchmark: 100 concurrent streams, 64 KB each
  - Benchmark: Stream open/close cycle (latency)
  - Benchmark: Heartbeat round-trip latency
  - Target: > 1 GB/s throughput over net.Pipe, > 100 MB/s with flow control

### 2.5 Integration Test A

- [ ] **T-210** (M) Create `internal/mux/integration_test.go`:
  - Test: Full mux over `net.Pipe()` — client opens stream, writes "Hello", server reads, writes "World", client reads
  - Test: Full mux over real TCP loopback — same as above but with `net.Listen("tcp", "127.0.0.1:0")`
  - Test: 100 streams simultaneously over TCP loopback
  - Test: Large transfer (10 MB) with flow control active
  - Test: One side disconnects abruptly — other side detects within heartbeat timeout

---

## Phase 3: Server Core

> **Dependency:** Phase 1, 2  
> **Output:** Server skeleton that accepts client connections and manages sessions

### 3.1 Router

- [ ] **T-300** (M) Create `internal/server/router.go`:
  - `Router` struct (httpRoutes sync.Map, tcpRoutes sync.Map, reserved map)
  - `NewRouter() *Router` — pre-populate reserved subdomains
  - `RegisterHTTP(subdomain string, tunnel *Tunnel) error` — reject reserved, reject duplicates
  - `RegisterHTTPHostname(hostname string, tunnel *Tunnel) error` — for custom domains
  - `LookupHTTP(hostname string) (*Tunnel, bool)` — extract subdomain, fallback to full hostname
  - `RegisterTCP(port int, tunnel *Tunnel)`
  - `LookupTCP(port int) (*Tunnel, bool)`
  - `Unregister(tunnel *Tunnel)` — remove all routes for a tunnel
  - `extractSubdomain(hostname, baseDomain) string` — strip port, strip base domain

- [ ] **T-301** (S) Create router tests:
  - Test: Register + Lookup HTTP subdomain
  - Test: Register duplicate subdomain → error
  - Test: Register reserved subdomain → error
  - Test: Lookup with port in hostname (strip port)
  - Test: Custom domain registration + lookup
  - Test: Unregister removes all routes
  - Test: Subdomain extraction edge cases
  - Test: TCP register + lookup
  - Benchmark: LookupHTTP with 10,000 routes — target < 100ns

### 3.2 Session Management

- [ ] **T-302** (M) Create `internal/server/session.go`:
  - `SessionState` type (Active, Grace, Closed)
  - `Session` struct (ID, AccountID, Mux, Tunnels, State, CreatedAt, LastSeen, RemoteAddr, GraceDeadline, mu)
  - `SessionStore` struct (sessions sync.Map)
  - `NewSessionStore() *SessionStore`
  - `Create(mux, accountID, remoteAddr) *Session`
  - `Get(sessionID) (*Session, bool)`
  - `Remove(sessionID)`
  - `EnterGrace(sessionID, gracePeriod)` — set state to Grace with deadline
  - `Restore(sessionID, newMux) bool` — restore from grace if within deadline
  - `EvictExpired()` — remove sessions past grace deadline
  - `BroadcastGoAway(reason, message)` — send GO_AWAY to all active sessions
  - `Count() int`
  - `ActiveTunnelCount() (http int, tcp int)`
  - `ForEach(fn func(*Session))` — iterate all sessions

- [ ] **T-303** (S) Create session tests:
  - Test: Create session → Get returns it
  - Test: Remove session → Get returns false
  - Test: Grace period: enter grace → restore within deadline → success
  - Test: Grace period: enter grace → restore after deadline → fail
  - Test: EvictExpired removes only expired sessions
  - Test: BroadcastGoAway sends to all
  - Test: ForEach iterates all sessions
  - Test: Concurrent create/get/remove safety

### 3.3 Tunnel Model

- [ ] **T-304** (S) Create `internal/server/tunnel.go`:
  - `TunnelType` (HTTP, TCP)
  - `Tunnel` struct:
    - ID, Type, Name
    - Subdomain, Hostname (HTTP)
    - RemotePort (TCP)
    - LocalAddr
    - Session *Session
    - Inspect bool
    - Auth *proto.TunnelAuth
    - CustomHeaders map[string]string
    - CreatedAt time.Time
    - BytesIn, BytesOut atomic.Int64
    - Connections atomic.Int64
    - mu sync.RWMutex
  - `NewTunnel(req *proto.TunnelReq, session *Session) *Tunnel`
  - `Stats() TunnelStats` — snapshot of current metrics

### 3.4 Control Plane

- [ ] **T-305** (L) Create `internal/server/control.go`:
  - `ControlPlane` struct (server, listener, tlsConfig)
  - `NewControlPlane(server *Server) *ControlPlane`
  - `Start() error` — listen on control port (TLS)
  - `acceptLoop()` — accept connections, verify magic, create mux
  - `handleConnection(conn net.Conn)`:
    1. Read magic bytes → validate
    2. Create mux (SideServer)
    3. Start mux
    4. Read first frame (expect AUTH_REQ)
    5. Call `handleAuth()`
    6. Enter control loop (read control frames)
  - `handleAuth(mux, frame) (*Session, error)`:
    1. Unmarshal AuthReq
    2. Validate token (or allow anonymous)
    3. Check session restore (if SessionID provided)
    4. Create new session or restore existing
    5. Send AuthRes
  - `handleTunnelReq(session, frame) error`:
    1. Unmarshal TunnelReq
    2. Validate subdomain / port
    3. Create Tunnel
    4. Register routes
    5. For TCP: allocate port
    6. Send TunnelRes
  - `handleTunnelClose(session, frame) error`
  - `controlLoop(session, mux)` — reads control frames in a loop

- [ ] **T-306** (S) Create control plane tests:
  - Test: Accept connection → magic validation → auth → session created
  - Test: Invalid magic → connection closed with error
  - Test: Invalid token → AUTH_RES with ok=false
  - Test: Valid auth → tunnel request → route registered
  - Test: Tunnel close → route unregistered
  - Test: Reconnect with session_id → session restored

### 3.5 Server Orchestrator

- [ ] **T-307** (M) Create `internal/server/server.go`:
  - `Config` struct (ControlAddr, HTTPAddr, HTTPInsecureAddr, DashboardAddr, Domain, TLS, TCP, Auth, Limits, Session, Logging)
  - `Server` struct (config, control, httpEdge, tcpEdge, router, sessions, dashboard, portAlloc, ctx, cancel, wg)
  - `New(config *Config) *Server`
  - `Start() error` — start all components
  - `Shutdown(ctx context.Context) error` — graceful shutdown
  - `sessionJanitor()` — periodic EvictExpired
  - `openStreamForTunnel(tunnel, remoteAddr) (*mux.Stream, error)` — used by edges

- [ ] **T-308** (S) Create server config defaults:
  - Default ports: control=4443, http=443, http-insecure=80, dashboard=8080
  - Default limits: maxSessions=1000, maxTunnelsPerSession=10, maxStreamsPerTunnel=256
  - Default timeouts: heartbeat=30s, heartbeatTimeout=90s, gracePeriod=60s
  - Default TCP port range: 20000-29999

---

## Phase 4: Client Core

> **Dependency:** Phase 1, 2  
> **Output:** Client agent that connects, authenticates, and proxies streams

### 4.1 Agent Controller

- [ ] **T-400** (L) Create `internal/client/agent.go`:
  - `Config` struct (ServerAddr, AuthToken, Tunnels []TunnelConfig, Inspect, InspectAddr, Insecure)
  - `TunnelConfig` struct (Name, Type, LocalAddr, Subdomain, Hostname, RemotePort, Auth, Headers)
  - `Agent` struct (config, muxConn, tunnels, sessionID, inspector, ctx, cancel)
  - `TunnelInfo` struct (Config, ID, PublicURL)
  - `NewAgent(config *Config) *Agent`
  - `Run() error` — calls RunWithReconnect
  - `Stop()` — cancel context
  - `session(conn net.Conn) error`:
    1. Create mux (SideClient)
    2. Authenticate
    3. Request tunnels
    4. Print status
    5. Accept + handle streams loop
  - `authenticate(mux) error` — send AUTH_REQ, wait for AUTH_RES
  - `requestTunnel(mux, config) error` — send TUNNEL_REQ, wait for TUNNEL_RES
  - `handleStream(stream)` — dispatch to HTTP or TCP proxy based on tunnel type

- [ ] **T-401** (S) Create `internal/client/agent_test.go`:
  - Test: Agent connects → authenticates → requests tunnel
  - Test: Agent receives stream → proxies to local
  - Test: Agent handles auth failure gracefully

### 4.2 Reconnection Logic

- [ ] **T-402** (M) Create `internal/client/reconnect.go`:
  - `RunWithReconnect(ctx, addr, insecure, sessionFn) error`
  - `calcBackoff(attempt int) time.Duration`:
    - Initial: 500ms
    - Factor: 2x
    - Max: 30s
    - Reset after 60s stable connection
  - `dialServer(ctx, addr, insecure) (net.Conn, error)`:
    - TLS dial with configurable verification
    - Write magic bytes after connection
    - 10s connect timeout

- [ ] **T-403** (S) Create reconnect tests:
  - Test: calcBackoff values: 500ms, 1s, 2s, 4s, 8s, 16s, 30s, 30s (capped)
  - Test: Backoff resets after stable connection
  - Test: Context cancellation stops reconnect loop
  - Test: Magic bytes written on connect

### 4.3 Local Proxy

- [ ] **T-404** (M) Create `internal/client/proxy.go`:
  - `proxyHTTP(stream, localAddr) error`:
    1. Read HTTP request from stream
    2. Rewrite Host, URL.Scheme, URL.Host
    3. Clear RequestURI
    4. Forward via http.DefaultTransport.RoundTrip
    5. Write response back to stream
    6. On error: write 502 response to stream
  - `proxyTCP(stream, localAddr) error`:
    1. Dial local address
    2. bridgeStreams(stream, localConn)
  - `bridgeStreams(a, b io.ReadWriteCloser)`:
    - Bidirectional io.CopyBuffer with pooled buffers
    - Closes both on first direction finish
  - `writeErrorResponse(stream, statusCode, message)` — write HTTP error response to stream

- [ ] **T-405** (S) Create proxy tests:
  - Test: proxyHTTP — request forwarded to local server, response returned
  - Test: proxyHTTP — local server unreachable → 502 response
  - Test: proxyTCP — bidirectional data exchange
  - Test: bridgeStreams — both sides close when one finishes

### 4.4 Integration Test B

- [ ] **T-406** (L) Create `test/integration_b_test.go`:
  - Test: Start server → start client → client connects and authenticates
  - Test: Client requests HTTP tunnel → server allocates subdomain → URL returned
  - Test: Client requests TCP tunnel → server allocates port → port returned
  - Test: Client disconnect → session enters grace → client reconnects → session restored
  - Test: Client disconnect → grace expires → session removed → client reconnects → new session

---

## Phase 5: HTTP Tunneling

> **Dependency:** Phase 3, 4  
> **Output:** End-to-end HTTP request tunneling

### 5.1 HTTP Edge

- [ ] **T-500** (L) Create `internal/server/edge_http.go`:
  - `HTTPEdge` struct (server, httpServer, listener)
  - `NewHTTPEdge(server *Server) *HTTPEdge`
  - `Start() error` — start HTTP server
  - `Stop(ctx) error` — graceful shutdown
  - `ServeHTTP(w, r)`:
    1. Extract Host → Router lookup
    2. Not found → 502 "Tunnel not found" HTML page
    3. Check tunnel-level auth
    4. Detect WebSocket upgrade → handleWebSocket
    5. Open mux stream (STREAM_OPEN)
    6. Add X-Forwarded-* headers
    7. Write HTTP request to stream (r.Write)
    8. Read HTTP response from stream (http.ReadResponse)
    9. Copy response headers + status + body to w
    10. Update tunnel metrics
  - `handleWebSocket(w, r, tunnel)`:
    1. Hijack HTTP connection
    2. Open mux stream
    3. Forward upgrade request to stream
    4. bridgeStreams(hijackedConn, stream)
  - `addForwardHeaders(r, tunnel)` — X-Forwarded-For, Proto, Host, X-Real-IP
  - `isWebSocketUpgrade(r) bool`
  - `checkTunnelAuth(r, auth) bool` — Basic or Bearer validation

- [ ] **T-501** (S) Create tunnel error pages:
  - `errPageNotFound` — "Tunnel not found" (HTML, minimal styling)
  - `errPageOffline` — "Tunnel is offline" (503)
  - `errPageBadGateway` — "Failed to connect to local service" (502)
  - `errPageUnauthorized` — "Authentication required" (401)
  - Use `html/template` for error pages, embed via `go:embed`

- [ ] **T-502** (S) Create `internal/server/helpers.go`:
  - `openStreamForTunnel(tunnel, remoteAddr) (*mux.Stream, error)` — creates stream via tunnel's session mux
  - `generateRequestID() string` — for X-Tunnel-Request-Id header

### 5.2 Client HTTP Proxy Enhancement

- [ ] **T-503** (M) Enhance `internal/client/proxy.go` for HTTP:
  - Handle request body streaming (don't buffer entire body)
  - Handle chunked transfer encoding
  - Handle HTTP/1.0 vs HTTP/1.1
  - Set appropriate timeouts (connect: 5s, response: 60s)
  - Add X-Tunnel-Session and X-Tunnel-Request-Id headers

### 5.3 HTTP Tests

- [ ] **T-504** (L) Create HTTP tunneling tests:
  - Test: GET request → response matches local server
  - Test: POST request with JSON body → body forwarded correctly
  - Test: Large response body (5 MB) → streamed correctly
  - Test: Response headers preserved (Content-Type, Set-Cookie, etc.)
  - Test: X-Forwarded-For header set correctly
  - Test: WebSocket upgrade → bidirectional message exchange
  - Test: Tunnel auth (basic) → unauthorized without creds, authorized with creds
  - Test: Multiple concurrent HTTP requests through same tunnel
  - Test: Local service returns 500 → 500 forwarded to public client
  - Test: Local service unreachable → 502 returned
  - Test: Tunnel not found → 502 with error page
  - Test: Custom headers from tunnel config applied

---

## Phase 6: TCP Tunneling

> **Dependency:** Phase 3, 4  
> **Output:** Raw TCP port forwarding

### 6.1 Port Allocator

- [ ] **T-600** (M) Create `internal/server/portalloc.go`:
  - `PortAllocator` struct (min, max, used map, mu)
  - `NewPortAllocator(min, max int) *PortAllocator`
  - `Allocate(requested int, tunnel *Tunnel) (int, error)`:
    - requested != 0: try specific port
    - requested == 0: auto-assign first available
    - Verify with `probePort()` before allocation
  - `Release(port int)`
  - `probePort(port int) error` — try net.Listen briefly

- [ ] **T-601** (S) Create port allocator tests:
  - Test: Auto-allocate returns port in range
  - Test: Specific port allocation
  - Test: Specific port already used → error
  - Test: Port outside range → error
  - Test: Release → port available again
  - Test: Exhaust all ports → error

### 6.2 TCP Edge

- [ ] **T-602** (M) Create `internal/server/edge_tcp.go`:
  - `TCPEdge` struct (server, allocator, listeners map, mu)
  - `NewTCPEdge(server *Server) *TCPEdge`
  - `Start() error`
  - `OpenPort(tunnel, requestedPort) (int, error)`:
    1. Allocate port
    2. Start listener
    3. Start accept goroutine
  - `ClosePort(port int)`:
    1. Close listener
    2. Release port
  - `handleTCPConn(conn, tunnel)`:
    1. Open mux stream
    2. bridgeStreams(conn, stream)

- [ ] **T-603** (S) Create TCP edge tests:
  - Test: Open port → accept connection → data flows to tunnel
  - Test: Close port → listener stops
  - Test: Multiple connections to same port → each gets own stream

### 6.3 Integration Test C

- [ ] **T-604** (XL) Create `test/integration_c_test.go`:
  - **Full E2E HTTP test:**
    1. Start local HTTP server (handler echoes request details)
    2. Start tunnel server
    3. Start tunnel client → connects, gets `test.localhost` subdomain
    4. Make HTTP GET to server with Host: test.localhost → verify response
    5. Make HTTP POST with body → verify body forwarded
    6. Test WebSocket upgrade → verify bidirectional
  - **Full E2E TCP test:**
    1. Start local TCP echo server
    2. Start tunnel client → gets TCP port
    3. Connect to TCP port → send data → verify echo
  - **Multi-tunnel test:**
    1. Client with 2 HTTP tunnels + 1 TCP tunnel
    2. All three work simultaneously
  - **Concurrent load test:**
    1. 50 concurrent HTTP requests through tunnel
    2. All complete successfully with correct responses

---

## Phase 7: TLS & Certificates

> **Dependency:** Phase 3  
> **Output:** TLS termination with self-signed, manual, and ACME modes

### 7.1 Certificate Manager

- [ ] **T-700** (M) Create `internal/tls/manager.go`:
  - `Mode` type (ModeAuto, ModeManual, ModeSelfSigned)
  - `Manager` struct (mode, certDir, acmeClient, certs sync.Map, mu)
  - `NewManager(mode, certDir, acmeEmail) *Manager`
  - `GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error)` — SNI-based lookup
  - `LoadOrObtain(hostname) (*tls.Certificate, error)` — load from disk or obtain new
  - `TLSConfig() *tls.Config` — returns tls.Config with GetCertificate wired
  - `StartRenewalLoop(ctx)` — check certs every 12h, renew if < 30 days

- [ ] **T-701** (S) Create `internal/tls/manager_test.go`:
  - Test: GetCertificate returns correct cert for SNI hostname
  - Test: Multiple hostnames, each gets its own cert
  - Test: Fallback to default cert when SNI unknown

### 7.2 Self-Signed Certificates

- [ ] **T-702** (M) Create `internal/tls/selfsigned.go`:
  - `GenerateSelfSigned(hosts []string, validDays int) (*tls.Certificate, error)`:
    - ECDSA P-256 key generation
    - x509 certificate template (serial, subject, validity, key usage, ext key usage)
    - DNS names and IP SANs
    - Self-sign with x509.CreateCertificate
    - PEM encode cert + key
    - Return tls.X509KeyPair
  - `SaveToFiles(cert *tls.Certificate, certPath, keyPath) error`
  - `LoadFromFiles(certPath, keyPath) (*tls.Certificate, error)`

- [ ] **T-703** (S) Create self-signed tests:
  - Test: Generate cert → load → TLS handshake succeeds
  - Test: Generated cert has correct DNS names
  - Test: Generated cert has correct validity period
  - Test: SaveToFiles → LoadFromFiles round-trip

### 7.3 ACME Client

- [ ] **T-704** (XL) Create `internal/tls/acme.go`:
  - `ACMEClient` struct (directoryURL, accountKey, httpClient, nonces, mu)
  - `NewACMEClient(directoryURL, accountKeyPath) (*ACMEClient, error)`
  - `ObtainCertificate(domain string) (*tls.Certificate, error)`:
    1. `getDirectory()` — fetch ACME directory JSON
    2. `newAccount()` — register or retrieve account
    3. `newOrder(domain)` — create order
    4. `getAuthorizations(order)` — get challenges
    5. `solveHTTP01(challenge)` — serve token, notify ACME server
    6. `waitForValid(authURL)` — poll until valid
    7. `finalizeOrder(orderURL, csr)` — submit CSR
    8. `downloadCertificate(certURL)` — download PEM chain
  - JWS signing helpers:
    - `base64url(data []byte) string` — base64.RawURLEncoding
    - `jwsSign(url, payload, nonce) ([]byte, error)` — ECDSA P-256
    - `signedPost(url, payload) (*http.Response, error)`
  - `getNonce() (string, error)` — HEAD to newNonce URL
  - CSR generation using `crypto/x509` + `crypto/ecdsa`

- [ ] **T-705** (M) Create HTTP-01 challenge server:
  - `ChallengeServer` struct — temporary HTTP handler
  - `Serve(token, keyAuth)` — starts serving `/.well-known/acme-challenge/<token>`
  - `Stop()` — stops the challenge server
  - Integrate with server's port 80 listener

- [ ] **T-706** (M) Create ACME tests (using Pebble or mock):
  - Test: Account registration
  - Test: JWS signing produces valid ECDSA signature
  - Test: HTTP-01 challenge serve and cleanup
  - Test: Full flow with mock ACME server (end-to-end)
  - Test: Certificate renewal check logic

### 7.4 Integration Test D

- [ ] **T-707** (L) Create `test/integration_d_test.go`:
  - Test: Server with self-signed TLS → client connects with InsecureSkipVerify
  - Test: Server with manual cert → client connects with CA
  - Test: Auth failure with TLS → proper error response (not crash)
  - Test: Multiple tunnels over single TLS connection

---

## Phase 8: Authentication

> **Dependency:** Phase 3  
> **Output:** Token-based auth with file store

### 8.1 Token Management

- [ ] **T-800** (S) Create `internal/auth/token.go`:
  - `GenerateToken() (string, error)` — `tk_` + 32 random bytes base64url
  - `HashToken(token string) string` — SHA-256 base64url
  - `CompareTokenHash(token, hash string) bool` — constant-time compare
  - `ValidateTokenFormat(token string) error` — check prefix, length, charset

- [ ] **T-801** (S) Create token tests:
  - Test: GenerateToken format matches `^tk_[A-Za-z0-9_-]{43}$`
  - Test: Two generated tokens are different (randomness)
  - Test: HashToken is deterministic (same input → same hash)
  - Test: CompareTokenHash succeeds for matching token
  - Test: CompareTokenHash fails for wrong token
  - Test: ValidateTokenFormat accepts valid tokens
  - Test: ValidateTokenFormat rejects invalid tokens

### 8.2 Auth Store

- [ ] **T-802** (M) Create `internal/auth/store.go`:
  - `Account` struct (ID, Name, TokenHash, MaxTunnels, AllowedSubdomains, CreatedAt)
  - `FileStore` struct (path, accounts []Account, mu)
  - `NewFileStore(path string) (*FileStore, error)` — load JSON file
  - `Validate(token string) (*Account, error)` — hash token, find matching account
  - `CreateAccount(name string, maxTunnels int) (account *Account, plainToken string, error)`:
    1. Generate token
    2. Hash token
    3. Create account record
    4. Save to file
    5. Return account + plaintext token (displayed once)
  - `RevokeToken(tokenPrefix string) error` — find by prefix, remove
  - `ListAccounts() []Account`
  - `Save() error` — write JSON to file (atomic via temp file + rename)
  - `Load() error` — read JSON from file

- [ ] **T-803** (S) Create auth store tests:
  - Test: CreateAccount → Validate with returned token → success
  - Test: Validate with wrong token → error
  - Test: RevokeToken → Validate fails
  - Test: ListAccounts returns all
  - Test: Save → Load persists data
  - Test: File doesn't exist → create empty store
  - Test: Concurrent Validate calls (thread safety)
  - Test: AllowedSubdomains pattern matching

### 8.3 Anonymous Mode

- [ ] **T-804** (S) Implement anonymous tunnel support:
  - If `auth.allow_anonymous = true`:
    - Accept connections without token
    - Limit: 1 tunnel per IP
    - Random subdomain only
    - Rate limit: 10 req/s
    - TTL: 2 hours
  - Track anonymous sessions by IP

- [ ] **T-805** (S) Anonymous mode tests:
  - Test: Anonymous connection → tunnel created with random subdomain
  - Test: Second anonymous from same IP → rejected
  - Test: Anonymous tunnel expires after TTL

---

## Phase 9: Custom Domains

> **Dependency:** Phase 5, 7  
> **Output:** CNAME-verified custom domain tunnels

### 9.1 DNS Verification

- [ ] **T-900** (M) Create `internal/server/customdomain.go`:
  - `verifyCNAME(hostname, expectedTarget string) error`:
    - `net.LookupCNAME(hostname)`
    - Check suffix matches expected target
  - `verifyTXT(hostname string) (bool, error)`:
    - `net.LookupTXT("_tunnel-verify." + hostname)`
    - Check for valid verification token
  - `generateVerificationToken() string` — `v_` + random
  - `VerifyDomain(hostname, baseDomain string) error` — try CNAME, fall back to TXT

- [ ] **T-901** (S) Create custom domain tests:
  - Test: CNAME verification with valid CNAME (mock DNS)
  - Test: CNAME verification with wrong target → error
  - Test: TXT verification with valid record
  - Test: TXT verification missing → error
  - Test: Domain without any verification → error

### 9.2 Custom Domain in Tunnel Flow

- [ ] **T-902** (M) Integrate custom domains into control plane:
  - In `handleTunnelReq`: if `hostname` is set:
    1. Call `VerifyDomain`
    2. Register route by hostname (not subdomain)
    3. Trigger async ACME cert obtainment
    4. Return public URL with custom hostname
  - In router: `LookupHTTP` checks full hostname after subdomain miss

- [ ] **T-903** (S) Custom domain integration test:
  - Test: Request tunnel with hostname → domain verified → route registered
  - Test: HTTP request with Host: custom-domain → reaches tunnel
  - Test: TLS cert obtained for custom domain (mock ACME)

---

## Phase 10: Dashboard & Traffic Inspection

> **Dependency:** Phase 5  
> **Output:** Client-side web dashboard + request inspection

### 10.1 Inspector

- [ ] **T-1000** (M) Create `internal/client/inspector.go`:
  - `CapturedRequest` struct (ID, TunnelID, Timestamp, Duration, RemoteAddr, Method, URL, Proto, ReqHeaders, ReqBodySize, ReqBody, StatusCode, ResHeaders, ResBodySize, ResBody)
  - `Inspector` struct (requests ring, maxItems, idx, mu, subscribers, subMu)
  - `NewInspector(maxItems int) *Inspector`
  - `Capture(req, resp, duration)` — store + notify subscribers
  - `List(offset, limit) []*CapturedRequest`
  - `Get(id) (*CapturedRequest, bool)`
  - `Subscribe(id string) chan *CapturedRequest`
  - `Unsubscribe(id string)`
  - Body capture: max 1 MB, truncate with flag

- [ ] **T-1001** (S) Create inspector tests:
  - Test: Capture → List returns it
  - Test: Capture > maxItems → oldest dropped (ring buffer)
  - Test: Get by ID → correct request
  - Test: Subscribe receives new captures via channel
  - Test: Body truncation at 1 MB

### 10.2 Client Dashboard API

- [ ] **T-1002** (M) Create `internal/client/dashboard.go`:
  - `Dashboard` struct (agent, inspector, mux *http.ServeMux)
  - `NewDashboard(agent, inspector) *Dashboard`
  - `Start(addr string) error`
  - Endpoints:
    - `GET /api/status` → agent status, connection info
    - `GET /api/tunnels` → list tunnels with URLs and stats
    - `GET /api/requests` → list captured requests (pagination: ?offset=&limit=)
    - `GET /api/requests/:id` → single request detail
    - `POST /api/requests/:id/replay` → re-send request to local service
    - `GET /api/requests/stream` → SSE stream of new requests

- [ ] **T-1003** (S) Create dashboard API tests:
  - Test: GET /api/status returns valid JSON
  - Test: GET /api/tunnels lists active tunnels
  - Test: GET /api/requests returns captured requests
  - Test: GET /api/requests/:id returns specific request
  - Test: POST /api/requests/:id/replay triggers local request
  - Test: SSE stream delivers new captures

### 10.3 Dashboard Web UI

- [ ] **T-1004** (L) Create `dashboard/dist/index.html`:
  - Single-file HTML with embedded CSS + JS
  - Dark theme (background: #1a1a2e, accent: #16c784)
  - Layout: sidebar (tunnel list) + main area (request log)
  - Auto-refresh via SSE connection to `/api/requests/stream`

- [ ] **T-1005** (M) Create `dashboard/dist/app.js`:
  - Vanilla JS, no framework
  - `fetchStatus()` — poll /api/status every 5s
  - `fetchTunnels()` — display tunnel cards
  - `connectSSE()` — live request stream
  - `renderRequestList(requests)` — table with sortable columns
  - `renderRequestDetail(request)` — expandable panel (headers, body, timing)
  - `replayRequest(id)` — POST to /api/requests/:id/replay
  - JSON body pretty-printing
  - Copy curl command button

- [ ] **T-1006** (S) Create `dashboard/dist/style.css`:
  - Dark theme variables
  - Table styling (striped rows, hover effect)
  - Status badge colors (2xx green, 4xx yellow, 5xx red)
  - Responsive layout
  - Monospace font for headers/body display

- [ ] **T-1007** (S) Embed dashboard in binary:
  - Add `//go:embed dashboard/dist/*` in dashboard.go
  - Serve embedded FS via http.FileServer
  - Fallback to /index.html for SPA-like routing

### 10.4 Server Admin API

- [ ] **T-1008** (M) Create `internal/server/dashboard.go`:
  - `Dashboard` struct (server, mux *http.ServeMux)
  - `Start(addr string) error`
  - Endpoints:
    - `GET /api/v1/status` → server health, uptime, version
    - `GET /api/v1/sessions` → list active sessions
    - `GET /api/v1/sessions/:id` → session detail
    - `DELETE /api/v1/sessions/:id` → force disconnect
    - `GET /api/v1/tunnels` → list active tunnels
    - `GET /api/v1/tunnels/:id` → tunnel detail + stats
    - `DELETE /api/v1/tunnels/:id` → close tunnel
    - `GET /api/v1/metrics` → Prometheus format
  - Admin auth: API key in Authorization header

- [ ] **T-1009** (S) Create server dashboard tests:
  - Test: GET /api/v1/status returns valid JSON with uptime
  - Test: GET /api/v1/sessions lists sessions
  - Test: DELETE /api/v1/sessions/:id disconnects session
  - Test: Unauthorized request → 401

### 10.5 Replay Feature

- [ ] **T-1010** (M) Implement request replay:
  - `Replay(captured *CapturedRequest) (*CapturedRequest, error)`:
    1. Reconstruct http.Request from captured data
    2. Send to local service
    3. Capture response
    4. Return new CapturedRequest with replay flag
  - Support modified replay (change headers, body, method via POST body)

---

## Phase 11: CLI

> **Dependency:** Phase 4, 7, 8  
> **Output:** Client and server CLI interfaces

### 11.1 CLI Framework

- [ ] **T-1100** (M) Create `internal/cli/cli.go`:
  - `App` struct (Name, Version, Commands, Flags)
  - `Command` struct (Name, Desc, Usage, Run, Sub, Flags)
  - `Flag` struct (Name, Short, Desc, Default, Required)
  - `Context` struct (Args, Flags)
  - `App.Run(args []string) error`
  - `parseFlags(args, flags) (*Context, error)`:
    - Parse `--flag value`, `--flag=value`, `-f value`
    - Support boolean flags (presence = true)
    - Collect positional args
  - `App.printHelp()` — auto-generated help text
  - `Command.printHelp()` — command-specific help

- [ ] **T-1101** (S) Create `internal/cli/help.go`:
  - Format help text with aligned columns
  - Command listing with descriptions
  - Flag listing with defaults
  - Usage examples

- [ ] **T-1102** (M) Create `internal/cli/cli_test.go`:
  - Test: Parse long flag `--name value`
  - Test: Parse long flag `--name=value`
  - Test: Parse short flag `-n value`
  - Test: Boolean flag (presence only)
  - Test: Positional args collected correctly
  - Test: Required flag missing → error
  - Test: Default values applied
  - Test: Unknown flag → error
  - Test: Sub-command dispatch
  - Test: Help text generation

### 11.2 Client CLI

- [ ] **T-1103** (M) Create `cmd/client/main.go`:
  - Commands:
    - `http <port>` — start HTTP tunnel (shorthand)
    - `tcp <port>` — start TCP tunnel (shorthand)
    - `start [name]` — start from config file
    - `authtoken <token>` — save token to config
    - `status` — show active tunnels (connects to local dashboard API)
    - `version` — show version info
  - Global flags:
    - `--server` — server address
    - `--auth-token` — override token
    - `--config` — config file path
    - `--log-level` — debug/info/warn/error
    - `--inspect` / `--no-inspect` — enable/disable inspector
    - `--inspect-addr` — inspector listen address

- [ ] **T-1104** (S) Implement `http` command:
  - Parse port from positional arg
  - Optional flags: `--subdomain`, `--basic-auth user:pass`, `--host-header`
  - Create agent config with single HTTP tunnel
  - Run agent

- [ ] **T-1105** (S) Implement `tcp` command:
  - Parse port from positional arg
  - Optional flag: `--remote-port`
  - Create agent config with single TCP tunnel
  - Run agent

- [ ] **T-1106** (S) Implement `start` command:
  - Load config file
  - Optionally filter to named tunnel
  - Run agent

- [ ] **T-1107** (S) Implement `authtoken` command:
  - Save token to config file (~/.config/wirerift/config.toml)
  - Create config dir if not exists
  - Print confirmation

### 11.3 Server CLI

- [ ] **T-1108** (M) Create `cmd/server/main.go`:
  - Commands:
    - `start` — start server
    - `token create --name <name> [--max-tunnels N]` — create auth token
    - `token list` — list accounts
    - `token revoke <token-prefix>` — revoke token
    - `status` — show server status (connects to dashboard API)
    - `version` — show version info
  - Global flags:
    - `--config` — config file path
    - `--log-level`

- [ ] **T-1109** (S) Implement `token create`:
  - Create account via auth store
  - Print token (shown once, warn user to save)
  - Print account ID

- [ ] **T-1110** (S) Implement `token list`:
  - List all accounts (ID, name, max tunnels, created at)
  - Tabular output

- [ ] **T-1111** (S) Implement `token revoke`:
  - Find by token prefix
  - Confirm before revoking
  - Remove from store

### 11.4 Terminal Status Display

- [ ] **T-1112** (M) Create `internal/client/terminal.go`:
  - `printStatus(tunnels []TunnelInfo, sessionID string)`:
    - Box-drawing characters for border
    - Table with tunnel info (type, URL, local addr)
    - Connection stats (connections, bytes in/out)
  - `updateStats(stats)` — ANSI escape codes to overwrite stats line
  - Color support detection (check TERM env var)
  - Fallback to plain text if not TTY

---

## Phase 12: Configuration

> **Dependency:** None (standalone)  
> **Output:** TOML-subset parser + config structs

### 12.1 TOML Parser

- [ ] **T-1200** (L) Create `internal/config/parser.go`:
  - `Value` struct (Str, Int, Bool, Array, Type)
  - `ValueType` (TypeString, TypeInt, TypeBool, TypeArray)
  - `Section` struct (Name, Values, Sub)
  - `Parse(r io.Reader) (*Section, error)`:
    - Line-by-line parsing
    - Skip blank lines and `#` comments
    - `[section]` → create section
    - `[section.sub]` → nested section
    - `key = "string"` → string value (handle escape chars: `\"`, `\\`, `\n`, `\t`)
    - `key = 123` → integer value
    - `key = true` / `key = false` → boolean value
    - `key = ["a", "b"]` → array value
    - Error reporting with line numbers

- [ ] **T-1201** (M) Create `internal/config/parser_test.go`:
  - Test: Parse string values (with and without quotes)
  - Test: Parse integer values (positive, negative, zero)
  - Test: Parse boolean values
  - Test: Parse arrays of strings
  - Test: Parse arrays of integers
  - Test: Parse sections
  - Test: Parse nested sections `[a.b]`
  - Test: Comments are ignored
  - Test: Blank lines are ignored
  - Test: Escaped characters in strings
  - Test: Unterminated string → error with line number
  - Test: Invalid value → error with line number
  - Test: Duplicate key → error
  - Test: Empty file → empty root section
  - Test: Full config file round-trip (real server config)
  - Test: Full config file round-trip (real client config)

### 12.2 Server Config

- [ ] **T-1202** (M) Create `internal/config/server.go`:
  - `ServerConfig` struct (all fields from SPECIFICATION.md §14.2)
  - `LoadServerConfig(path string) (*ServerConfig, error)`:
    1. Parse TOML file
    2. Map sections to struct fields
    3. Apply defaults for missing values
    4. Validate (required fields, port ranges, etc.)
  - `DefaultServerConfig() *ServerConfig`
  - `ApplyEnvOverrides(config *ServerConfig)` — read TUNNEL_* env vars

- [ ] **T-1203** (S) Server config tests:
  - Test: Load full config → all values populated
  - Test: Load minimal config → defaults applied
  - Test: Env override takes precedence
  - Test: Invalid port range → error
  - Test: Missing required field → error

### 12.3 Client Config

- [ ] **T-1204** (M) Create `internal/config/client.go`:
  - `ClientConfig` struct (all fields from SPECIFICATION.md §14.3)
  - `LoadClientConfig(path string) (*ClientConfig, error)`
  - `DefaultClientConfig() *ClientConfig`
  - `FindConfigFile() string` — search order: flag, ./.wirerift.toml, ~/.config/wirerift/config.toml
  - `SaveAuthToken(token string) error` — write/update config file

- [ ] **T-1205** (S) Client config tests:
  - Test: Load config with single tunnel
  - Test: Load config with multiple tunnels
  - Test: Tunnel auth parsing
  - Test: Custom headers parsing
  - Test: Config file search order
  - Test: SaveAuthToken creates/updates file

### 12.4 Environment Variable Overlay

- [ ] **T-1206** (S) Create `internal/config/env.go`:
  - `applyEnv(config any, prefix string)` — reflection-based env overlay
  - Pattern: `TUNNEL_` + section + `_` + field (uppercased, dots → underscores)
  - Example: `TUNNEL_SERVER_CONTROL_ADDR` → server.control_addr
  - Support: string, int, bool, duration

---

## Phase 13: Observability

> **Dependency:** Phase 3  
> **Output:** Structured logging + Prometheus metrics + health checks

### 13.1 Structured Logging

- [ ] **T-1300** (S) Configure `log/slog` throughout the codebase:
  - Set up default logger based on config (level, format)
  - JSON format for production
  - Text format for development
  - Add consistent attributes: component, session_id, tunnel_id
  - Ensure no sensitive data in logs (tokens, passwords)

- [ ] **T-1301** (S) Create log helper for request logging:
  - Log each tunneled request: method, path, status, duration, bytes
  - Debug level: full headers
  - Info level: summary only

### 13.2 Prometheus Metrics

- [ ] **T-1302** (M) Create `internal/server/metrics.go`:
  - `Metrics` struct with atomic counters
  - Gauge metrics: active_sessions, active_tunnels{type}
  - Counter metrics: requests_total{status_class}, bytes_transferred{direction}, connection_errors{type}
  - Histogram metrics: stream_duration_seconds (buckets: 0.1, 0.5, 1, 5, 10, 30, +Inf)
  - `WritePrometheus(w io.Writer)` — format as Prometheus text exposition
  - Integrate metric updates into request flow

- [ ] **T-1303** (S) Metrics tests:
  - Test: Increment counters → correct Prometheus output
  - Test: Histogram bucket distribution
  - Test: Concurrent metric updates (thread safety)

### 13.3 Health Checks

- [ ] **T-1304** (S) Add health endpoints to server dashboard:
  - `GET /health` → 200 always (liveness)
  - `GET /health/ready` → 200 if accepting connections, 503 if shutting down
  - Include uptime, version, go version in response body

---

## Phase 14: Hardening

> **Dependency:** All previous phases  
> **Output:** Production-ready reliability and security

### 14.1 Graceful Shutdown

- [ ] **T-1400** (M) Implement signal handling in both binaries:
  - Catch SIGINT, SIGTERM
  - Server: send GO_AWAY to all clients → drain connections → close listeners
  - Client: close mux gracefully → close local connections
  - Configurable shutdown timeout (default 30s)
  - Force exit on second signal

### 14.2 Rate Limiting

- [ ] **T-1401** (M) Create `internal/ratelimit/bucket.go`:
  - `TokenBucket` struct (tokens, maxTokens, refillRate, lastRefill, mu)
  - `NewTokenBucket(maxTokens float64, refillRate float64) *TokenBucket`
  - `Allow() bool` — consume 1 token, return false if empty
  - `AllowN(n int) bool` — consume N tokens

- [ ] **T-1402** (S) Create rate limiter tests:
  - Test: Burst up to maxTokens
  - Test: Refill over time
  - Test: AllowN with various N values
  - Test: Concurrent Allow calls

- [ ] **T-1403** (M) Integrate rate limiting:
  - Per-tunnel rate limiter (HTTP requests/s)
  - Per-account rate limiter (tunnel creation/s)
  - Per-IP rate limiter (connections/s) — for anonymous mode
  - Global rate limiter (total connections/s)
  - Return 429 Too Many Requests when exceeded

### 14.3 Input Validation

- [ ] **T-1404** (M) Create validation helpers:
  - `ValidateSubdomain(s string) error` — regex: `^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`
  - `ValidateHostname(h string) error` — RFC 1123
  - `ValidatePort(p int) error` — 1-65535
  - `ValidateToken(t string) error` — format check
  - `SanitizeHeaders(h http.Header)` — remove hop-by-hop headers
  - Apply validation at all input boundaries (CLI, control plane, config)

### 14.4 Timeouts

- [ ] **T-1405** (M) Configure timeouts throughout:
  - HTTP server: ReadTimeout=30s, ReadHeaderTimeout=10s, WriteTimeout=60s, IdleTimeout=120s
  - Control connection: deadline based on heartbeat timeout (90s)
  - Local proxy dial timeout: 5s
  - Local proxy response timeout: 60s
  - Mux stream idle timeout: 120s
  - ACME operations timeout: 60s

### 14.5 Panic Recovery

- [ ] **T-1406** (S) Add panic recovery to all goroutines:
  - `safeGo(fn func())` helper — defer recover, log stack trace
  - Wrap: stream handlers, accept loops, janitor, heartbeat
  - Ensure panics don't crash the entire server/client

### 14.6 Error Pages

- [ ] **T-1407** (S) Create user-friendly HTML error pages:
  - 502 "Tunnel Not Found" — subdomain doesn't exist
  - 502 "Bad Gateway" — local service unreachable
  - 503 "Tunnel Offline" — client disconnected (grace period)
  - 504 "Gateway Timeout" — local service timed out
  - 429 "Rate Limited" — too many requests
  - Embed via `go:embed`, minimal styled HTML

### 14.7 Connection Draining

- [ ] **T-1408** (M) Implement connection draining on shutdown:
  - Stop accepting new connections
  - Wait for in-flight streams to complete (up to timeout)
  - Force-close remaining streams after timeout
  - Track in-flight streams with WaitGroup

### 14.8 Security Hardening

- [ ] **T-1409** (S) Add security headers to HTTP edge:
  - `Strict-Transport-Security` (for HTTPS)
  - `X-Content-Type-Options: nosniff`
  - `X-Frame-Options: DENY` (for error pages)
  - Don't leak server version in headers

- [ ] **T-1410** (S) Sanitize log output:
  - Never log auth tokens (mask to `tk_****...`)
  - Never log passwords
  - Redact sensitive headers (Authorization, Cookie)

### 14.9 Full System Test

- [ ] **T-1411** (XL) Create `test/system_test.go`:
  - Test: Complete lifecycle: start server → create token → start client → HTTP tunnel → TCP tunnel → request inspection → replay → disconnect → reconnect → graceful shutdown
  - Test: 100 concurrent HTTP clients, each making 10 requests through tunnel
  - Test: Large file transfer through tunnel (50 MB)
  - Test: WebSocket tunnel with 1000 messages
  - Test: Server restart with client reconnection
  - Test: Rate limiting kicks in at threshold
  - Test: Custom domain with TLS
  - Test: Anonymous tunnel creation and expiry
  - Test: Dashboard API returns correct data during load test

---

## Summary

| Phase | Tasks | Estimated Total |
|-------|-------|----------------|
| 0. Scaffolding | 15 | ~3h |
| 1. Wire Protocol | 13 | ~6h |
| 2. Multiplexer | 11 | ~14h |
| 3. Server Core | 9 | ~8h |
| 4. Client Core | 7 | ~8h |
| 5. HTTP Tunneling | 5 | ~10h |
| 6. TCP Tunneling | 5 | ~5h |
| 7. TLS & Certs | 7 | ~16h |
| 8. Authentication | 6 | ~4h |
| 9. Custom Domains | 4 | ~4h |
| 10. Dashboard | 11 | ~14h |
| 11. CLI | 13 | ~10h |
| 12. Configuration | 7 | ~8h |
| 13. Observability | 5 | ~4h |
| 14. Hardening | 12 | ~14h |
| **Total** | **130** | **~128h** |

---

## Execution Notes

### Parallel Work Opportunities

The following tasks can be worked on in parallel:

- **Track A (Core):** Phase 1 → Phase 2 → Phase 3 → Phase 5 → Phase 6
- **Track B (Support):** Phase 12 (Config) + Phase 11 (CLI) — independent of core
- **Track C (Security):** Phase 7 (TLS) + Phase 8 (Auth) — after Phase 3
- **Track D (UX):** Phase 10 (Dashboard) — after Phase 5

### Definition of Done

Each task is complete when:
1. Code is written and compiles (`go build ./...`)
2. Tests pass (`go test ./...`)
3. No lint errors (`golangci-lint run`)
4. Zero external dependencies verified (`go mod tidy && test -z "$(cat go.sum)"`)
5. Committed with descriptive message following conventional commits

### Claude Code Workflow

For implementation with Claude Code, each phase should be:
1. Give Claude Code the SPECIFICATION.md + IMPLEMENTATION.md as context
2. Reference specific task IDs (e.g., "Implement T-101 through T-105")
3. After each phase: run `go test ./...` and verify zero deps
4. Run integration test before proceeding to next phase
