# WireRift — Technical Specification

> **Project:** WireRift  
> **Tagline:** Tear a rift through the wire. Expose localhost to the world.  
> **Version:** 1.0.0-draft  
> **Status:** Design Phase  
> **Language:** Go 1.23+  
> **Dependencies:** Zero (stdlib only)  
> **License:** MIT  
> **Repository:** github.com/wirerift/wirerift  
> **Domain:** wirerift.com

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Problem Statement](#2-problem-statement)
3. [Architecture Overview](#3-architecture-overview)
4. [Wire Protocol](#4-wire-protocol)
5. [Stream Multiplexer](#5-stream-multiplexer)
6. [Server (Edge) Architecture](#6-server-edge-architecture)
7. [Client (Agent) Architecture](#7-client-agent-architecture)
8. [HTTP Tunneling](#8-http-tunneling)
9. [TCP Tunneling](#9-tcp-tunneling)
10. [TLS & Certificate Management](#10-tls--certificate-management)
11. [Authentication & Authorization](#11-authentication--authorization)
12. [Custom Domains](#12-custom-domains)
13. [Dashboard & Traffic Inspection](#13-dashboard--traffic-inspection)
14. [Configuration](#14-configuration)
15. [CLI Design](#15-cli-design)
16. [Observability](#16-observability)
17. [Security Model](#17-security-model)
18. [Performance Targets](#18-performance-targets)
19. [Project Structure](#19-project-structure)
20. [Version Roadmap](#20-version-roadmap)
21. [Open Questions](#21-open-questions)

---

## 1. Executive Summary

This project is a self-hosted, open-source tunnel solution written entirely in Go with **zero external dependencies**. It exposes local services (HTTP, TCP, WebSocket) to the public internet through a relay server, similar to ngrok, but fully self-hostable and transparent.

### Core Value Propositions

- **Zero dependency:** Single static binary for both client and server. No CGO, no vendor folder, empty `go.sum`.
- **Self-hosted first:** Run your own tunnel infrastructure on any cloud provider or bare metal.
- **Production-grade:** TLS termination, custom domains, authentication, rate limiting, traffic inspection.
- **Developer-friendly:** Instant setup, intuitive CLI, built-in web dashboard for request inspection.
- **Extensible:** Middleware chain architecture for request/response transformation.

### What This Is NOT

- Not a VPN (no IP-level tunneling, no tun/tap devices)
- Not a service mesh (no service discovery, no load balancing between services)
- Not a CDN (no caching, no edge compute)

---

## 2. Problem Statement

Developers frequently need to expose local services to the internet for:

- Webhook development (Stripe, GitHub, Slack callbacks)
- Mobile app development (testing against local API)
- Demoing work to remote stakeholders
- IoT device communication testing
- CI/CD pipeline callback testing

Existing solutions either:
- Are SaaS-only with usage limits and pricing tiers (ngrok)
- Lack key features like traffic inspection or custom domains (bore, localtunnel)
- Have heavy dependency trees or require complex setup (frp, rathole)
- Don't support both HTTP and TCP tunneling well

This project aims to be the **"SQLite of tunneling"** — a single binary, zero-config, production-ready solution.

---

## 3. Architecture Overview

### 3.1 High-Level Topology

```
                         ┌─────────────────────────────────────┐
                         │          TUNNEL SERVER (Edge)        │
                         │                                     │
  Internet ──[HTTPS]───▶ │  ┌─────────┐    ┌──────────────┐   │
  Users                  │  │  Edge    │    │   Control     │   │
                         │  │  Router  │◀──▶│   Plane       │   │
  Internet ──[TCP]─────▶ │  │ (HTTP/   │    │  (manages     │   │
  Users                  │  │  TCP)    │    │   tunnels)    │   │
                         │  └────┬────┘    └──────┬───────┘   │
                         │       │                │            │
                         │       │         ┌──────┴───────┐   │
                         │       │         │  Dashboard    │   │
                         │       │         │  API Server   │   │
                         │       │         └──────────────┘   │
                         └───────┼────────────────┼───────────┘
                                 │                │
                          [Mux Stream]     [TLS/TCP Control]
                                 │                │
                         ┌───────┴────────────────┴───────────┐
                         │         TUNNEL CLIENT (Agent)       │
                         │                                     │
                         │  ┌──────────┐    ┌──────────────┐  │
                         │  │  Local    │    │  Inspector   │  │
                         │  │  Proxy   │    │  (Web UI)    │  │
                         │  └────┬─────┘    └──────────────┘  │
                         └───────┼────────────────────────────┘
                                 │
                          [HTTP/TCP]
                                 │
                         ┌───────┴───────┐
                         │ Local Service  │
                         │ localhost:3000 │
                         └───────────────┘
```

### 3.2 Component Responsibilities

| Component | Responsibility |
|-----------|---------------|
| **Edge Router** | Accepts public HTTP/TCP connections, routes to correct tunnel based on Host header or port |
| **Control Plane** | Manages client connections, tunnel registration, heartbeat, auth |
| **Stream Multiplexer** | Carries multiple logical streams over a single TCP connection |
| **Local Proxy** | Forwards tunnel traffic to the local service |
| **Dashboard API** | REST API for tunnel management + embedded web UI for traffic inspection |
| **Inspector** | Captures, stores, and replays HTTP request/response pairs |

### 3.3 Connection Lifecycle

```
1. Client starts → Reads config → Connects to server control port (TLS)
2. Client sends AuthRequest with token
3. Server validates → Sends AuthResponse (success + session_id)
4. Client sends TunnelRequest (type=HTTP, subdomain="myapp")
5. Server allocates subdomain → Sends TunnelResponse (url="https://myapp.wirerift.com")
6. Server starts listening for public traffic on that subdomain
7. Public request arrives → Server creates new mux stream → Forwards to client
8. Client receives stream → Proxies to localhost:3000 → Returns response via stream
9. Heartbeat every 30s to keep connection alive
10. On disconnect → Exponential backoff reconnect (preserving tunnel ID if within grace period)
```

---

## 4. Wire Protocol

### 4.1 Design Goals

- Binary-efficient for data frames
- Human-debuggable for control messages
- Minimal overhead (< 9 bytes per data frame)
- No external serialization library (no protobuf, no msgpack)

### 4.2 Frame Format

All communication uses a unified frame format:

```
┌──────────────────────────────────────────────┐
│  Frame Header (9 bytes)                      │
├──────────┬──────────┬───────────┬────────────┤
│ Version  │   Type   │ Stream ID │  Length    │
│ (1 byte) │ (1 byte) │ (3 bytes) │ (4 bytes) │
├──────────┴──────────┴───────────┴────────────┤
│  Payload (0 to 16 MB)                        │
│  (variable length, up to Length bytes)        │
└──────────────────────────────────────────────┘
```

- **Version (1 byte):** Protocol version. Currently `0x01`.
- **Type (1 byte):** Frame type identifier.
- **Stream ID (3 bytes):** Logical stream identifier (0 = control stream). Supports up to 16,777,215 concurrent streams.
- **Length (4 bytes):** Big-endian uint32. Max payload size: 16 MB (`0x01000000`).

### 4.3 Frame Types

| Type ID | Name | Direction | Payload | Description |
|---------|------|-----------|---------|-------------|
| `0x01` | `AUTH_REQ` | C→S | JSON | Client authentication request |
| `0x02` | `AUTH_RES` | S→C | JSON | Authentication result |
| `0x03` | `TUNNEL_REQ` | C→S | JSON | Request to open a tunnel |
| `0x04` | `TUNNEL_RES` | S→C | JSON | Tunnel allocation result |
| `0x05` | `TUNNEL_CLOSE` | Both | JSON | Close a specific tunnel |
| `0x10` | `STREAM_OPEN` | S→C | JSON | New incoming connection (stream metadata) |
| `0x11` | `STREAM_DATA` | Both | Raw bytes | Data payload for a stream |
| `0x12` | `STREAM_CLOSE` | Both | — | Close a stream (half-close or full) |
| `0x13` | `STREAM_RST` | Both | — | Reset/abort a stream |
| `0x14` | `STREAM_WINDOW` | Both | 4 bytes | Flow control: window size update |
| `0x20` | `HEARTBEAT` | Both | 8 bytes | Ping with timestamp (unix nano) |
| `0x21` | `HEARTBEAT_ACK` | Both | 8 bytes | Pong echoing timestamp |
| `0xFE` | `GO_AWAY` | Both | JSON | Graceful shutdown signal |
| `0xFF` | `ERROR` | Both | JSON | Protocol-level error |

### 4.4 Control Message Payloads (JSON)

**AUTH_REQ:**
```json
{
  "token": "tk_a1b2c3d4e5f6...",
  "client_id": "cli_xxxx",
  "version": "1.0.0",
  "os": "linux",
  "arch": "amd64",
  "hostname": "ersin-dev"
}
```

**AUTH_RES:**
```json
{
  "ok": true,
  "session_id": "sess_xxxx",
  "server_version": "1.0.0",
  "heartbeat_interval_ms": 30000,
  "max_tunnels": 10,
  "max_streams_per_tunnel": 256
}
```

**TUNNEL_REQ:**
```json
{
  "type": "http",
  "subdomain": "myapp",
  "local_addr": "localhost:3000",
  "inspect": true,
  "auth": {
    "type": "basic",
    "username": "admin",
    "password": "secret"
  },
  "headers": {
    "X-Forwarded-Proto": "https"
  }
}
```

For TCP tunnels:
```json
{
  "type": "tcp",
  "remote_port": 0,
  "local_addr": "localhost:5432"
}
```

**TUNNEL_RES:**
```json
{
  "ok": true,
  "tunnel_id": "tun_xxxx",
  "type": "http",
  "public_url": "https://myapp.wirerift.com",
  "metadata": {
    "remote_port": null,
    "subdomain": "myapp"
  }
}
```

**STREAM_OPEN (sent by server when public request arrives):**
```json
{
  "tunnel_id": "tun_xxxx",
  "stream_id": 42,
  "remote_addr": "203.0.113.50:43210",
  "protocol": "http"
}
```

**GO_AWAY:**
```json
{
  "reason": "server_shutdown",
  "message": "Server is shutting down for maintenance",
  "reconnect_after_ms": 5000
}
```

### 4.5 Flow Control

Each stream has an independent flow control window to prevent fast senders from overwhelming slow receivers.

- Default window size: **256 KB** per stream.
- `STREAM_WINDOW` frames advertise additional capacity.
- Sender MUST NOT send more than the current window allows.
- This prevents memory exhaustion when client's local service is slow.

### 4.6 Protocol Negotiation

On initial TCP connection (before AUTH_REQ), client sends a magic byte sequence:

```
0x57 0x52 0x46 0x01
 'W'   'R'   'F'  version
```

Server validates the magic and version. If incompatible, server responds with `ERROR` frame and closes the connection.

---

## 5. Stream Multiplexer

### 5.1 Purpose

The multiplexer allows carrying multiple independent bidirectional streams over a single TCP connection. Each public HTTP request or TCP connection maps to one stream.

### 5.2 Stream Lifecycle

```
            Server                              Client
              │                                   │
              │──── STREAM_OPEN (stream_id=42) ──▶│
              │                                   │ (opens connection to local service)
              │──── STREAM_DATA (HTTP request) ──▶│
              │                                   │──▶ localhost:3000
              │                                   │◀── (response)
              │◀── STREAM_DATA (HTTP response) ───│
              │                                   │
              │◀── STREAM_CLOSE ──────────────────│
              │──── STREAM_CLOSE ────────────────▶│
              │                                   │
```

### 5.3 Stream States

```
              STREAM_OPEN
                  │
                  ▼
         ┌──── ACTIVE ────┐
         │                 │
    Send CLOSE         Recv CLOSE
         │                 │
         ▼                 ▼
    HALF_CLOSED       HALF_CLOSED
    (local)           (remote)
         │                 │
    Recv CLOSE         Send CLOSE
         │                 │
         └──────┬──────────┘
                ▼
             CLOSED
```

At any point, either side can send `STREAM_RST` to immediately abort.

### 5.4 Implementation Notes

```go
type Mux struct {
    conn     net.Conn
    streams  sync.Map            // map[uint32]*Stream
    nextID   atomic.Uint32       // for client-initiated streams
    accept   chan *Stream         // incoming streams
    closed   chan struct{}
    mu       sync.Mutex
}

type Stream struct {
    id       uint32
    mux      *Mux
    readBuf  *ringBuffer         // incoming data buffer
    readCh   chan struct{}        // signal new data available
    window   atomic.Int32        // send window remaining
    windowCh chan struct{}        // signal window update
    state    atomic.Uint32       // stream state
    onClose  sync.Once
}

// Stream implements io.ReadWriteCloser
func (s *Stream) Read(p []byte) (int, error)  { ... }
func (s *Stream) Write(p []byte) (int, error) { ... }
func (s *Stream) Close() error                { ... }
```

### 5.5 Ring Buffer

Custom lock-free ring buffer for stream reads. Avoids `bytes.Buffer` allocation churn.

```go
type ringBuffer struct {
    buf   []byte
    size  int
    r     int  // read cursor
    w     int  // write cursor
    full  bool
    mu    sync.Mutex
}
```

- Fixed allocation per stream (default 64 KB).
- Grows up to max window size if needed.
- Zero-copy reads when possible.

### 5.6 Concurrency Model

- **1 goroutine** for reading frames from TCP (frame reader loop).
- **1 goroutine** per active stream for writing to local connection.
- Frame reader dispatches data to appropriate stream's ring buffer.
- Keepalive (heartbeat) runs in frame reader loop — no separate goroutine.

---

## 6. Server (Edge) Architecture

### 6.1 Component Diagram

```
┌──────────────────────────────────────────────────────┐
│                    TUNNEL SERVER                      │
│                                                      │
│  ┌────────────┐   ┌────────────┐   ┌─────────────┐  │
│  │ HTTP Edge  │   │  TCP Edge  │   │  Control    │  │
│  │ Listener   │   │  Listener  │   │  Listener   │  │
│  │ :80/:443   │   │ :20000+    │   │  :4443      │  │
│  └─────┬──────┘   └─────┬──────┘   └──────┬──────┘  │
│        │                │                  │         │
│        ▼                ▼                  ▼         │
│  ┌─────────────────────────────────────────────┐     │
│  │              Router / Registry               │     │
│  │                                             │     │
│  │  HTTP routes: map[hostname] → *Tunnel       │     │
│  │  TCP routes:  map[port] → *Tunnel           │     │
│  │  Sessions:    map[session_id] → *Session     │     │
│  │  Auth:        map[token] → *Account          │     │
│  └─────────────────────────────────────────────┘     │
│                                                      │
│  ┌─────────────┐   ┌──────────────┐                  │
│  │  Dashboard   │   │  Metrics     │                  │
│  │  API :8080   │   │  Endpoint    │                  │
│  └─────────────┘   └──────────────┘                  │
└──────────────────────────────────────────────────────┘
```

### 6.2 HTTP Edge

The HTTP edge listener handles all incoming public HTTP/HTTPS requests.

**Routing logic:**
1. Extract `Host` header from incoming request.
2. Strip port and base domain → extract subdomain (e.g., `myapp.wirerift.com` → `myapp`).
3. Look up subdomain in router registry.
4. If found → Open new mux stream to client → Forward request.
5. If not found → Return `502 Tunnel not found` page.

**WebSocket support:**
- Detect `Upgrade: websocket` header.
- Hijack the HTTP connection using `http.Hijacker`.
- Bridge raw TCP between public connection and mux stream.

**Request/Response transformation:**
- Add `X-Forwarded-For`, `X-Forwarded-Proto`, `X-Forwarded-Host` headers.
- Optionally rewrite `Host` header to match local service expectation.
- Strip hop-by-hop headers.

### 6.3 TCP Edge

For raw TCP tunnels, the server dynamically opens listener ports.

- TCP port range: `20000–29999` (configurable).
- Each TCP tunnel gets a unique port.
- On new TCP connection → Open mux stream → Bidirectional `io.Copy`.
- Port is released when tunnel closes.

### 6.4 Control Plane

Listens on a dedicated TLS port (default `4443`).

Responsibilities:
- Accept client connections.
- Verify magic bytes + protocol version.
- Handle AUTH_REQ → validate token → create session.
- Handle TUNNEL_REQ → allocate resources → register routes.
- Heartbeat monitoring → evict dead sessions.
- Handle GO_AWAY for graceful shutdown.

### 6.5 Session Management

```go
type Session struct {
    ID          string
    AccountID   string
    Mux         *mux.Mux
    Tunnels     map[string]*Tunnel   // tunnel_id → Tunnel
    CreatedAt   time.Time
    LastSeen    time.Time
    RemoteAddr  net.Addr
    mu          sync.RWMutex
}

type Tunnel struct {
    ID          string
    Type        TunnelType           // HTTP or TCP
    Subdomain   string               // for HTTP tunnels
    RemotePort  int                  // for TCP tunnels
    LocalAddr   string
    Session     *Session
    Inspect     bool
    CreatedAt   time.Time
    BytesIn     atomic.Int64
    BytesOut    atomic.Int64
    Connections atomic.Int64
}
```

### 6.6 Session Grace Period

When a client disconnects unexpectedly:
1. Session enters **GRACE** state (default: 60 seconds).
2. Tunnel routes are preserved but return `503 Tunnel Offline` to public requests.
3. If client reconnects within grace period, session is restored seamlessly.
4. After grace period → session is destroyed, routes are released.

---

## 7. Client (Agent) Architecture

### 7.1 Component Diagram

```
┌──────────────────────────────────────────────────┐
│                  TUNNEL CLIENT                    │
│                                                  │
│  ┌──────────┐  ┌───────────┐  ┌──────────────┐  │
│  │  CLI     │  │  Config   │  │  Inspector   │  │
│  │  Parser  │  │  Loader   │  │  (Web UI)    │  │
│  └────┬─────┘  └─────┬─────┘  └──────┬───────┘  │
│       │              │               │           │
│       ▼              ▼               │           │
│  ┌────────────────────────────┐      │           │
│  │      Agent Controller      │◀─────┘           │
│  │                            │                  │
│  │  - Connect to server       │                  │
│  │  - Request tunnels         │                  │
│  │  - Handle reconnection     │                  │
│  │  - Manage mux streams      │                  │
│  └────────────┬───────────────┘                  │
│               │                                  │
│               ▼                                  │
│  ┌────────────────────────────┐                  │
│  │      Local Proxy           │                  │
│  │                            │                  │
│  │  Stream ←→ localhost:PORT  │                  │
│  └────────────────────────────┘                  │
└──────────────────────────────────────────────────┘
```

### 7.2 Agent Controller

The central orchestrator on the client side.

**Startup sequence:**
1. Parse CLI flags / load config file.
2. Resolve server address.
3. Dial server control port (TLS).
4. Send magic bytes + AUTH_REQ.
5. Receive AUTH_RES → store session info.
6. For each configured tunnel: send TUNNEL_REQ → receive TUNNEL_RES.
7. Print tunnel URLs to terminal.
8. Enter main loop: accept mux streams + heartbeat.

**Reconnection strategy:**
```
Attempt 1: immediate
Attempt 2: 500ms
Attempt 3: 1s
Attempt 4: 2s
Attempt 5: 4s
...
Max backoff: 30s
Reset backoff on successful connection held > 60s
```

On reconnect:
- Include `session_id` from previous AUTH_RES in new AUTH_REQ.
- Server may restore previous tunnels if within grace period.

### 7.3 Local Proxy

For each incoming mux stream:

**HTTP tunnels:**
1. Read HTTP request from stream.
2. Rewrite `Host` header to local target.
3. Forward to local address using `httputil.ReverseProxy` or raw TCP.
4. Pipe response back to stream.

**TCP tunnels:**
1. Dial local address.
2. Bidirectional `io.Copy` between stream and local connection.

**Error handling:**
- If local service is unreachable → Return `502 Bad Gateway` with descriptive error.
- If local service times out → Return `504 Gateway Timeout`.
- If connection is refused → Return `502` with "Connection refused — is your service running?"

### 7.4 Terminal UI

On successful tunnel establishment, print:

```
┌──────────────────────────────────────────────────────┐
│  WireRift v1.0.0                                       │
│                                                      │
│  Dashboard:  http://127.0.0.1:4040                   │
│  Session:    sess_a1b2c3d4                           │
│                                                      │
│  Tunnel      Public URL                     Local    │
│  ─────────── ───────────────────────────── ────────  │
│  http        https://myapp.wirerift.com       :3000    │
│  tcp         tcp://wirerift.com:20001         :5432    │
│                                                      │
│  Connections: 0     Bytes In: 0 B    Bytes Out: 0 B  │
└──────────────────────────────────────────────────────┘
```

Live-updating stats using ANSI escape codes (no external TUI library).

---

## 8. HTTP Tunneling

### 8.1 Request Flow (Detailed)

```
1. Public client sends:  GET /api/users HTTP/1.1
                         Host: myapp.wirerift.com

2. Server HTTP edge receives request.

3. Router lookup: "myapp" → Tunnel{session=sess_123, stream via mux}

4. Server opens new mux stream (STREAM_OPEN):
   {
     "tunnel_id": "tun_abc",
     "stream_id": 42,
     "remote_addr": "203.0.113.50:43210",
     "protocol": "http"
   }

5. Server writes raw HTTP request bytes to stream 42.

6. Client receives STREAM_OPEN → dials localhost:3000.

7. Client reads HTTP request from stream → adds X-Forwarded-* headers.

8. Client forwards modified request to localhost:3000.

9. Local service responds with HTTP response.

10. Client reads response → writes to stream 42.

11. Server reads response from stream 42 → writes to public client.

12. Both sides send STREAM_CLOSE.
```

### 8.2 Header Manipulation

**Added by server before forwarding:**
```
X-Forwarded-For: <original client IP>
X-Forwarded-Proto: https
X-Forwarded-Host: myapp.wirerift.com
X-Real-IP: <original client IP>
```

**Added by client before forwarding to local:**
```
X-Tunnel-Session: sess_xxxx
X-Tunnel-Request-Id: req_xxxx
```

### 8.3 HTTP/1.1 Keep-Alive Handling

Each HTTP request gets its own mux stream. The server's edge does NOT reuse mux streams across keep-alive requests from the same public client. This simplifies the implementation significantly.

Public-facing connection keep-alive is handled normally by Go's HTTP server. Each request within a keep-alive connection still gets a new mux stream.

### 8.4 Chunked Transfer & Streaming

- Streaming responses (Server-Sent Events, chunked transfer) work naturally since mux streams support bidirectional byte streaming.
- Client reads from local service in chunks → writes as STREAM_DATA frames.
- No buffering of the full response body.

### 8.5 WebSocket Tunneling

1. Server detects `Upgrade: websocket` in request headers.
2. Instead of using `httputil.ReverseProxy`, server hijacks the HTTP connection.
3. Raw bytes are bridged between public connection and mux stream.
4. Client also hijacks the local connection after forwarding the upgrade request.
5. Bidirectional raw byte streaming until either side closes.

---

## 9. TCP Tunneling

### 9.1 Port Allocation

```go
type PortAllocator struct {
    min      int                  // 20000
    max      int                  // 29999
    used     map[int]*Tunnel
    mu       sync.Mutex
}

func (pa *PortAllocator) Allocate(requested int) (int, error) {
    // If requested != 0, try that specific port
    // Otherwise, find first available in range
    // Returns allocated port or error
}
```

### 9.2 TCP Tunnel Flow

```
1. Client requests TCP tunnel: { "type": "tcp", "remote_port": 0 }
2. Server allocates port 20001 → starts TCP listener on :20001
3. Public client connects to wirerift.com:20001
4. Server sends STREAM_OPEN to client via mux
5. Client dials localhost:5432
6. Bidirectional io.Copy between:
   - Public TCP conn ↔ Mux stream ↔ Local TCP conn
7. On either side close → propagate close through stream
```

### 9.3 Bidirectional Copy

```go
func bridgeStreams(a, b io.ReadWriteCloser) {
    done := make(chan struct{}, 2)
    
    copy := func(dst io.WriteCloser, src io.Reader) {
        io.Copy(dst, src)
        dst.Close()
        done <- struct{}{}
    }
    
    go copy(a, b)
    go copy(b, a)
    
    <-done  // Wait for one direction to finish
    <-done  // Wait for the other
}
```

---

## 10. TLS & Certificate Management

### 10.1 TLS Strategy

Three modes of TLS operation:

| Mode | Description | Use Case |
|------|-------------|----------|
| **Auto-TLS** | Automatic certificate via ACME (Let's Encrypt) using `crypto/tls` + `net/http` challenge server | Production deployment |
| **Manual-TLS** | User provides cert/key files | Corporate CA, custom certs |
| **Self-Signed** | Auto-generated self-signed cert using `crypto/x509` | Development, testing |

### 10.2 ACME Implementation (Zero-Dependency)

Since we cannot use `golang.org/x/crypto/acme`, we implement a minimal ACME client using only stdlib:

```go
// Minimal ACME flow using net/http and crypto
type ACMEClient struct {
    directoryURL string            // https://acme-v02.api.letsencrypt.org/directory
    accountKey   *ecdsa.PrivateKey
    httpClient   *http.Client
}

func (c *ACMEClient) ObtainCertificate(domain string) (*tls.Certificate, error) {
    // 1. Register account (or retrieve existing)
    // 2. Create new order for domain
    // 3. Solve HTTP-01 challenge (serve token on /.well-known/acme-challenge/)
    // 4. Finalize order with CSR
    // 5. Download certificate chain
    // 6. Return tls.Certificate
}
```

**HTTP-01 Challenge:**
- Server temporarily serves challenge response on port 80.
- Path: `/.well-known/acme-challenge/<token>`
- After validation → certificate issued → stored on disk.

**Certificate storage:**
```
/var/lib/wirerift/certs/
├── accounts/
│   └── acme-v02/
│       └── account.json
├── wirerift.com/
│   ├── cert.pem
│   ├── key.pem
│   └── meta.json
└── custom-domain.com/
    ├── cert.pem
    └── key.pem
```

**Auto-renewal:** Background goroutine checks cert expiry every 12 hours. Renews when < 30 days remaining.

### 10.3 TLS Configuration

```go
tlsConfig := &tls.Config{
    MinVersion: tls.VersionTLS12,
    CipherSuites: []uint16{
        tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
        tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
        tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
    },
    GetCertificate: certManager.GetCertificate, // SNI-based cert selection
}
```

### 10.4 Control Connection TLS

Client-to-server control connection always uses TLS.

- In production: server's ACME cert.
- In dev: self-signed cert (client skips verification with `--insecure` flag).
- Optional mTLS: client presents cert for auth (enterprise feature, V2).

---

## 11. Authentication & Authorization

### 11.1 Token-Based Auth

```
Token format: tk_<base64url(32 random bytes)>
Example:      tk_a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8s9T0u1V2
```

**Generation:** `crypto/rand` → 32 bytes → base64url encode → prefix `tk_`.

### 11.2 Auth Flow

```
Client                           Server
  │                                │
  │── AUTH_REQ { token: "tk_..." } ─▶│
  │                                │ validate token against store
  │                                │ create session
  │◀── AUTH_RES { ok: true, ... } ──│
  │                                │
```

### 11.3 Auth Store

V1: File-based JSON store.

```json
{
  "accounts": [
    {
      "id": "acc_001",
      "name": "ersin",
      "token_hash": "<sha256 hash>",
      "max_tunnels": 10,
      "allowed_subdomains": ["ersin-*", "myapp"],
      "created_at": "2025-01-15T10:00:00Z"
    }
  ]
}
```

Tokens are stored as SHA-256 hashes (never plaintext). Comparison uses `crypto/subtle.ConstantTimeCompare`.

### 11.4 Anonymous Mode

Server can optionally allow unauthenticated tunnels:
- Limited to 1 tunnel per IP.
- Random subdomain only (no custom).
- Rate limited (10 req/s).
- Tunnel auto-expires after 2 hours.

### 11.5 Tunnel-Level Auth

Individual tunnels can require authentication from public visitors:

**Basic Auth:**
```
Server returns 401 unless public request includes valid
Authorization: Basic <base64(user:pass)>
```

**Bearer Token:**
```
Server validates Authorization: Bearer <token> header.
```

Configured per-tunnel in TUNNEL_REQ payload.

---

## 12. Custom Domains

### 12.1 How It Works

1. User owns `api.mycompany.com`.
2. User creates CNAME: `api.mycompany.com → wirerift.com`.
3. Client requests tunnel with custom domain:
   ```json
   { "type": "http", "hostname": "api.mycompany.com" }
   ```
4. Server verifies CNAME via DNS lookup (using `net.LookupCNAME`).
5. Server obtains TLS certificate for `api.mycompany.com` via ACME.
6. Traffic to `api.mycompany.com` routes to client's tunnel.

### 12.2 DNS Verification

```go
func verifyCNAME(hostname, expectedTarget string) error {
    cname, err := net.LookupCNAME(hostname)
    if err != nil {
        return fmt.Errorf("DNS lookup failed: %w", err)
    }
    if !strings.HasSuffix(strings.TrimSuffix(cname, "."), expectedTarget) {
        return fmt.Errorf("CNAME %s does not point to %s", cname, expectedTarget)
    }
    return nil
}
```

### 12.3 Alternative: TXT Record Verification

For users who cannot set CNAME (apex domains):
1. Server generates a verification token: `_tunnel-verify=v_a1b2c3d4`.
2. User adds TXT record to their domain.
3. Server verifies via `net.LookupTXT`.
4. After verification, user can use A/AAAA records pointing to server IP.

### 12.4 Certificate Handling for Custom Domains

- ACME HTTP-01 challenge works because traffic already routes to our server.
- Certificate is obtained and cached on first request.
- `tls.Config.GetCertificate` callback handles SNI-based cert selection.

---

## 13. Dashboard & Traffic Inspection

### 13.1 Server Dashboard (Admin API)

**Endpoint:** `http://server:8080/api/v1/`

| Method | Path | Description |
|--------|------|-------------|
| GET | `/status` | Server health and stats |
| GET | `/sessions` | List active sessions |
| GET | `/sessions/:id` | Session detail |
| DELETE | `/sessions/:id` | Force-disconnect session |
| GET | `/tunnels` | List active tunnels |
| GET | `/tunnels/:id` | Tunnel detail with stats |
| DELETE | `/tunnels/:id` | Close specific tunnel |
| GET | `/metrics` | Prometheus-compatible metrics |

Protected by admin API key in `Authorization` header.

### 13.2 Client Inspector (Local Dashboard)

**Endpoint:** `http://127.0.0.1:4040`

Features:
- List all active tunnels and their public URLs.
- Live stream of HTTP requests/responses.
- Request detail view (headers, body, timing).
- Request replay (resend captured request to local service).
- Filter and search requests.
- Connection status indicator.

### 13.3 Request Capture

```go
type CapturedRequest struct {
    ID            string        `json:"id"`
    TunnelID      string        `json:"tunnel_id"`
    Timestamp     time.Time     `json:"timestamp"`
    Duration      time.Duration `json:"duration_ms"`
    RemoteAddr    string        `json:"remote_addr"`
    
    // Request
    Method        string            `json:"method"`
    URL           string            `json:"url"`
    Proto         string            `json:"proto"`
    ReqHeaders    http.Header       `json:"req_headers"`
    ReqBodySize   int64             `json:"req_body_size"`
    ReqBody       []byte            `json:"req_body,omitempty"`    // capped at 1 MB
    
    // Response
    StatusCode    int               `json:"status_code"`
    ResHeaders    http.Header       `json:"res_headers"`
    ResBodySize   int64             `json:"res_body_size"`
    ResBody       []byte            `json:"res_body,omitempty"`    // capped at 1 MB
}
```

**Storage:** In-memory ring buffer, last 1000 requests (configurable). No disk persistence.

### 13.4 Dashboard Web UI

Embedded in the client binary using `embed` package.

```go
//go:embed dashboard/dist/*
var dashboardFS embed.FS
```

Static HTML/CSS/JS dashboard (no build step needed — hand-written vanilla JS or precompiled).

**UI Design:** Minimal, dark-themed, inspired by ngrok's inspect UI.

**Pages:**
- **Overview:** Tunnel list, connection status, quick stats.
- **Traffic:** Live request log with expandable details.
- **Request Detail:** Full headers, formatted body (JSON pretty-print), timing waterfall.
- **Replay:** Modify and resend any captured request.

### 13.5 Dashboard API (Client-Side)

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/tunnels` | List local tunnels |
| GET | `/api/requests` | List captured requests |
| GET | `/api/requests/:id` | Request detail |
| POST | `/api/requests/:id/replay` | Replay request |
| GET | `/api/status` | Agent status |
| GET | `/api/requests/stream` | SSE stream of new requests |

---

## 14. Configuration

### 14.1 Config File Format

Hand-rolled TOML-subset parser (no external TOML library). Supports:
- Key-value pairs: `key = "value"`, `key = 123`, `key = true`
- Sections: `[section]`
- Nested sections: `[section.subsection]`
- Comments: `# comment`
- Arrays: `key = ["a", "b", "c"]`

### 14.2 Server Config

File: `/etc/wirerift/server.toml`

```toml
# Server Configuration

[server]
control_addr = "0.0.0.0:4443"
http_addr = "0.0.0.0:443"
http_insecure_addr = "0.0.0.0:80"
dashboard_addr = "127.0.0.1:8080"
domain = "wirerift.com"

[tls]
mode = "auto"                    # auto | manual | self-signed
cert_dir = "/var/lib/wirerift/certs"
acme_email = "admin@wirerift.com"

# Only for mode = "manual":
# cert_file = "/path/to/cert.pem"
# key_file = "/path/to/key.pem"

[tcp]
port_range_min = 20000
port_range_max = 29999

[auth]
required = true
store_file = "/var/lib/wirerift/auth.json"
allow_anonymous = false
anonymous_tunnel_ttl = "2h"

[limits]
max_sessions = 1000
max_tunnels_per_session = 10
max_streams_per_tunnel = 256
max_request_body_size = "50MB"

[session]
heartbeat_interval = "30s"
heartbeat_timeout = "90s"
grace_period = "60s"

[logging]
level = "info"                   # debug | info | warn | error
format = "json"                  # json | text
```

### 14.3 Client Config

File: `~/.config/wirerift/config.toml` or `.wirerift.toml` in project root.

```toml
# Client Configuration

[client]
server_addr = "wirerift.com:4443"
auth_token = "tk_a1B2c3D4e5F6..."
inspect = true
inspect_addr = "127.0.0.1:4040"

# Optional: skip TLS verification (dev only)
# insecure = true

[[tunnels]]
name = "web"
type = "http"
local_addr = "localhost:3000"
subdomain = "myapp"

[tunnels.auth]
type = "basic"
username = "admin"
password = "secret"

[[tunnels]]
name = "db"
type = "tcp"
local_addr = "localhost:5432"
remote_port = 0                  # 0 = auto-assign

[[tunnels]]
name = "api"
type = "http"
local_addr = "localhost:8080"
hostname = "api.mycompany.com"   # custom domain

[tunnels.headers]
"X-Custom-Header" = "value"
```

### 14.4 Environment Variables

All config values can be overridden via env vars:

```
WIRERIFT_SERVER_ADDR=wirerift.com:4443
WIRERIFT_AUTH_TOKEN=tk_xxxx
WIRERIFT_LOG_LEVEL=debug
```

Pattern: `WIRERIFT_` + section + `_` + key (uppercased).

### 14.5 Config Precedence

```
CLI flags > Environment variables > Config file > Defaults
```

---

## 15. CLI Design

### 15.1 Client CLI

```bash
# Start tunnel with CLI args (simplest usage)
wirerift http 3000
wirerift http 3000 --subdomain myapp
wirerift tcp 5432

# Start with config file
wirerift start
wirerift start --config ./tunnel.toml

# Specific tunnel from config
wirerift start web

# One-off commands
wirerift authtoken tk_xxxx           # save token to config
wirerift status                      # show active tunnels
wirerift version                     # show version info

# Options
wirerift http 3000 \
  --subdomain myapp \
  --server wirerift.com:4443 \
  --auth-token tk_xxxx \
  --inspect \
  --inspect-addr 127.0.0.1:4040 \
  --basic-auth admin:secret \
  --host-header myapp.local \
  --log-level debug
```

### 15.2 Server CLI

```bash
# Start server
wirerift-server start
wirerift-server start --config /etc/tunnel/server.toml

# Token management
wirerift-server token create --name "ersin" --max-tunnels 10
wirerift-server token list
wirerift-server token revoke tk_xxxx

# Status
wirerift-server status
wirerift-server sessions
wirerift-server tunnels
```

### 15.3 CLI Parser

Hand-rolled argument parser (no `cobra`, no `urfave/cli`):

```go
type CLI struct {
    commands map[string]*Command
    flags    map[string]*Flag
}

type Command struct {
    Name    string
    Desc    string
    Run     func(args []string, flags map[string]string) error
    Sub     map[string]*Command
}
```

Supports:
- Positional args: `tunnel http 3000`
- Long flags: `--subdomain myapp`
- Short flags: `-s myapp`
- Combined: `-vvv`
- Value flags: `--port=3000` or `--port 3000`
- `--help` auto-generation

---

## 16. Observability

### 16.1 Structured Logging

Using `log/slog` (Go 1.21+ stdlib):

```go
slog.Info("tunnel opened",
    "tunnel_id", tunnel.ID,
    "type", tunnel.Type,
    "subdomain", tunnel.Subdomain,
    "session_id", session.ID,
    "remote_addr", session.RemoteAddr,
)
```

Log levels: `DEBUG`, `INFO`, `WARN`, `ERROR`

### 16.2 Metrics

Prometheus-compatible `/metrics` endpoint using hand-rolled text format:

```
# HELP wirerift_active_sessions Number of active sessions
# TYPE wirerift_active_sessions gauge
wirerift_active_sessions 42

# HELP wirerift_active_tunnels Number of active tunnels
# TYPE wirerift_active_tunnels gauge
wirerift_active_tunnels{type="http"} 35
wirerift_active_tunnels{type="tcp"} 7

# HELP wirerift_requests_total Total HTTP requests through tunnels
# TYPE wirerift_requests_total counter
wirerift_requests_total{status_class="2xx"} 15234
wirerift_requests_total{status_class="3xx"} 3421
wirerift_requests_total{status_class="4xx"} 892
wirerift_requests_total{status_class="5xx"} 45

# HELP wirerift_bytes_transferred_total Total bytes transferred
# TYPE wirerift_bytes_transferred_total counter
wirerift_bytes_transferred_total{direction="in"} 1073741824
wirerift_bytes_transferred_total{direction="out"} 2147483648

# HELP wirerift_stream_duration_seconds Stream duration histogram
# TYPE wirerift_stream_duration_seconds histogram
wirerift_stream_duration_seconds_bucket{le="0.1"} 5000
wirerift_stream_duration_seconds_bucket{le="0.5"} 8000
wirerift_stream_duration_seconds_bucket{le="1.0"} 9500
wirerift_stream_duration_seconds_bucket{le="5.0"} 9900
wirerift_stream_duration_seconds_bucket{le="+Inf"} 10000

# HELP wirerift_connection_errors_total Connection errors
# TYPE wirerift_connection_errors_total counter
wirerift_connection_errors_total{type="auth_failed"} 12
wirerift_connection_errors_total{type="local_refused"} 45
wirerift_connection_errors_total{type="timeout"} 8
```

### 16.3 Health Check

```
GET /health → 200 OK
GET /health/ready → 200 OK (or 503 if not ready)
```

---

## 17. Security Model

### 17.1 Threat Model

| Threat | Mitigation |
|--------|-----------|
| Unauthorized tunnel creation | Token-based auth, rate limiting |
| Subdomain squatting | Reserved subdomain list, account-bound subdomains |
| DDoS via tunnel | Per-tunnel rate limiting, connection limits |
| Data interception | TLS on all connections (control + edge) |
| Token theft | Tokens stored as hashes, rotation support |
| Protocol attacks | Frame size limits, stream count limits |
| Resource exhaustion | Max streams, max tunnels, memory limits |
| Subdomain enumeration | Random subdomains by default, no directory listing |

### 17.2 Rate Limiting

Token bucket algorithm (stdlib only):

```go
type RateLimiter struct {
    tokens     float64
    maxTokens  float64
    refillRate float64     // tokens per second
    lastRefill time.Time
    mu         sync.Mutex
}

func (rl *RateLimiter) Allow() bool {
    rl.mu.Lock()
    defer rl.mu.Unlock()
    
    now := time.Now()
    elapsed := now.Sub(rl.lastRefill).Seconds()
    rl.tokens = min(rl.maxTokens, rl.tokens + elapsed * rl.refillRate)
    rl.lastRefill = now
    
    if rl.tokens >= 1 {
        rl.tokens--
        return true
    }
    return false
}
```

Applied at:
- Per-account: max tunnel creation rate
- Per-tunnel: max requests per second
- Per-IP: max connections per second
- Global: max total connections

### 17.3 Input Validation

- Subdomain: `^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$` (max 63 chars)
- Token: `^tk_[A-Za-z0-9_-]{43}$`
- Hostnames: validated per RFC 1123
- Frame payload: hard limit at 16 MB
- Request body: configurable limit (default 50 MB)

### 17.4 Reserved Subdomains

Blocked by default: `www`, `api`, `admin`, `dashboard`, `status`, `health`, `metrics`, `mail`, `smtp`, `ftp`, `ssh`, `ns1`, `ns2`, etc.

---

## 18. Performance Targets

### 18.1 Benchmarks (V1 Targets)

| Metric | Target | Notes |
|--------|--------|-------|
| Tunnel establishment | < 100ms | After auth |
| HTTP request latency overhead | < 5ms | Added by tunnel vs direct |
| Throughput per tunnel | > 500 Mbps | On 1 Gbps link |
| Concurrent tunnels per server | > 10,000 | With connection pooling |
| Concurrent streams per tunnel | > 256 | Configurable |
| Memory per idle tunnel | < 50 KB | Mostly mux overhead |
| Server binary size | < 15 MB | Static, stripped |
| Client binary size | < 10 MB | Static, stripped |
| Cold start time | < 50ms | Client ready to serve |

### 18.2 Optimization Strategies

- **Zero-copy forwarding:** Use `io.Copy` with `*net.TCPConn` to leverage `sendfile(2)` syscall on Linux.
- **Buffer pooling:** `sync.Pool` for frame buffers and HTTP buffers.
- **Minimal allocations:** Reuse frame headers, avoid string concatenation in hot paths.
- **Connection pooling:** Reuse local connections to backend service (HTTP keep-alive).
- **Goroutine budget:** Aim for 2-3 goroutines per active stream, not more.
- **Lock-free where possible:** Atomic operations for counters, `sync.Map` for read-heavy registries.

### 18.3 Memory Budget

```
Per idle tunnel:
  - Mux overhead:     ~4 KB
  - Tunnel metadata:  ~2 KB
  - Router entry:     ~200 bytes
  Total: ~6 KB

Per active stream (HTTP request in flight):
  - Ring buffer:       64 KB
  - Frame buffer:      16 KB
  - HTTP buffer:       8 KB
  - Goroutine stack:   8 KB (initial)
  Total: ~96 KB

Server with 10,000 idle tunnels + 1,000 active streams:
  - Tunnels: 10,000 × 6 KB  = 60 MB
  - Streams: 1,000 × 96 KB  = 96 MB
  - Base server overhead:    ~50 MB
  Total: ~206 MB
```

---

## 19. Project Structure

```
wirerift/
├── cmd/
│   ├── server/                  # Server binary entry point
│   │   └── main.go
│   └── client/                  # Client binary entry point
│       └── main.go
│
├── internal/
│   ├── proto/                   # Wire protocol
│   │   ├── frame.go             # Frame encoding/decoding
│   │   ├── frame_test.go
│   │   ├── message.go           # Control message types (JSON)
│   │   ├── message_test.go
│   │   └── constants.go         # Frame types, magic bytes, limits
│   │
│   ├── mux/                     # Stream multiplexer
│   │   ├── mux.go               # Mux connection manager
│   │   ├── mux_test.go
│   │   ├── stream.go            # Individual stream
│   │   ├── stream_test.go
│   │   ├── ringbuf.go           # Ring buffer
│   │   └── ringbuf_test.go
│   │
│   ├── server/                  # Server components
│   │   ├── server.go            # Main server orchestrator
│   │   ├── control.go           # Control plane listener
│   │   ├── edge_http.go         # HTTP edge listener
│   │   ├── edge_tcp.go          # TCP edge listener
│   │   ├── router.go            # Host/port → tunnel routing
│   │   ├── session.go           # Session management
│   │   ├── portalloc.go         # TCP port allocator
│   │   ├── dashboard.go         # Admin API endpoints
│   │   ├── metrics.go           # Prometheus metrics
│   │   └── server_test.go
│   │
│   ├── client/                  # Client components
│   │   ├── agent.go             # Main agent controller
│   │   ├── proxy.go             # Local service proxy
│   │   ├── reconnect.go         # Reconnection logic
│   │   ├── inspector.go         # Traffic capture
│   │   ├── dashboard.go         # Local web dashboard API
│   │   ├── terminal.go          # Terminal UI (live stats)
│   │   └── agent_test.go
│   │
│   ├── auth/                    # Authentication
│   │   ├── token.go             # Token generation/validation
│   │   ├── store.go             # File-based auth store
│   │   └── token_test.go
│   │
│   ├── tls/                     # TLS management
│   │   ├── manager.go           # Certificate manager
│   │   ├── acme.go              # Minimal ACME client
│   │   ├── selfsigned.go        # Self-signed cert generator
│   │   └── acme_test.go
│   │
│   ├── config/                  # Configuration
│   │   ├── parser.go            # TOML-subset parser
│   │   ├── parser_test.go
│   │   ├── server.go            # Server config struct
│   │   ├── client.go            # Client config struct
│   │   └── env.go               # Environment variable overlay
│   │
│   ├── ratelimit/               # Rate limiting
│   │   ├── bucket.go            # Token bucket
│   │   └── bucket_test.go
│   │
│   └── cli/                     # CLI framework
│       ├── cli.go               # Command parser
│       ├── help.go              # Help text generation
│       └── cli_test.go
│
├── dashboard/                   # Embedded web UI assets
│   └── dist/
│       ├── index.html
│       ├── app.js
│       └── style.css
│
├── go.mod                       # Module definition (zero deps)
├── go.sum                       # Empty!
├── Makefile                     # Build, test, release targets
├── Dockerfile                   # Multi-stage, scratch-based
├── SPECIFICATION.md             # This document
├── IMPLEMENTATION.md            # Implementation guide (next)
├── TASKS.md                     # Task breakdown (next)
├── README.md                    # User-facing documentation
├── CHANGELOG.md
├── LICENSE
└── .github/
    └── workflows/
        └── ci.yml               # Build + test + release
```

---

## 20. Version Roadmap

### V1.0 — Foundation (Current Scope)

- [x] Wire protocol with frame encoding/decoding
- [x] Stream multiplexer with flow control
- [x] Server: HTTP edge with subdomain routing
- [x] Server: TCP edge with port allocation
- [x] Server: Control plane with session management
- [x] Client: Agent with tunnel management
- [x] Client: Local HTTP/TCP proxy
- [x] TLS: Self-signed + manual cert support
- [x] TLS: ACME (Let's Encrypt) auto-cert
- [x] Authentication: Token-based
- [x] Custom domains with CNAME verification
- [x] Traffic inspection (capture + replay)
- [x] Client web dashboard (inspect UI)
- [x] Server admin API
- [x] CLI for client and server
- [x] Config file support (TOML-subset)
- [x] Structured logging (slog)
- [x] Prometheus-compatible metrics
- [x] Rate limiting
- [x] WebSocket passthrough
- [x] Graceful shutdown + reconnection

### V2.0 — Production Hardening

- [ ] Cluster mode: multiple edge servers with shared state (gossip protocol)
- [ ] Persistent tunnel URLs (survive server restart)
- [ ] OAuth/OIDC tunnel-level auth
- [ ] IP whitelisting per tunnel
- [ ] Request/response transformation middleware
- [ ] gRPC / HTTP/2 tunneling
- [ ] UDP tunneling (QUIC)
- [ ] Binary config format for embedding
- [ ] Plugin system (Go plugin or WASM)
- [ ] Relay chain (tunnel through multiple hops)

### V3.0 — Enterprise

- [ ] Multi-tenant with organizations
- [ ] RBAC (role-based access control)
- [ ] Audit logging
- [ ] Compliance features (data residency, encryption-at-rest)
- [ ] SLA monitoring and alerting
- [ ] Horizontal autoscaling
- [ ] Web console for team management

---

## 21. Open Questions

### Naming — DECIDED
- **Project name: WireRift**
- Binary names: `wirerift` (client), `wirerift-server` (server)
- Config file: `.wirerift.toml` or `~/.config/wirerift/config.toml`
- Subdomain pattern: `*.wirerift.com`
- Environment variable prefix: `WIRERIFT_`
- Protocol magic: `0x57 0x52 0x46 0x01` → `W`, `R`, `F`, version

### Protocol Versioning
- How to handle protocol version upgrades? Options:
  - A) Version in magic bytes → incompatible versions rejected.
  - B) Feature negotiation in AUTH_REQ/AUTH_RES.
  - C) Both: magic for major, negotiate for minor.
  - **Recommendation:** Option C.

### TOML Parser Scope
- Full TOML compliance is complex. How minimal can we go?
  - V1: Support strings, integers, booleans, arrays, sections. No inline tables, no datetime, no multiline strings.
  - This covers 95% of use cases.

### Dashboard UI Technology
- Options:
  - A) Vanilla JS (zero build step, embed directly).
  - B) Preact (small, but needs build step).
  - C) Server-rendered HTML (no JS, htmx-style).
  - **Recommendation:** Option A for V1. Minimal JS, maximum compatibility.

### ACME Complexity
- Implementing ACME from scratch is significant work (~500-800 LOC).
- Alternative: V1 ships with manual + self-signed only. ACME in V1.1.
- **Recommendation:** Include ACME in V1 — it's a key differentiator for self-hosted.

### go.sum Truly Empty?
- Yes, if all imports are from stdlib. `go mod tidy` will produce empty go.sum.
- The `embed` package is stdlib. `log/slog` is stdlib (Go 1.21+).
- `crypto/tls`, `net/http`, `crypto/x509` — all stdlib.
- Confirmed: zero external dependencies is achievable for full V1 scope.

---

> **Next steps:** Create IMPLEMENTATION.md (build order, code patterns) → TASKS.md (granular task list) → Begin coding.
