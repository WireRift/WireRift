<h1 align="center">WireRift</h1>

<p align="center">
  <strong>Tear a rift through the wire. Expose localhost to the world.</strong>
</p>

<p align="center">
  <a href="https://goreportcard.com/report/github.com/wirerift/wirerift"><img src="https://goreportcard.com/badge/github.com/wirerift/wirerift" alt="Go Report Card"></a>
  <a href="https://opensource.org/licenses/MIT"><img src="https://img.shields.io/badge/License-MIT-yellow.svg" alt="License: MIT"></a>
  <a href="https://github.com/WireRift/WireRift/releases/latest"><img src="https://img.shields.io/github/v/release/WireRift/WireRift" alt="Release"></a>
</p>

<p align="center">
  <img src="wirerift.png" alt="WireRift Overview" width="100%">
</p>

Open-source, zero-dependency tunnel server and client. Written in Go.

## Features

- **Zero dependencies** — uses only Go standard library
- **Single binary** — no runtime dependencies
- **Self-hosted** — run your own tunnel server
- **HTTP & TCP tunnels** — expose web services or raw TCP
- **Auto TLS** — automatic HTTPS with self-signed certificates
- **WebSocket support** — real-time applications work out of the box
- **Custom domains** — use your own domain names
- **Built-in Dashboard** — web UI for monitoring tunnels and traffic
- **Traffic Inspector** — real-time request/response capture in dashboard
- **Request Replay** — replay captured requests with one click
- **Basic Auth** — HTTP Basic Authentication per tunnel
- **IP Whitelist** — restrict tunnel access by IP address or CIDR range
- **PIN Protection** — require a PIN to access tunnels via browser, header, or URL
- **Custom Headers** — inject response headers through tunnels
- **File Server Mode** — serve static files directly through a tunnel
- **Webhook Relay** — fan-out incoming requests to multiple endpoints
- **Stream Multiplexing** — multiple connections over single TCP
- **Flow Control** — backpressure handling per stream
- **Rate Limiting** — per-IP HTTP and per-session tunnel creation limits
- **Auto Reconnect** — automatic reconnection with tunnel re-creation
- **Comprehensive Tests** — 99.7% coverage, fuzz tests, stress tests

## Quick Start

### Build from Source

```bash
git clone https://github.com/wirerift/wirerift
cd wirerift
make build
```

### Start the Server

```bash
./bin/wirerift-server
./bin/wirerift-server -domain mytunnel.com
./bin/wirerift-server -auto-cert -cert-dir ./certs
```

### Create Tunnels

```bash
# HTTP tunnel
wirerift http 3000
wirerift http 3000 myapp              # custom subdomain

# TCP tunnel
wirerift tcp 5432

# Serve static files
wirerift serve ./dist -subdomain mysite

# With access control
wirerift http 8080 -pin mysecret
wirerift http 8080 -whitelist "10.0.0.0/8"
wirerift http 8080 -auth "admin:secret"
wirerift http 8080 -inspect           # enable traffic inspector

# Custom response headers
wirerift http 8080 -header "X-Robots-Tag:noindex,X-Frame-Options:DENY"

# Combine everything
wirerift http 8080 -subdomain api \
  -auth "admin:pass" \
  -pin 1234 \
  -whitelist "10.0.0.0/8" \
  -header "X-Frame-Options:DENY" \
  -inspect
```

## Configuration

```yaml
# wirerift.yaml
server: localhost:4443
token: ""

tunnels:
  - type: http
    local_port: 8080
    subdomain: myapp

  - type: http
    local_port: 9090
    subdomain: admin
    auth: "admin:secret"
    pin: "mysecret"
    whitelist: "10.0.0.0/8"
    inspect: true
    headers: "X-Robots-Tag:noindex"

  - type: tcp
    local_port: 5432
```

```bash
wirerift start wirerift.yaml
```

## Traffic Inspector

Enable request/response inspection on any tunnel:

```bash
wirerift http 8080 -inspect
```

The dashboard at `http://localhost:4040` shows live traffic with:
- Real-time request log (method, path, status, duration, client IP)
- Expandable header details per request
- Tunnel filtering
- **Request Replay** — resend any captured request with one click

API access:
```bash
# List captured requests
curl -H "Authorization: Bearer TOKEN" http://localhost:4040/api/requests?limit=50

# Replay a request
curl -X POST -H "Authorization: Bearer TOKEN" http://localhost:4040/api/requests/{id}/replay
```

## Access Control

### Basic Auth

```bash
wirerift http 8080 -auth "user:password"
```

Uses constant-time comparison. Returns `401` with `WWW-Authenticate` header.

### IP Whitelist

```bash
wirerift http 8080 -whitelist "203.0.113.50,10.0.0.0/8"
```

Supports IPv4, IPv6, CIDR. HTTP returns `403`, TCP silently drops.

### PIN Protection

```bash
wirerift http 8080 -pin mysecret
```

PIN entry via:
- **Browser form** — dark-themed PIN page, sets HttpOnly HMAC cookie for 24h
- **HTTP Header** — `X-WireRift-PIN: mysecret`
- **Query parameter** — `?pin=mysecret` (redirects to clean URL)

## Webhook Relay

Fan-out incoming webhook requests to multiple local endpoints:

```go
relay := server.NewWebhookRelay("tunnel-id", []string{
    "localhost:8081",  // staging
    "localhost:8082",  // dev
})
results := relay.Relay("POST", "/webhook", headers, body)
```

## File Server

Serve a directory through a tunnel without running a local web server:

```bash
wirerift serve ./dist -subdomain mysite
wirerift serve ./public -pin secret -whitelist "10.0.0.0/8"
```

## API Reference

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/tunnels` | GET | List active tunnels |
| `/api/sessions` | GET | List connected sessions |
| `/api/stats` | GET | Server statistics |
| `/api/requests` | GET | List captured requests |
| `/api/requests/{id}/replay` | POST | Replay a captured request |
| `/api/domains` | GET/POST | List/add custom domains |
| `/api/domains/{domain}` | GET/DELETE | Get/remove domain |
| `/api/domains/{domain}/dns` | GET | Get DNS records |
| `/api/domains/{domain}/verify` | POST | Verify domain |

```bash
curl -H "Authorization: Bearer YOUR_TOKEN" http://localhost:4040/api/tunnels
```

## Architecture

```
+--------+--------+----------+-----------+
| Version|  Type  | StreamID |  Length   |
| 1 byte | 1 byte | 3 bytes  |  4 bytes  |
+--------+--------+----------+-----------+
|            Payload (variable)          |
+----------------------------------------+

Header: 9 bytes, Magic: 0x57 0x52 0x46 0x01 ("WRF\x01")
```

```
Client                              Server
  |------- AUTH_REQ ----------------->|
  |<------ AUTH_RES ------------------|
  |------- TUNNEL_REQ --------------->|  myapp.wirerift.com
  |<------ TUNNEL_RES ----------------|
  |------- STREAM_OPEN(1) ----------->|  Request #1
  |------- STREAM_DATA(1) ----------->|
  |<------ STREAM_DATA(1) ------------|
  |------- STREAM_CLOSE(1) ---------->|
  |------- STREAM_OPEN(2) ----------->|  Concurrent!
```

## Project Structure

```
wirerift/
├── cmd/
│   ├── wirerift/          # Client CLI
│   └── wirerift-server/   # Server CLI
├── internal/
│   ├── auth/              # Token authentication
│   ├── client/            # Client implementation
│   ├── config/            # Configuration & domains
│   ├── dashboard/         # Web dashboard & traffic inspector
│   ├── mux/               # Stream multiplexing
│   ├── proto/             # Wire protocol
│   ├── ratelimit/         # Rate limiting
│   ├── server/            # Server, proxy, webhook relay
│   ├── tls/               # TLS certificate management
│   └── utils/             # Subdomain validation
├── test/
│   ├── advanced/          # Security, stress, reconnect, soak tests
│   └── benchmark/         # Throughput & latency benchmarks
├── website/               # Documentation website (React + Vite)
└── Makefile
```

## Benchmark

AMD Ryzen 9 9950X3D, Windows 11, Go 1.23 (local):

| Metric | Value |
|--------|-------|
| Latency overhead | ~0.5ms (small), ~0ms (1KB+) |
| Download throughput | **95.8 MB/s** |
| Single-thread RPS | **10,442 req/s** |
| 10 concurrent | 9,814 req/s |
| 100 concurrent | 3,915 req/s |
| Tunnel creation | **31,000/sec** |

```bash
go run ./test/benchmark/      # Throughput & latency
go test -bench=. ./internal/  # Micro-benchmarks
go run ./test/advanced/       # Security, stress, soak tests
```

## Client Options

```
Commands:
  http <port> [subdomain]   Create an HTTP tunnel
  tcp <port>                Create a TCP tunnel
  serve <dir>               Serve static files through tunnel
  start [config]            Start tunnels from config file
  list                      List active tunnels

HTTP/Serve Options:
  -server string      Server address (default "localhost:4443")
  -token string       Authentication token
  -subdomain string   Requested subdomain
  -auth string        Basic auth "user:password"
  -pin string         PIN protection
  -whitelist string   IP whitelist "ip1,ip2,cidr"
  -header string      Response headers "Key:Val,Key:Val"
  -inspect            Enable traffic inspector
  -v                  Verbose output
```

## Security

- Token-based authentication for all connections
- TLS support with auto-generated certificates
- Basic Auth with constant-time comparison
- IP whitelist (IPv4/IPv6/CIDR)
- PIN protection with HMAC cookies
- Custom response headers
- Rate limiting per session
- Stream isolation with independent flow control

## License

MIT License — see [LICENSE](LICENSE)
