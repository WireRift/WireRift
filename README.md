<p align="center">
  <img src="logo.png" alt="WireRift Logo" width="200">
</p>

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
- **Built-in Dashboard** — web UI for monitoring active tunnels
- **Stream Multiplexing** — multiple connections over single TCP
- **Flow Control** — backpressure handling per stream
- **IP Whitelist** — restrict tunnel access by IP address or CIDR range
- **PIN Protection** — require a PIN to access tunnels via browser, header, or URL
- **Rate Limiting** — per-IP HTTP and per-session tunnel creation limits
- **Auto Reconnect** — automatic reconnection with tunnel re-creation
- **Session Timeout** — inactive sessions cleaned up automatically
- **Comprehensive Tests** — all packages tested with CI coverage enforcement

## Quick Start

### Build from Source

```bash
git clone https://github.com/wirerift/wirerift
cd wirerift
make build
```

### Start the Server

```bash
# Basic server
./bin/wirerift-server

# With custom domain
./bin/wirerift-server -domain mytunnel.com

# With auto-generated certificates
./bin/wirerift-server -auto-cert -cert-dir ./certs

# Verbose logging
./bin/wirerift-server -v
```

### Create a Tunnel

```bash
# HTTP tunnel - exposes local port 3000
./bin/wirerift http 3000
# → http://random-subdomain.wirerift.com

# HTTP tunnel with custom subdomain
./bin/wirerift http 3000 myapp
# → http://myapp.wirerift.com

# TCP tunnel - expose any TCP service
./bin/wirerift tcp 5432
# → tcp://wirerift.com:20001

# PIN-protected tunnel
./bin/wirerift http 3000 -pin mysecret
# → Visitors must enter PIN to access

# IP-restricted tunnel
./bin/wirerift http 3000 -whitelist 1.2.3.4,10.0.0.0/8
# → Only whitelisted IPs can connect
```

## Configuration

Create a `wirerift.yaml` file:

```yaml
# Server configuration
server: localhost:4443
token: ""  # Your API token

# Tunnels to start
tunnels:
  - type: http
    local_port: 8080
    subdomain: ""            # Empty = random subdomain
    # whitelist: "1.2.3.4"   # Restrict by IP (comma-separated, CIDR supported)
    # pin: "secret123"       # Require PIN to access

  - type: tcp
    local_port: 25565
```

Then run:

```bash
./bin/wirerift start wirerift.yaml
```

## Architecture

WireRift uses a custom binary protocol with stream multiplexing:

### Protocol Frame Format

```
+--------+--------+----------+-----------+
| Version|  Type  | StreamID |  Length   |
| 1 byte | 1 byte | 3 bytes  |  4 bytes  |
+--------+--------+----------+-----------+
|            Payload (variable)          |
+----------------------------------------+

Header: 9 bytes total
Magic bytes: 0x57 0x52 0x46 0x01 ("WRF\x01")
```

### Frame Types

| Type | Value | Description |
|------|-------|-------------|
| AUTH_REQ | 0x01 | Authentication request |
| AUTH_RES | 0x02 | Authentication response |
| TUNNEL_REQ | 0x03 | Tunnel creation request |
| TUNNEL_RES | 0x04 | Tunnel creation response |
| TUNNEL_CLOSE | 0x05 | Tunnel close |
| STREAM_OPEN | 0x10 | Open new stream |
| STREAM_DATA | 0x11 | Data frame |
| STREAM_CLOSE | 0x12 | Graceful close |
| STREAM_RST | 0x13 | Reset stream |
| STREAM_WINDOW | 0x14 | Flow control update |
| HEARTBEAT | 0x20 | Keepalive ping |
| HEARTBEAT_ACK | 0x21 | Keepalive pong |
| GO_AWAY | 0xFE | Server shutdown notice |
| ERROR | 0xFF | Error frame |

### Stream Multiplexing

Multiple streams share a single TCP connection:

```
Client                              Server
  |                                   |
  |------- AUTH_REQ ----------------->|
  |<------ AUTH_RES ------------------|
  |                                   |
  |------- TUNNEL_REQ --------------->|  Create tunnel
  |<------ TUNNEL_RES ----------------|  myapp.wirerift.com
  |                                   |
  |------- STREAM_OPEN(1) ----------->|  Request #1
  |------- STREAM_DATA(1) ----------->|  Headers
  |<------ STREAM_DATA(1) ------------|  Response
  |------- STREAM_CLOSE(1) ---------->|
  |                                   |
  |------- STREAM_OPEN(2) ----------->|  Request #2
  |------- STREAM_DATA(2) ----------->|  Concurrent!
  |<------ STREAM_DATA(2) ------------|
```

## API Reference

The dashboard provides REST API endpoints at `http://localhost:4040/api`:

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/tunnels` | GET | List active tunnels |
| `/api/sessions` | GET | List connected sessions |
| `/api/stats` | GET | Server statistics |
| `/api/domains` | GET/POST | List/add custom domains |
| `/api/domains/{domain}` | GET/DELETE | Get/remove domain |
| `/api/domains/{domain}/dns` | GET | Get DNS records |
| `/api/domains/{domain}/verify` | POST | Verify domain |

All API endpoints require Bearer token authentication:

```bash
curl -H "Authorization: Bearer YOUR_TOKEN" http://localhost:4040/api/tunnels
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
│   ├── dashboard/         # Web dashboard
│   ├── mux/               # Stream multiplexing
│   ├── proto/             # Wire protocol
│   ├── ratelimit/         # Rate limiting
│   ├── server/            # Server implementation
│   └── tls/               # TLS certificate management
├── Makefile
└── README.md
```

## Development

```bash
# Run all tests
make test

# Run tests with coverage
make test-coverage

# Format code
make fmt

# Run linter
make lint

# Build all binaries
make build

# Clean build artifacts
make clean
```

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `WIRERIFT_SERVER` | Server address | `localhost:4443` |
| `WIRERIFT_TOKEN` | Authentication token | `""` |

## Server Options

```
Usage: wirerift-server [options]

Options:
  -control string
        Control plane address (default ":4443")
  -http string
        HTTP edge address (default ":80")
  -https string
        HTTPS edge address (default ":443")
  -dashboard-port int
        Dashboard port (default 4040)
  -domain string
        Base domain for tunnels (default "wirerift.com")
  -tcp-ports string
        TCP tunnel port range (default "20000-29999")
  -auto-cert
        Auto-generate self-signed certificates
  -cert-dir string
        Directory for certificates (default "certs")
  -v    Verbose logging
  -json
        JSON log format
```

## Client Options

```
Usage: wirerift <command> [options]

Commands:
  http <port> [subdomain]   Create an HTTP tunnel
  tcp <port>                Create a TCP tunnel
  start [config]            Start tunnels from config file
  list                      List active tunnels
  config                    Show/edit configuration
  version                   Show version

HTTP Options:
  -server string
        Server address (default "localhost:4443")
  -token string
        Authentication token
  -subdomain string
        Requested subdomain
  -whitelist string
        Comma-separated IP whitelist (e.g., "1.2.3.4,10.0.0.0/8")
  -pin string
        PIN protection for tunnel access
  -v    Verbose output
```

## Access Control

### IP Whitelist

Restrict tunnel access to specific IP addresses or CIDR ranges:

```bash
# Single IP
wirerift http 8080 -whitelist 203.0.113.50

# Multiple IPs and CIDR
wirerift http 8080 -whitelist "203.0.113.50,10.0.0.0/8,192.168.1.0/24"
```

Works for both HTTP and TCP tunnels. Non-whitelisted connections get `403 Forbidden` (HTTP) or are silently dropped (TCP).

### PIN Protection

Require a PIN code to access HTTP tunnels:

```bash
wirerift http 8080 -pin mysecret
```

PIN can be provided via:
- **Browser form** — auto-shown on first visit, sets HttpOnly cookie for 24h
- **HTTP Header** — `X-WireRift-PIN: mysecret` (ideal for API/CLI access)
- **Query parameter** — `?pin=mysecret` (auto-redirects to clean URL after cookie set)

## Security

- Token-based authentication for all connections
- TLS support for encrypted communication
- IP whitelist for tunnel-level access control
- PIN protection for sensitive tunnels
- Rate limiting per session
- Domain verification for custom domains
- Stream isolation with independent flow control

## License

MIT License — see [LICENSE](LICENSE)
