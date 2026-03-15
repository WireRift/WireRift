# WireRift — Branding & Identity

## Name

**WireRift** — Tear a rift through the wire. Expose localhost to the world.

- **Wire** = network, connection, data pathway
- **Rift** = opening, gateway, a tear in the fabric that lets things pass through
- Together: "opening a rift in the network" — your local service becomes publicly accessible

## Writing Style

| Context | Usage |
|---------|-------|
| Title case | WireRift |
| Code / CLI | `wirerift` |
| Server binary | `wirerift-server` |
| Go module | `github.com/wirerift/wirerift` |
| Docker image | `wirerift/wirerift-server` |
| Config file | `.wirerift.toml` |
| Env prefix | `WIRERIFT_` |
| Subdomain | `*.wirerift.com` |
| Hashtag | #wirerift |

**Never:** Wire-Rift, Wire Rift, wire_rift, WIRERIFT (in prose)

## Taglines (pick per context)

- **Primary:** Tear a rift through the wire.
- **Technical:** Zero-dependency tunnels. Single binary. Self-hosted.
- **Developer:** Expose localhost to the world in one command.
- **Short:** Open source tunnels, zero dependencies.

## CLI Examples (for README / docs)

```bash
# Expose a local HTTP server
wirerift http 3000

# With custom subdomain
wirerift http 3000 --subdomain myapp
# → https://myapp.wirerift.com

# Expose a TCP service (e.g., PostgreSQL)
wirerift tcp 5432
# → tcp://wirerift.com:20001

# Start from config file
wirerift start

# Server management
wirerift-server start
wirerift-server token create --name ersin
```

## Protocol Identity

| Field | Value |
|-------|-------|
| Magic bytes | `0x57 0x52 0x46` (`WRF`) |
| Version byte | `0x01` |
| Full magic | `WRF\x01` (4 bytes) |

## Terminal Banner

```
┌──────────────────────────────────────────────────────┐
│  WireRift v1.0.0                                     │
│                                                      │
│  Dashboard:  http://127.0.0.1:4040                   │
│  Session:    sess_a1b2c3d4                           │
│                                                      │
│  Tunnel      Public URL                     Local    │
│  ─────────── ───────────────────────────── ────────  │
│  http        https://myapp.wirerift.com     :3000    │
│  tcp         tcp://wirerift.com:20001       :5432    │
│                                                      │
│  Connections: 0     Bytes In: 0 B    Bytes Out: 0 B  │
└──────────────────────────────────────────────────────┘
```

## Project Structure

```
wirerift/
├── cmd/
│   ├── wirerift-server/
│   │   └── main.go
│   └── wirerift/
│       └── main.go
├── internal/
│   ├── proto/
│   ├── mux/
│   ├── server/
│   ├── client/
│   ├── auth/
│   ├── tls/
│   ├── config/
│   ├── ratelimit/
│   └── cli/
├── dashboard/dist/
├── go.mod          → github.com/wirerift/wirerift
├── go.sum          → empty (zero deps!)
├── Makefile
├── Dockerfile
├── SPECIFICATION.md
├── IMPLEMENTATION.md
├── TASKS.md
├── README.md
├── CHANGELOG.md
└── LICENSE (MIT)
```

## GitHub

- **Org:** github.com/wirerift
- **Repo:** github.com/wirerift/wirerift
- **Topics:** `tunnel`, `ngrok-alternative`, `self-hosted`, `golang`, `zero-dependency`, `reverse-proxy`, `tcp-tunnel`, `http-tunnel`
- **Description:** Open-source, zero-dependency tunnel server and client. Expose localhost to the world with a single binary. Written in Go.

## Metrics Prefix

All Prometheus metrics use `wirerift_` prefix:
- `wirerift_active_sessions`
- `wirerift_active_tunnels{type="http|tcp"}`
- `wirerift_requests_total{status_class="2xx|3xx|4xx|5xx"}`
- `wirerift_bytes_transferred_total{direction="in|out"}`

## Positioning vs Competitors

| | ngrok | frp | bore | WireRift |
|---|---|---|---|---|
| Open source | No (v2+) | Yes | Yes | Yes |
| Zero deps | N/A | No | No (Rust) | **Yes** |
| Single binary | Yes | Yes | Yes | **Yes** |
| Self-hosted | Paid | Yes | Yes | **Yes** |
| HTTP inspect | Yes | No | No | **Yes** |
| Custom domains | Paid | Yes | No | **Yes** |
| TCP tunnels | Yes | Yes | Yes | **Yes** |
| Auto TLS | Yes | No | No | **Yes** |
| WebSocket | Yes | Yes | No | **Yes** |
| Dashboard | Paid | Basic | No | **Yes** |
