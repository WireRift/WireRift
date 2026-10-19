# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What is WireRift

WireRift is a zero-dependency, self-hosted tunnel server and client written in Go (like ngrok). It exposes local services to the internet through secure tunnels over a custom binary multiplexing protocol. Module: `github.com/wirerift/wirerift`, requires Go 1.23+.

## Build & Test Commands

```bash
# Build
go build -o bin/wirerift-server ./cmd/wirerift-server
go build -o bin/wirerift ./cmd/wirerift
make build                    # builds both to bin/

# Test
go test ./cmd/... ./internal/... ./test/integration/ -timeout 120s   # all unit + integration
go test -race ./cmd/... ./internal/... -timeout 180s                 # race detector
go test ./internal/proto/ -run TestReadFrame                         # single test
go test ./internal/mux/... -v                                        # single package verbose
go test -cover ./cmd/... ./internal/...                              # coverage

# Fuzz
go test -fuzz=FuzzReadFrame -fuzztime=30s ./internal/proto/

# Lint
go vet ./cmd/... ./internal/...
golangci-lint run ./cmd/... ./internal/...   # config in .golangci.yml

# Advanced E2E (not go test — runs as a binary)
go run ./test/advanced/
go run ./test/benchmark/

# Cross-compile all platforms
make release
```

**Important:** The `website/` directory is excluded from all Go commands (tests, lint, build). Always use `./cmd/... ./internal/...` or the Makefile's `$(PACKAGES)` variable, never `./...`.

## Architecture

### Two Binaries

- **`cmd/wirerift-server/`** — Server: accepts client connections on control plane (:4443), runs HTTP edge (:80/:443), dashboard (:4040), and allocates TCP tunnel ports.
- **`cmd/wirerift/`** — Client CLI: connects to server, authenticates, creates tunnels, forwards local traffic.

### Wire Protocol (`internal/proto/`)

Custom binary protocol. Magic bytes `WRF\x01`, 9-byte frame header (version + type + 3-byte stream ID + 4-byte length), max 16MB payload. Frame types: control (auth, tunnel req/res), stream (open/data/close/rst/window), heartbeat, error. Messages are JSON-encoded payloads inside frames. `FrameWriter` is mutex-protected for thread safety.

### Stream Multiplexer (`internal/mux/`)

Carries multiple streams over a single TCP connection. Flow control via window-based backpressure (`DefaultWindowSize` = 256KB). Uses `sync.Map` for stream tracking, `RingBuffer` for buffering, atomic operations for heartbeat/ID tracking. Streams implement `net.Conn` interface.

### Server (`internal/server/`)

- `server.go` — Core: session management, tunnel registry, control plane listener, heartbeat monitoring
- `http_edge.go` — HTTP routing: extracts subdomain from Host header, looks up tunnel, proxies request through multiplexed stream
- `http_proxy.go` — Request/response serialization over the wire protocol
- `tcp_proxy.go` — Raw TCP bidirectional copy between stream and client
- `pin.go` — PIN protection with HMAC cookies
- `inspect.go` — Traffic capture for the inspector/replay feature
- `customdomain.go` — Custom domains: stateless DNS TXT ownership proof (HMAC), validation, alias registry keys (`domain:<name>`)
- `errorpage.go` — HTML error pages for browsers, plain text for API clients

### Client (`internal/client/`)

Connects to server, performs magic+auth handshake, creates tunnels. Auto-reconnects with exponential backoff (1s-30s). For HTTP tunnels, deserializes requests from streams and forwards to local service via `http.Transport`.

### Supporting Packages

- `internal/auth/` — Token validation with constant-time comparison
- `internal/dashboard/` — Embedded web UI (`embed.FS` for static files), REST API, CSP nonce-based security
- `internal/tls/` — ACME (Let's Encrypt) certificate management, self-signed cert generation, and the persistent name-constrained local dev CA (`localca.go`) with trust-store install/removal (`trust.go`) used by `wirerift-server -dev` / `ca` subcommands
- `internal/ratelimit/` — Token bucket (per-IP) and sliding window (per-session) rate limiters

## Key Conventions

- Zero external dependencies — stdlib only (no third-party modules in go.mod).
- All `internal/` packages have `_test.go` files with high coverage (CI enforces >90%).
- Fuzz tests exist for protocol parsing (`proto/`), HTTP deserialization (`server/`), and subdomain extraction.
- `test/advanced/` and `test/benchmark/` are standalone binaries (run with `go run`), not `go test`.
- The linter config (`.golangci.yml`) suppresses `G104` (deferred close errors) and `G114` (http.ListenAndServe) via gosec excludes.
- CI runs on all three platforms (Linux, macOS, Windows).
- Version is injected via `-ldflags "-X main.version=..."` at build time.
