# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.4.1] - 2026-03-16

### Fixed
- **Token auth not working** — `auth.NewManager` now accepts user-defined token (`-token` flag > `WIRERIFT_TOKEN` env > auto-random)
- **`--double-dash` flags** — both `-token` and `--token` now work (Go's `flag` package only supports single dash)
- Server banner quick start command address formatting

### Added
- `-token` flag on server CLI to set a persistent auth token
- Server banner shows full connection info (control, HTTP, dashboard, domain) + copy-paste quick start command

## [1.4.0] - 2026-03-16

### Added
- **Health check endpoint** (`/healthz`) for load balancer and orchestrator integration
- **X-Request-ID header** for distributed request tracing (auto-generated or preserved from client)
- **JSON config file support** (`wirerift.json`) alongside YAML, with auto-fallback
- **CSP nonce-based security** on dashboard — each request gets a unique script nonce
- **Healthz benchmark** in benchmark suite
- **E2E tests** for healthz, X-Request-ID generation, X-Request-ID preservation
- **2500+ lines of new tests** across all packages
- Token banner display on server startup with copy-friendly format and export command

### Security
- **CRITICAL**: Replaced hardcoded HMAC key with per-instance `crypto/rand` secret for PIN cookies
- **CRITICAL**: Added `ReadHeaderTimeout`, `ReadTimeout`, `WriteTimeout`, `IdleTimeout` to all HTTP servers (Slowloris DoS prevention)
- **CRITICAL**: Fixed `sync.Map` race — empty `&Tunnel{}` placeholder replaced with atomic `LoadOrStore` of real tunnel
- **CRITICAL**: Fixed `mux.Close()` not called on auth failure — goroutine leak on failed connections
- Added `Content-Security-Policy` with per-request nonce to dashboard
- Added `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy` headers
- CSRF protection: session cookies restricted to GET-only requests on dashboard
- `Secure` flag on PIN cookies when served over HTTPS
- `MaxBytesReader` (1MB) on dashboard POST endpoints
- Generic `"Unauthorized"` error messages (no internal detail leakage)
- `gosec`, `bodyclose`, `noctx` linters added to CI

### Fixed
- **CRITICAL**: Reconnect mux race — `handleStreams` and `heartbeatLoop` now receive mux as parameter instead of reading shared `c.mux` field
- **CRITICAL**: Old mux goroutine leak on reconnect — old mux and connection are explicitly closed before creating new ones
- **HIGH**: `inspectResponseWriter` now implements `http.Flusher` and `http.Hijacker` — streaming and WebSocket tunnels work with `inspect=true`
- **HIGH**: Request log slice memory leak — backing array properly released via copy
- **HIGH**: Nil map panic in `handleTunnelClose` and `handleTunnelRequest` — nil checks added
- **HIGH**: Silent `Close()` errors on TLS certificate writes — `writeFileAtomic` helper checks close error
- **HIGH**: ACME `io.ReadAll` without size limit — bounded to 4MB
- **HIGH**: 6 ignored `json.Unmarshal` errors in ACME flow — all checked
- DNS case-insensitive subdomain matching (`extractSubdomain` lowercases input)
- `X-Forwarded-For` now strips port and chains with existing header
- `time.After` leak in reconnect loop replaced with `time.NewTimer` + `Stop()`
- `json.Encode` errors explicitly handled in dashboard responses
- ACME metadata write error now logged (was silently ignored)
- Non-deterministic domain verification codes — now stored at creation time

### Changed
- **Server architecture**: `server.go` (1575→1025 lines) split into `pin.go`, `inspect.go`, `http_edge.go`
- `handleTunnelRequest` (135 lines) refactored into `createHTTPTunnel`, `createTCPTunnel`, `sendTunnelError`
- `fmt.Sprintf("tcp:%d")` replaced with `strconv.Itoa` + string concatenation
- ACME operations accept `context.Context` for cancellation support
- `StartAutoRenewal` uses cancellable context derived from done channel
- `checkAndRenew` extracted as testable function from renewal loop
- `GetCertificate` uses `hello.Context()` for ACME request cancellation
- Client uses shared `http.Client` with connection pooling instead of per-request client
- `doServe` file server uses `http.Server.Shutdown` for graceful cleanup
- `recover()` added to all production goroutines (TCP proxy, webhook relay, ACME renewal, stream handler, dashboard)
- Graceful shutdown for HTTP/HTTPS edge servers via `http.Server.Shutdown`
- Removed dead code: no-op `init()`, misleading interface assertion, custom `min()` (Go 1.23 builtin)

### Infrastructure
- **Dockerfile**: `scratch` → `alpine:3.20` with CA certificates, non-root user, healthcheck
- **docker-compose.yml**: V2 format, TCP port range, healthcheck, command parameters
- **CI**: Added `golangci-lint` step, coverage artifact upload, threshold adjusted to 90%
- **Makefile**: Added `test-race`, `fuzz`, `docker`, improved `lint` targets
- **.golangci.yml**: Added `gosec`, `bodyclose`, `noctx`, `exportloopref` linters

### Test Coverage
| Package | Before | After |
|---------|--------|-------|
| internal/client | 100.0% | 100.0% |
| internal/config | 100.0% | 100.0% |
| internal/server | 94.2% | 99.7% |
| internal/tls | 74.4% | 97.4% |
| internal/dashboard | 99.2% | 99.3% |
| cmd/wirerift | 97.5% | 99.6% |
| Advanced E2E | 30/30 | 34/34 |

## [1.3.0] - 2026-03-16

### Added
- **Let's Encrypt ACME** - automatic HTTPS via HTTP-01 challenge, zero external dependencies
- ACME account key management (ECDSA P-256, persisted to disk)
- JWS signed requests per RFC 8555
- HTTP-01 challenge solver with automatic token serving on port 80
- Certificate auto-renewal (checks every 12h, renews 30 days before expiry)
- Certificate bundle storage with metadata (issued_at, expires_at, domains)
- Fallback chain: disk → ACME → self-signed
- CLI flags: `-acme-email` (enables ACME), `-acme-staging` (test server)
- 15 new ACME unit tests

## [1.2.0] - 2026-03-16

### Added
- **Basic Auth** for HTTP tunnels (`-auth user:pass`) with constant-time comparison
- **Custom Response Headers** (`-header "X-Robots:noindex,Cache-Control:no-store"`)
- **Traffic Inspector** - real-time request/response capture with dashboard UI
- **Request Replay** - replay any captured request from dashboard or API
- **File Server Mode** (`wirerift serve ./dist`) - serve static files through tunnel
- **Webhook Relay** - fan-out incoming requests to multiple local endpoints
- Dashboard Traffic Inspector panel with auto-refresh, filtering, and expandable details
- API endpoints: `GET /api/requests`, `POST /api/requests/{id}/replay`
- Config file support for `auth`, `inspect`, and `headers` per tunnel
- CLI flags: `-auth`, `-inspect`, `-header` for HTTP tunnels

## [1.1.1] - 2026-03-15

### Added
- Fuzz test suite: 6 fuzzers testing frame parser, JSON payload, magic bytes, HTTP response, subdomain extraction, IP whitelist (~52M inputs, 0 crashes)
- Advanced test suite: security (16), stress (5), reconnect (5), soak (4) = 30 tests
- Benchmark suite: HTTP latency/throughput/concurrency, TCP throughput, tunnel creation speed
- CI: race detector, fuzz tests, advanced tests, coverage threshold enforcement

## [1.1.0] - 2026-03-15

### Added
- IP whitelist for HTTP tunnels (`-whitelist 1.2.3.4,10.0.0.0/8`) - restrict tunnel access by IP/CIDR
- PIN protection for HTTP tunnels (`-pin 1234`) - require PIN to access tunnel via browser, header, or query param
- PIN challenge page with dark theme UI for browser-based access
- TCP tunnel whitelist enforcement (reject non-whitelisted IPs on TCP connections)
- `WithAllowedIPs()` and `WithPIN()` client library options
- Config file support for `whitelist` and `pin` per tunnel
- Dashboard "Protection" column showing IP/PIN indicators per tunnel
- `allowed_ips` and `has_pin` fields in `/api/tunnels` API response
- Rate limiter eviction to prevent memory leak from unique client IPs
- Working gzip compression middleware (was previously a no-op)
- Server-side bytes_in/bytes_out traffic tracking in Stats API
- Cryptographic domain verification codes (was previously deterministic)

### Security
- Fix: Mask dev token in server startup logs to prevent credential leakage
- Fix: Use constant-time comparison in BasicAuth to prevent timing attacks
- Fix: Eliminate modulo bias in random string generation (auth tokens, subdomains)
- Fix: Validate client-requested subdomains using `utils.IsValidSubdomain`
- Fix: Write TLS certificate files with 0600 permissions instead of 0666
- Fix: Write config files with 0600 permissions to protect tokens
- Fix: Check `pem.Encode` return values to prevent corrupt cert/key files on disk
- Fix: Remove deprecated `PreferServerCipherSuites` from TLS config
- Fix: PIN comparison now uses constant-time (`crypto/subtle`) to prevent timing attacks
- Fix: PIN cookie stores HMAC instead of raw PIN value (XSS mitigation)
- Fix: Stream ID 0 no longer collides with ControlStreamID (data streams start at ID 2)
- Fix: Server and dashboard now share the same auth manager (was creating separate instances)
- Fix: `IsValidSubdomain` rejects trailing hyphens per RFC 1123

### Fixed
- Fix: Add 10-second timeout to dashboard graceful shutdown (was unbounded)
- Fix: Cap ring buffer growth at 16 MB to prevent memory exhaustion from malicious clients
- Fix: Limit `io.ReadAll` calls to 64 MB (responses) and 32 MB (request bodies)
- Fix: Eliminate port allocation race condition using modulo wrap-around
- Fix: Add `sync.RWMutex` to Stream metadata to prevent data races
- Fix: Generate unique request IDs using `crypto/rand` (was deterministic constant)
- Fix: Validate port range (1-65535) in client CLI commands
- Fix: Handle `local_port` parse errors in config file instead of silently defaulting to 0
- Fix: Add 30-second timeout to HTTP client in tunnel proxy to prevent goroutine leaks
- Fix: Correct Prometheus metrics format (`# TYPE` lines now include metric names)
- Fix: CORS preflight now returns 403 for non-allowed origins instead of 204
- Fix: `Server.StartTime()` now uses instance field instead of package-level variable
- Fix: `handleSignals` goroutine no longer leaks on normal context cancellation
- Fix: Log warning on TCP proxy stream open failure instead of silent drop
- Fix: Handle `io.ReadAll` error in client `list` command
- Fix: Add rate limiter eviction (every 5min, stale after 10min) to prevent memory leak from unique IPs
- Fix: Dashboard token storage moved from localStorage to sessionStorage (XSS mitigation)
- Fix: Clipboard error handling in website Hero and CTA components
- Fix: SPA redirect URL parsing wrapped in try/catch to prevent crash on malformed URLs
- Fix: Internal doc links converted from `<a>` to React Router `<Link>` (prevents full page reloads)
- Fix: ThemeToggle exit animation now works with AnimatePresence wrapper
- Fix: Loading spinner now has accessible `role="status"` and screen reader text
- Fix: `ringBuffer.growLocked` no longer computes length with stale pointers after resize
- Fix: `-tcp-ports` flag now properly parsed (was hardcoded to 20000-29999)
- Fix: Port allocation no longer skips first port in range (off-by-one)
- Fix: Domain verification code now includes domain prefix + crypto random (was ignoring domain)
- Fix: Dockerfile no longer references non-existent `go.sum`, exposes port 4443
- Fix: README corrected HTTPS URLs to HTTP (HTTPS requires explicit TLS config)
- Fix: README "100% Test Coverage" claim replaced with accurate description

### Removed
- Dead code: `internal/metrics/` package (364 LOC, never imported)
- Dead code: `internal/middleware/` package (872 LOC, never imported)
- Dead code: `internal/version/` package (71 LOC, never imported)
- Dead code: `HTTPProxy`, `TCPProxy`, `TCPTunnel`, `bidiCopy` structs and 6 unused types in proxy files
- Dead code: 15 unused error sentinels across 6 packages
- Dead code: 6 unused utility functions, `TunnelMetadata` struct, redundant getters
- Dead code: `CopyButton.tsx`, `SocialLink` constant, unused assets
- Total: ~3,100 lines of dead code removed, codebase reduced by ~15%

## [1.0.1] - 2026-03-01

### Added
- Initial project scaffolding

## [1.0.0] - 2026-02-15

### Added
- Initial release
