# Test Coverage Analysis

**Date:** 2026-03-17
**Total Coverage:** 81.0% (statements, excluding test helpers in `test/`)
**All tests passing:** Yes (3 previously failing tests fixed)

---

## Per-Package Coverage

| Package | Coverage | Status |
|---------|----------|--------|
| `internal/client` | 100.0% | Excellent |
| `internal/config` | 100.0% | Excellent |
| `internal/mux` | 100.0% | Excellent |
| `internal/proto` | 100.0% | Excellent |
| `internal/ratelimit` | 100.0% | Excellent |
| `internal/utils` | 100.0% | Excellent |
| `cmd/wirerift` | 99.2% | Excellent |
| `internal/dashboard` | 99.3% | Excellent |
| `internal/server` | 98.7% | Excellent |
| `internal/auth` | 98.2% | Very Good |
| `internal/tls` | 97.2% | Very Good |
| `cmd/wirerift-server` | 92.4% | Good |

---

## Recommended Areas for Improvement

### Priority 1: Missing Dedicated Test Files

These source files have **no dedicated test file**. While some of their functions are exercised indirectly through `server_test.go`, they lack focused unit tests for edge cases and error paths.

#### 1. `internal/server/http_proxy.go` — HTTP Serialization/Deserialization

**Key untested functions:**
- `SerializeRequest()` — Serializes HTTP requests with X-Forwarded-* headers (32MB body limit)
- `DeserializeResponse()` — Parses HTTP responses from tunneled data
- `WriteResponse()` — Writes HTTP response back to client
- `IsWebSocketRequest()` — WebSocket upgrade detection

**Suggested tests:**
- Serialize/deserialize round-trip with various HTTP methods, headers, and body sizes
- Edge cases: empty body, body at 32MB limit, body exceeding limit
- Malformed response data handling in `DeserializeResponse`
- `X-Forwarded-For`, `X-Forwarded-Proto` header injection
- WebSocket detection with various `Upgrade` header values

#### 2. `internal/server/inspect.go` — Traffic Inspection & Replay

**Key untested functions:**
- `inspectResponseWriter` — Wrapped response writer capturing status/headers
- `logRequest()` — Request/response logging for traffic inspector
- `GetRequestLogs()` — Filtered log retrieval with limit
- `ReplayRequest()` — Request replay by ID
- `getTunnelByID()` — Tunnel lookup helper

**Suggested tests:**
- `inspectResponseWriter.WriteHeader()` captures status correctly
- `inspectResponseWriter.Flush()` and `Hijack()` interface delegation
- Log storage and retrieval with tunnel ID filtering
- Request replay re-execution and result storage
- Concurrent access to request logs

#### 3. `internal/server/pin.go` — PIN Protection

**Key untested functions:**
- `pinMAC()` — HMAC-SHA256 computation for cookie storage
- `pinMatch()` — Constant-time PIN comparison
- `checkPIN()` — Full PIN validation flow (cookies, headers, query params, form POST)
- `servePINPage()` — HTML PIN entry page rendering

**Suggested tests:**
- HMAC computation correctness and consistency
- Constant-time comparison (correct PIN, wrong PIN, empty PIN)
- PIN validation via cookie, header, query parameter, and POST form
- Cookie setting after successful PIN entry
- PIN page HTML rendering with error states

#### 4. `internal/server/tcp_proxy.go` — TCP Tunnel Proxying

**Key untested functions:**
- `StreamOpenForTCP()` — Creates STREAM_OPEN frame for TCP connections
- `StreamOpenForHTTP()` — Creates STREAM_OPEN frame for HTTP connections

**Suggested tests:**
- Frame construction with various tunnel IDs and stream IDs
- Correct metadata encoding (remoteAddr, protocol)

#### 5. `internal/server/http_edge.go` — HTTP Edge Handler (partially tested)

**Tested indirectly** through integration-style tests, but missing unit tests for:
- `extractSubdomain()` edge cases (already has fuzz tests, but no unit tests for IPv6 hosts, unusual port formats)
- `isIPAllowed()` with CIDR ranges, IPv6, malformed IPs
- `checkBasicAuth()` with edge cases (empty credentials, unicode)
- `forwardWebSocket()` — WebSocket upgrade and bidirectional copy

#### 6. `internal/mux/stream.go` — Stream Lifecycle (partially tested)

Tested indirectly via `mux_test.go`, but missing dedicated tests for:
- Stream state machine transitions (Open → HalfClosedLocal → Closed, etc.)
- `onResetFrame()` and `Reset()` abort behavior
- `SetMetadata()` propagation
- Concurrent Read/Write during close
- Window update signaling under flow control pressure

---

### Priority 2: Functions with Low Coverage

| Function | File | Coverage | Gap |
|----------|------|----------|-----|
| `handleTunnelRequests` | `server.go:457` | 66.7% | Heartbeat-based LastSeen update path |
| `normalizeArgs` | `wirerift-server/main.go:36` | 73.7% | Uncommon CLI argument patterns |
| `NewManager` | `auth.go:57` | 81.8% | `WIRERIFT_TOKEN` env var path |
| `normalizeArgs` | `wirerift/main.go:126` | 84.2% | Edge case argument normalization |
| `StartAutoRenewal` | `acme.go:684` | 85.7% | Renewal ticker loop, panic recovery |
| `ListSessions` | `server.go:957` | 91.7% | Session listing edge cases |
| `handleRequestActions` | `dashboard.go:282` | 92.9% | Dashboard action edge cases |
| `generateSelfSigned` | `certs.go:159` | 92.3% | Certificate generation error paths |
| `NewManager` | `certs.go:64` | 93.8% | TLS manager init edge cases |
| `loadOrCreateKey` | `acme.go:556` | 93.3% | Key file I/O error paths |

**Key recommendations:**
- **`handleTunnelRequests` (66.7%):** Add tests for the heartbeat ticker path that updates `session.LastSeen` from mux heartbeat timestamps. This is critical for session keepalive correctness.
- **`normalizeArgs` (73.7% / 84.2%):** Add tests for unusual CLI flag formats (e.g., `--flag=value`, short flags, combined flags).
- **`NewManager` in auth (81.8%):** Test the `WIRERIFT_TOKEN` environment variable fallback path.
- **`StartAutoRenewal` (85.7%):** Test renewal trigger timing and graceful shutdown via `done` channel.

---

### Priority 3: Structural Testing Gaps

#### Integration Tests
- `test/integration/integration_test.go` exists but reports `[no statements]` — it doesn't measure coverage of internal packages. Consider restructuring to provide end-to-end coverage metrics.

#### Benchmark & Advanced Tests
- `test/benchmark/main.go` and `test/advanced/main.go` are standalone executables (not `_test.go` files), so they don't contribute to coverage and aren't run by `go test`. Consider converting to proper Go benchmarks and test functions.

#### Missing Test Categories
- **Concurrency tests:** The mux, server, and stream packages handle concurrent operations but have limited race-condition-focused tests. Running with `-race` is good but targeted concurrent tests would catch more issues.
- **Error injection tests:** Many error paths (network failures, I/O errors, malformed frames) are difficult to reach. Consider adding interfaces or test hooks for fault injection.

---

## Fixed Issues

Three tests in `internal/server` were failing due to binding to `:0` (all interfaces) instead of `127.0.0.1:0` (loopback only), which was rejected by the test environment:

- `TestHealthzEndpoint` — Got 403 "Access denied: private_ipv4_blocked"
- `TestRequestIDHeader` — X-Request-ID header not set (request blocked before handler)
- `TestRequestIDPreserved` — Same root cause

**Fix:** Changed `cfg.ControlAddr` and `cfg.HTTPAddr` from `":0"` to `"127.0.0.1:0"` to match the convention used by all other server tests.
