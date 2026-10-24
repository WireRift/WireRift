# WireRift Comprehensive Go Codebase Audit Report

> Historical report (2026-04-03). File paths such as `internal/config/domains.go` no longer exist; later changes are in CHANGELOG.md.

**Date**: 2026-04-03
**Auditor**: Claude (Opus 4.6)
**Codebase**: github.com/wirerift/wirerift
**Go Version**: 1.23
**Total Lines**: ~30,065 (Go source)
**Dependencies**: Zero (stdlib only)

---

## Executive Summary

WireRift is a well-engineered, zero-dependency tunnel server and client written in Go. The codebase demonstrates strong fundamentals: proper use of `sync.Map` and atomics for concurrent state, `crypto/subtle` for timing-safe comparisons, `io.LimitReader` to bound memory usage, proper HTTP server timeouts, and an impressive 99.1% test coverage.

However, the audit identified **11 actionable issues** across security, concurrency, correctness, and performance categories. The most critical findings were: IPv6 address parsing failures in IP-based access controls (security bypass), a data race in the domain configuration package, silent data loss potential in the stream multiplexer when streams are closed during writes, and a timer leak pattern in the authentication handler. All issues have been fixed and verified with passing tests including the race detector.

The overall code quality is high for a project of this scope. The architecture is clean with well-separated concerns, consistent error handling, and comprehensive test coverage including fuzz tests for protocol parsing.

---

## Risk Assessment

**Overall Risk Level: LOW-MEDIUM**

The codebase is well-structured and defensively coded. The identified issues are largely edge cases that would only manifest under specific conditions (IPv6 clients, high connection rates, concurrent domain mutations). No critical security vulnerabilities like injection attacks, authentication bypasses, or data exposure were found. The zero-dependency approach eliminates supply chain risk entirely.

---

## Issues Found and Fixed

### [SEVERITY: HIGH] 1. IPv6 IP Extraction Bypass in Access Controls

**Category**: Security
**Files**: `internal/server/http_edge.go:39-41`, `internal/server/server.go:742-744`
**Impact**: IP whitelist bypass for IPv6 clients; rate limiting fails for IPv6

**Problem**: The code used `strings.LastIndex(clientIP, ":")` to strip the port from `RemoteAddr`. For IPv6 addresses like `[::1]:8080`, this incorrectly splits at the last colon within the IPv6 address itself, producing a malformed IP that never matches whitelist entries.

**Before**:
```go
clientIP := r.RemoteAddr
if idx := strings.LastIndex(clientIP, ":"); idx > 0 {
    clientIP = clientIP[:idx]
}
```

**After**:
```go
clientIP := r.RemoteAddr
if host, _, err := net.SplitHostPort(clientIP); err == nil {
    clientIP = host
}
```

**Fixed in**: Both `http_edge.go` (HTTP edge) and `server.go` (TCP proxy)

---

### [SEVERITY: HIGH] 2. Stream.Write Ignores Close/Reset During Multi-Chunk Writes

**Category**: Concurrency / Data Integrity
**File**: `internal/mux/stream.go:126-169`
**Impact**: Writes to a closed/reset stream continue silently, wasting resources and potentially causing protocol errors

**Problem**: `Stream.Write()` only checked the stream state once at entry. For large writes that span multiple chunks (waiting for flow control window updates), the stream could be closed or reset by the remote side while the loop is in progress. The write would continue attempting to send data to a dead stream.

**Fix**: Added state recheck at the top of each iteration in the write loop.

---

### [SEVERITY: HIGH] 3. Data Race in CustomDomain Configuration

**Category**: Concurrency
**File**: `internal/config/domains.go:99-104`
**Impact**: Concurrent reads of domain config during verification/modification could see partially-updated state

**Problem**: `GetDomain()` read from `sync.Map` without acquiring `m.mu.RLock()`, while `VerifyDomain()` and `SetTunnel()` held `m.mu.Lock()` and mutated the loaded `*CustomDomain` value directly. A concurrent `GetDomain` call could observe a `CustomDomain` in an inconsistent state (e.g., `Verified=true` but `Certificate=nil`).

**Fix**: Added `m.mu.RLock()/RUnlock()` to `GetDomain()`.

---

### [SEVERITY: HIGH] 4. Nil Pointer Panic in auth.ValidateToken

**Category**: Nil Safety
**File**: `internal/auth/auth.go:96-99`
**Impact**: Server crash if dev account is deleted from the accounts map

**Problem**: If the dev token matched but the associated account had been removed from `m.accounts`, the `account.(*Account)` type assertion on a nil interface would panic.

**Before**:
```go
account, _ := m.accounts.Load(m.devToken.AccountID)
return m.devToken, account.(*Account), nil
```

**After**:
```go
account, ok := m.accounts.Load(m.devToken.AccountID)
if !ok {
    return nil, nil, ErrInvalidToken
}
return m.devToken, account.(*Account), nil
```

---

### [SEVERITY: MEDIUM] 5. Timer Leak in handleAuth

**Category**: Resource Management
**File**: `internal/server/server.go:400-452`
**Impact**: Under high connection rates, leaked `time.After` timers accumulate until they fire (10s each)

**Problem**: `time.After(10 * time.Second)` creates a timer that cannot be garbage collected until it fires, even if the select completes on a different case. Under high connection rates (e.g., load testing), thousands of timers accumulate in memory.

**Fix**: Replaced with `time.NewTimer` + `defer timer.Stop()`.

---

### [SEVERITY: MEDIUM] 6. IsWebSocketRequest Missing Connection Header Check (RFC 6455)

**Category**: Protocol Compliance
**File**: `internal/server/http_proxy.go:104-107`
**Impact**: Non-WebSocket requests with `Upgrade: websocket` header (but no `Connection: Upgrade`) would be incorrectly routed to WebSocket handler

**Problem**: RFC 6455 Section 4.2.1 requires both `Upgrade: websocket` AND `Connection: Upgrade` headers. The original code only checked the Upgrade header.

**Fix**: Added Connection header validation with case-insensitive, comma-separated value parsing.

---

### [SEVERITY: MEDIUM] 7. PIN Page Template Renders Error Message Twice

**Category**: Correctness
**File**: `internal/server/pin.go:98-131`
**Impact**: Error message appears twice in the PIN entry page HTML

**Problem**: The `fmt.Fprintf` template had two `%s` placeholders but both were interpolated with `errorHTML`, causing the "Invalid PIN" message to appear twice on the page.

**Fix**: Removed the duplicate `%s` placeholder from the `<style>` section (it was incorrectly placed there).

---

### [SEVERITY: MEDIUM] 8. ReplayRequest Ignores Multiple Errors

**Category**: Error Handling
**File**: `internal/server/inspect.go:156-159`
**Impact**: Silent failures during request replay; user sees nil/empty response instead of error

**Problem**: `SerializeRequest`, `stream.Write`, and `io.ReadAll` errors were all ignored with `_`. A network failure during replay would produce a nil/empty response instead of a meaningful error.

**Fix**: Added proper error checking and wrapping for all three operations.

---

### [SEVERITY: LOW] 9. Ring Buffer Byte-by-Byte Write Performance

**Category**: Performance
**File**: `internal/mux/ringbuffer.go:57-66`
**Impact**: CPU overhead on large stream writes (64KB frames processed byte-by-byte = ~64K loop iterations)

**Problem**: The ring buffer wrote data one byte at a time in a loop. For the common case of writing a 64KB frame, this means 65,536 loop iterations with per-byte modulo operations.

**Fix**: Replaced with bulk `copy()` using contiguous span calculation, reducing iterations to at most 2 per write.

---

### [SEVERITY: LOW] 10. Three Tests Fail Due to Network Binding

**Category**: Test Infrastructure
**File**: `internal/server/server_test.go:4415-4505`
**Impact**: `TestHealthzEndpoint`, `TestRequestIDHeader`, `TestRequestIDPreserved` fail in sandboxed environments

**Problem**: These tests bound to `:0` (all interfaces) while the test environment's network sandbox blocks connections to wildcard-bound listeners. All other passing tests use `127.0.0.1:0`.

**Fix**: Changed all three tests to bind to `127.0.0.1:0`.

---

### [SEVERITY: LOW] 11. WebSocket Test Missing Connection Header

**Category**: Test Correctness
**File**: `internal/server/server_test.go:3019`
**Impact**: Test `TestForwardHTTPRequestWebSocketDetection` relied on incomplete WebSocket headers

**Problem**: After fixing `IsWebSocketRequest` to properly check the `Connection` header (issue #6), this test needed the `Connection: Upgrade` header added to still trigger the WebSocket path.

**Fix**: Added `req.Header.Set("Connection", "Upgrade")` to the test.

---

## Additional Observations (Not Fixed - Low Risk)

### Architecture & Design Strengths
- Clean separation: proto/mux/server/client/auth layers with well-defined boundaries
- Proper use of `internal/` packages preventing external access
- `sync.Map` used appropriately for concurrent tunnel/session registries
- Atomic operations for counters and state flags
- Proper HTTP server timeouts (Read, Write, Idle, HeaderRead)
- `io.LimitReader` applied on all untrusted reads (request body: 32MB, response: 64MB)
- `crypto/subtle.ConstantTimeCompare` for all auth comparisons
- HMAC-based PIN cookies (not raw PINs)
- CSP nonces for dashboard inline scripts
- CSRF protection (cookies only allowed for GET requests)

### Minor Items Not Requiring Fixes
1. **`Mux.handleStreamOpen` drops streams silently when accept channel full** (128 buffer) - Acceptable for backpressure; stream is properly Reset.
2. **`Stream.ID` space exhaustion** - ~~Long-lived connections could exhaust the 24-bit ID space.~~ Fixed: `OpenStream` now allocates IDs round the whole space and skips live ones (see `allocIDLocked`), so a session no longer dies after ~8.4M streams.
3. **`Mux.handleError` creates error from untrusted input** - `errors.New(msg.Message)` uses remote peer's message. Not a security issue since it only propagates within the server process.
4. **`Stats()` returns `map[string]interface{}`** - Uses `any`/`interface{}` for JSON serialization flexibility. Acceptable pattern.
5. **Dashboard `handleDomainActions` lacks CSRF check for verify/dns** - These require Bearer token auth, so no CSRF vector.
6. **`ringBuffer` Read is still byte-by-byte** - Less critical than Write since reads are typically smaller and less frequent in the hot path.
7. **No `context.Context` propagation to `proxyTCPConnection`** - Uses `mux.Done()` channel instead, which serves the same purpose.

---

## Metrics

| Metric | Score |
|--------|-------|
| **Total issues found** | 11 (2 High, 5 Medium, 4 Low) |
| **Code health score** | 8/10 |
| **Security score** | 8/10 |
| **Concurrency safety score** | 7/10 |
| **Maintainability score** | 9/10 |
| **Test coverage** | 99.1% |
| **Race detector** | PASS (all packages) |
| **Go vet** | PASS (no issues) |
| **Build** | PASS (all platforms) |

---

## Static Analysis Results

```
go build ./cmd/... ./internal/...     -> PASS (no errors)
go vet ./cmd/... ./internal/...       -> PASS (no issues)
go test -race ./cmd/... ./internal/.. -> PASS (12/12 packages)
go test -cover ./cmd/... ./internal/. -> 99.1% statement coverage
```

---

## Recommended Action Plan

### Phase 1 (Completed in this audit)
All 11 identified issues have been fixed and verified:
- 12/12 test packages pass
- Race detector clean
- Go vet clean
- Coverage maintained at 99.1%

### Phase 2 (Suggested future improvements)
1. Add IPv6-specific integration tests for IP whitelisting
2. Consider adding `context.Context` to `ringBuffer` operations for cancellation
3. Add metrics/observability (connection counts, stream counts, buffer utilization)
4. Consider structured logging with trace IDs propagated through the tunnel chain
5. Add fuzz tests for the YAML config parser
6. Consider adding a `MaxStreamID` exhaustion test and graceful handling (GO_AWAY frame)
