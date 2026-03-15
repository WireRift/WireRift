# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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

## [1.0.1] - 2026-03-01

### Added
- Initial project scaffolding

## [1.0.0] - 2026-02-15

### Added
- Initial release
