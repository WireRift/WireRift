# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.29.0] - 2026-11-11

### Changed
- Inspector: filter chips (All, 2xx, 3xx, 4xx, 5xx, Slow = 500 ms or more) and a duration bar on every row, amber for slow requests.
- Tunnels: the URL of an HTTP tunnel is a link, the type is a pill, and the age is relative.
- Narrow screens: the tab bar scrolls sideways instead of overflowing, and the keyboard hints are hidden.

### Fixed
- The dashboard script defined `fmtAgo` and `fmtUptime` twice; the duplicates are removed.

## [1.28.0] - 2026-11-11

### Changed
- The Admin tab is rebuilt as a console: a status summary that names what needs attention (not ready, certificate expiry, write errors, many open files, a high 5xx share, held names), metric tiles with sparklines for traffic and capacity, one interactive chart of the last hour (requests split into OK / 4xx / 5xx, or traffic in / out; hover for exact values; a table view), a response-time histogram with the slowest 5% marked, a status-class bar, and an account card per account with limit meters, traffic share, and New token / Set password shortcuts. The section bar highlights where you are. IDs use a monospace face; the token and password cards line up.

## [1.27.0] - 2026-11-11

### Added
- `-dashboard-allow`: addresses or CIDR ranges that may reach the dashboard at all (everyone else gets 403 before the sign-in page). Direct loopback access (an SSH tunnel to the local port) always works; a malformed entry stops the server from starting.

## [1.26.2] - 2026-11-11

### Fixed
- Dashboard: an unknown dashboard session key (sessions are in memory, so a restart ends them all) no longer counts as a failed sign-in attempt. A browser tab left open with an ended session could still poll fast enough to lock its owner's IP out.

## [1.26.1] - 2026-11-10

### Fixed
- Dashboard: a tab whose session was rejected (for example after a server restart, sessions are in memory) kept polling with the dead session, and every failed request counted toward the IP's sign-in lockout, so the user could not sign in again. The page now stops polling and shows the sign-in screen.

## [1.26.0] - 2026-11-10

### Added
- Admin: the Accounts table shows each account's requests and traffic (in / out) since the server started. TCP connections count as one request each.
- Activity: filter chips (All, Warnings, Auth, Sessions, Tunnels, Admin, Server) next to the search box; warnings are highlighted.

### Changed
- The four top counters are hidden on the Admin tab, where the health cards already show the same numbers.

## [1.25.0] - 2026-11-09

### Changed
- Admin tab: a sticky section bar (Health, Last hour, Accounts, Tokens, Sessions, Reserved, Certificates, Configuration), filter boxes for tokens and sessions, relative times ("4m ago", full time on hover), a *New token* button on every account row, and the token and password forms side by side and open by default. Health cards use two columns on phones. Password fields now match the other inputs.

## [1.24.0] - 2026-11-08

### Added
- The dashboard's activity log and one-hour history now survive a restart (`<cert-dir>/state.json`, saved every minute and on stop, mode 0600; entries older than 24 hours are dropped). Captured request bodies are not persisted.

## [1.23.0] - 2026-11-08

### Added
- Dashboard: sign in with a username (the account name) and a password instead of a token. Set passwords in the Admin tab or with `wirerift-server token passwd`. Salted PBKDF2-HMAC-SHA256 hashes in `tokens.json`; 12-hour in-memory sessions; same lockout as wrong tokens; a new password ends the account's sessions.

## [1.22.0] - 2026-11-08

### Added
- `wirerift ui`: saved tunnels. Save the form under a name, then open, edit, delete or open all of them with one click. They survive restarts and *Forget saved login*.

## [1.21.1] - 2026-11-08

### Fixed
- Dashboard: revoking the last active admin token is refused (HTTP 409), so the Admin tab can no longer lock itself out. The freshly created token is scrolled into view.

## [1.21.0] - 2026-11-07

### Added
- `wirerift ui`: the client's web interface. Set the server and token (optionally remembered in an owner-only file), connect and disconnect, open and close web and TCP tunnels from a form, and watch the traffic that passes through them live: method, path, status, time, sizes, visitor address, request/response headers and bodies, **Replay** to the local app, copy as `curl`. Loopback only, with a per-run key in the printed address and Host/Origin checks against DNS rebinding and cross-site requests.
- Client library: `Config.OnExchange` and `Config.CaptureBody` report each relayed exchange (HTTP, WebSocket, TCP) with headers, captured bodies, timing and the local error when the app did not answer; `Client.Tunnels()` lists the open tunnels. Without a callback nothing changes.

## [1.20.0] - 2026-11-07

### Added
- Admin tab **Access tokens**: list, create and revoke tokens from the dashboard. Every create gives a separate secret (shown once, with a ready client command) for a new or existing account, with label, lifetime, role and limits; revoking one token disconnects its clients and leaves the account's other tokens alone. New API (administrators only): `GET`/`POST /api/admin/tokens`, `POST /api/admin/tokens/{id}/revoke`; needs the token file (answers 501 without one). Actions appear in the activity log without secrets.

## [1.19.0] - 2026-11-07

### Added
- Dashboard **Connect** tab: choose what to publish (web or TCP, local port, subdomain, inspect, basic auth, PIN, IP allow-list, auto-close) and the operating system, and get the install command and the ready-to-run `wirerift` command for this server, token included (masked on screen, copied in full; or a `YOUR_TOKEN` placeholder). The page shows "Connected" when the tunnel appears. New `GET /api/connect` (any signed-in account) with the control address, public scheme, TCP port range and reserved subdomains.

## [1.18.1] - 2026-11-07

### Fixed
- Client: a login refusal ("authentication failed") that arrived together with the connection close was sometimes reported as "connection closed before login finished" with the TLS hint. The refusal is reported now.
- Tests: two timing assumptions in the TCP port tests (a closed tunnel's port is handed back a moment after its listener stops answering) no longer make Windows CI flaky.

## [1.18.0] - 2026-11-07

### Added
- TCP tunnels keep their public port like HTTP tunnels keep their subdomain: when a client drops, the port is reserved for its account for `-offline-grace`, nobody else is handed it (free-port requests skip it), and the reconnecting client asks for the same port, taking it over from its own stale session. It survives a server restart (`held.json`) and shows in the dashboard's reserved list as `tcp:<port>`. Closing on purpose still frees the port at once; a port taken in the meantime makes the client settle for a new one.
- `TunnelResponse.Port`: the server reports the assigned TCP port. A client may now also ask for a specific port inside the range (`TunnelRequest.RemotePort`, so far ignored); it gets "port already taken" or "port is outside the tunnel port range" when it cannot have it.

## [1.17.0] - 2026-11-07

### Added
- Dashboard **Activity** tab: connects, disconnects, tunnel creation and closing, failed logins and revoked sessions (in memory, last 500; an account sees its own, an administrator all).
- Dashboard **Admin** tab for administrator accounts: health cards, one hour of history charts (requests, errors, throughput, sessions, tunnels, heap, goroutines, open files), response-time distribution, accounts with live usage, all sessions with a Disconnect action, held subdomains, certificate expiry and the limits in effect. New API: `/api/me`, `/api/events`, `/api/admin/{overview,history,accounts,certs}` and `POST /api/admin/sessions/{id}/kick`.
- `wirerift-server token create -admin[=false]`: administrator accounts. Before, only the bootstrap token (now disabled when a token file is used) could see everything.
- `-dashboard-host`: serves the dashboard on its own host of the HTTPS edge (HTTP redirects to HTTPS, HSTS, rate limited, token required). Refuses to start without HTTPS.

### Fixed
- Disabling the bootstrap token also removes its account, so it no longer shows up as an administrator.

### Removed
- `website/` and its `Deploy Website` workflow and Dependabot npm entry: the site lives in its own repository.

## [1.16.1] - 2026-11-06

### Fixed
- Release binaries and `make build` / `make release` now include `wirerift-backup` (it was only in the Docker image), so a bare-metal install can back up and restore its state.
- Tests: the dashboard port-conflict test no longer hangs on macOS and Windows.

## [1.16.0] - 2026-11-06

### Security
- `/metrics` is no longer public. A direct loopback peer reads it as before; any other caller needs `Authorization: Bearer <token>` (a loopback peer that forwards a visitor, i.e. sets `X-Forwarded-For`/`Forwarded`/`X-Real-Ip`, counts as remote). `/healthz` and `/health/ready` stay public.
- The random first-run token is disabled (and no longer printed to the log) when a token file with tokens is in use and no bootstrap token was supplied. It used to stay valid as an unadvertised second credential.

### Added
- `wirerift-server -edge-rate` / `-edge-burst`: per-visitor-IP request limit of the HTTP edge (defaults stay 100 req/s, burst 50).
- The client reads `WIRERIFT_TOKEN_FILE` (used when `WIRERIFT_TOKEN` is unset), for `http`, `tcp`, `serve`, `start`, `list` and `doctor`. Before, only the server did, and a client given only the file sent an empty token.

### Changed
- A plaintext client talking to a TLS control plane now says "address it as tls://host:port" instead of a bare "connection closed".
- `wirerift-backup`: the key-format error tells how to create a key (`openssl rand -hex 32`).

## [1.15.0] - 2026-10-30

### Fixed
- A client that reconnects after a network drop (wifi loss, a half-open link) now gets its subdomain back from the server even while the previous session is still registered: tunnel requests sent while re-creating tunnels carry a new `reconnect` flag, and the server hands the name over from the same account's other session. Before, the name stayed "taken" and the client fell back to a random URL. Other accounts, and clients without the flag, are refused as before.
- Client: a tunnel whose subdomain stays taken no longer waits a useless 16 s after its last attempt, and the fallback request keeps the original deadline of a time-limited tunnel instead of reusing a stale TTL.

## [1.14.2] - 2026-10-29

### Fixed
- Subdomains reserved for connected or recently dropped clients now survive a server restart (saved to `<cert-dir>/held.json` on stop, loaded on start), so a restart no longer lets someone else take a name before its client reconnects.

## [1.14.1] - 2026-10-27

### Added
- `-tcp-idle-timeout`: closes a TCP tunnel connection that has moved no data in either direction for that long, freeing its port slot and stream. Off by default, so quiet sessions such as SSH are never cut; a connection that keeps trading data is never cut however long it lives.

### Fixed
- A client that exits on purpose (Ctrl-C, `Close`) now sends GO_AWAY, so the server releases its subdomains at once instead of showing visitors `503 Tunnel offline` and refusing other accounts for the whole `-offline-grace` period.
- Offline hold: it is released only after the reclaiming tunnel is really registered, and it is set before the dropped session's tunnels are torn down, so there is no window in which another account can take the name.
- A TCP idle watch could re-arm its timer after the connection had ended, and the half-close reaper could reset a stream the peer had just closed; both now check first.

## [1.14.0] - 2026-10-27

### Added
- A client that loses its connection keeps its HTTP URL: the server holds the subdomains of the dropped session for its account for `-offline-grace` (default 2m, 0 = release at once). Visitors get `503 Tunnel offline` with `Retry-After` meanwhile, no other account can claim the name, and the reconnecting client gets the same name back. A tunnel without an explicit `-subdomain` now asks for the name the server picked, so its URL no longer changes on every reconnect; if somebody else took the name in the meantime it settles for a new one. A tunnel closed on purpose, or one that expired, is released at once.
- `TunnelResponse.Subdomain` carries the assigned name to the client.
- The server sends GO_AWAY to every client when it is stopped, and the client logs "server closed the connection" with the reason instead of "connection lost". A client that does not read is not waited for longer than 2 seconds.

### Changed
- Release workflow: refuses to publish unless CI passed on the tagged commit, and runs the tests with the race detector.

### Fixed
- Docs: the notes at the top of `docs/SPECIFICATION.md` and `docs/IMPLEMENTATION.md` match the current code again.
- Client: concurrent `HTTP()`/`TCP()` calls could receive each other's tunnel response because the control channel has no request ID; tunnel requests are now sent one at a time.
- The Docker image reports its commit and build date (`wirerift version`) instead of `commit: none, built: unknown`.

## [1.13.0] - 2026-10-27

### Added
- `-half-close-timeout` (mux `HalfCloseTimeout`): resets a stream the server closed once the client has sent nothing for that long. Off by default, so slow responses are never cut.
- Releases publish a Docker image to `ghcr.io/wirerift/wirerift` (version tag and `latest`), and CI builds the Dockerfile and starts both binaries from it on every push

### Fixed
- `max_tunnels` is now enforced atomically, so parallel tunnel requests from one account's sessions can no longer overshoot the limit.
- Client: a refusal that is not about the credentials (the account is at its `max_sessions`, or the source IP is throttled after failed logins) is retried instead of ending the client as "authentication failed"; after a network drop the server may still hold the dead session for a while, and a `max_sessions: 1` client used to give up for good
- Client: the login now reports the client's real build version instead of a hard-coded `1.0.0`

## [1.12.0] - 2026-10-27

### Added
- Multiple tokens and accounts: `wirerift-server token create|list|revoke` manage a token file (default `<cert-dir>/tokens.json`, `-tokens-file`) that the server reads at startup. Only a SHA-256 digest of each token is stored, tokens can expire or be revoked, and accounts carry `max_tunnels`, `max_sessions` and `rate_limit` settings. The bootstrap token (`-token`, `WIRERIFT_TOKEN` or generated) keeps working unchanged. The file is reloaded while the server runs (every 5 seconds, or on SIGHUP); a revoked, expired or removed token also closes the connections opened with it, and a file that does not parse is ignored with an error in the log
- Dashboard: a token of a file account sees only its own tunnels, sessions, captured requests and counts and can replay only its own requests; the bootstrap token still sees everything
- Account limits are enforced: `max_sessions` (simultaneous connections), `max_tunnels` (over all of the account's connections) and `rate_limit` (tunnel creations per second, shared by the account's connections instead of restarting with every reconnect)
- Control port: a burst of 10 failed logins from one IP empties its allowance and further attempts, including valid ones, are refused until it refills (one per 5 seconds)

### Fixed
- Mux: a write to the connection now times out after 60s (`mux.Config.WriteTimeout`) and closes the connection, instead of a peer that stops reading holding the frame writer, every stream's writes and the heartbeat replies until the session timeout
- TLS: finished ACME back-off entries of hosts without a cached certificate are forgotten by the renewal pass instead of accumulating
- TCP tunnels: when the chosen port of the range was already used by another program (the default range overlaps the OS's ephemeral ports) the tunnel failed with "failed to bind tunnel port"; up to 16 ports are now tried before giving up

## [1.11.0] - 2026-10-25

### Security
- Control port: an unauthenticated connection now has 10s to finish the TLS handshake, send the magic bytes and authenticate, then it is cut (idle connections used to hold a goroutine and a file descriptor forever), and it cannot open streams before authenticating
- Control port: at most 32 unauthenticated connections per IP and 1024 overall are held at once; further ones are dropped until others authenticate or time out
- A tunnel request with an unknown or incomplete `auth` block (anything but `basic` with a username and password) is rejected instead of creating an unprotected tunnel
- A tunnel client that stops crediting the send window can no longer pin an upload: writing a buffered request body (or WebSocket upgrade) into the tunnel stream now ends when the visitor disconnects, the tunnel closes, or after 3 minutes, and releases its share of the global body budget (before, one stalled request held it until the 5-minute session timeout)
- Reserved subdomains (`www`, `api`, `admin`, `dashboard`, ...) can no longer be claimed by a tunnel
- The redirect after a successful PIN no longer follows a request path starting with `//` or `/\` to another host

### Changed
- TLS: certificates are renewed in the background (checked every 12 hours) once they enter the 14-day window, instead of by the first visitor after it opens; a failed renewal keeps serving the old, still valid certificate. The recorded expiry now comes from the certificate itself rather than a fixed 90 days, and several ACME orders may run at once, so one host's slow challenge no longer holds up every other first handshake
- Client: when the server rejects the token on a reconnect (revoked or changed), the client stops retrying, and `wirerift` exits with the error instead of staying up serving nothing
- Memory: a stream no longer preallocates its 256 KB receive window (it starts at 4 KB and grows as data arrives), so a peer opening thousands of idle streams costs ~40 MB instead of ~2.5 GB; a `WindowSize` above the 16 MB buffer limit is clamped instead of silently dropping data
- Memory: request bodies buffered for tunneling are capped across all in-flight requests (`Config.MaxBufferedBodyBytes`, default 256 MB); beyond it new uploads get `503` with `Retry-After` instead of exhausting memory. The body is also no longer copied a third time when sent
- Memory: the traffic inspector keeps at most 32 KB of headers per request and per response (credentials were already redacted)

### Fixed
- Windows: creating the local dev CA from several processes at once could fail with "Access is denied" on the lock file; that is now treated as another process holding the lock and retried
- ACME: a `badNonce` rejection is retried with a fresh nonce (up to 3 times) instead of failing the order, a missing `Replay-Nonce` is an error, and certificate, key and metadata files are written atomically so a crash cannot leave a torn file
- `wirerift list` can reach a dashboard on another port or behind TLS (`-dashboard host:port|https://...` or `WIRERIFT_DASHBOARD`) and warns before sending the token over plain HTTP to a non-local host
- Makefile test/lint/vet use the same package set as CI; the Docker image embeds its version (`--build-arg VERSION`); README: dashboard published on loopback in the `docker run` example, correct test and lint commands, no stale coverage table; the design documents say where they differ from the code
- Mux: a connection lost mid-stream is no longer reported as a clean end of stream (`io.EOF`), so close-delimited responses and TCP tunnels cannot look complete when they were cut short; a stream whose peer had already finished still delivers its data and ends in EOF
- Mux: stream IDs are now reused. A session used to refuse every new stream (all requests 502) after ~8.4M streams because IDs only counted up; the allocator now wraps round the 24-bit space and skips IDs still in use, so a long-lived tunnel never runs out
- Mux: send-window credit could be lost for good when the peer's window update arrived before the sender had debited its window, eventually stalling a long-lived stream; concurrent writers could also overdraw the window and get the stream reset. The window is now reserved before the frame is sent
- Client: tunnels that could not be re-created after a reconnect are kept and retried on the next reconnect instead of being dropped (the client stayed "connected" but served nothing); a connection that drops again mid re-creation no longer sits through the retry backoff
- Client: `Close` racing a reconnect could leave a live connection behind and hang; connection state is now mutex-guarded
- TLS: with ACME enabled, a still-valid certificate inside the 14-day renewal window is served while renewal fails or backs off, instead of a self-signed stand-in
- `wirerift start` rejects an unknown tunnel `type` before connecting, and exits with an error when no tunnel could be started
- `wirerift list` fails on a non-200 response (e.g. a wrong token) instead of exiting 0
- A valid PIN cookie is honoured even while the visitor's IP is locked out by bad guesses (shared NAT); replaying a request now times out (2 min) instead of hanging on a local app that never answers
- `wirerift-server`: an explicit `-domain`/`-control`/`-http` flag now wins over `WIRERIFT_DOMAIN`/`WIRERIFT_CONTROL_ADDR`/`WIRERIFT_HTTP_ADDR` even when it equals the default

## [1.10.1] - 2026-10-19

### Security
- TLS certificates (and ACME orders) are issued only for the base domain or names a live tunnel serves; random SNI names can no longer burn Let's Encrypt quota or grow the cache. Failed ACME hosts back off for 5 minutes and the self-signed stop-gap is no longer cached for a year
- The local dev CA is now restricted to TLS server authentication and to `.localhost`/`.test` for e-mail and URI identities too (a leaked key could previously mint S/MIME, client-auth and code-signing certificates); constraints are validated strictly on load, CAs created by older versions keep working but are flagged by `ca status` and `doctor`
- Closing or expiring a tunnel now also cuts visitors that are already connected (TCP, WebSocket, streamed responses); before, only new connections were refused
- `-dev` binds TCP tunnel ports to loopback as well
- Custom-domain probing: the DNS proof is checked before a client learns that a domain is in use

### Fixed
- Streams of any length work: the absolute 60s `WriteTimeout`/30s `ReadTimeout` that cut long SSE streams, downloads and uploads are replaced by a per-operation idle timeout (`Config.EdgeIdleTimeout`, default 60s)
- A local `Stream.Reset()` now wakes a blocked reader/writer (a visitor disconnecting used to leave the edge handler blocked until the local app finished)
- Concurrent first runs could produce a mismatched local CA key/certificate pair; the CA is now created under a lock
- `ca untrust -purge` deletes only the CA's own files, not the whole `-ca-dir`
- The `domain-secret` file is created atomically (no partial file, racing starts agree; an empty leftover is healed)
- Replaying a request whose path is not a valid URL path no longer panics; replay keeps the query string and the custom-domain Host
- Aborted responses are now recorded by the inspector
- Reconnecting never extends a tunnel's `-ttl` deadline (the remaining time is recomputed per attempt and rounded down)
- `wirerift-server doctor` accepts every server flag (including `-dev`)

## [1.10.0] - 2026-10-19

### Added
- **`wirerift-server doctor`**: checks, without starting anything, that this machine can run the server as configured: free ports (with setcap/`-dev` hints for ports below 1024), TCP tunnel range, certificate directory and domain-secret permissions, expiring certificates, wildcard DNS and the local dev CA. Shares its output format with `wirerift doctor` (new `internal/diag`).

### Fixed
- A local dev CA directory holding only `rootCA.pem` (or only the key) is no longer silently replaced with a brand-new CA, which would have broken every certificate users had already trusted; it is reported as an incomplete CA instead
- The inspector keeps query strings, so replay and cURL export reproduce the original request

## [1.9.0] - 2026-10-19

### Added
- **Custom domains**: `wirerift http|serve -domain app.example.com` (or `domain:` in `wirerift start` files) also serves a tunnel on your own domain. Ownership is proven with a DNS TXT record (`_wirerift.<domain>` = `wirerift-verification=<HMAC code>`) that the error message spells out; the code is derived from a persisted server secret (`<cert-dir>/domain-secret`). One tunnel per domain; certificates (ACME) are only requested for domains a verified, live tunnel is serving. `wirerift-server -dns-server` picks the resolver used for the check.
- ACME-enabled servers now hand out `https://` tunnel URLs.

### Removed
- The dashboard's `/api/domains*` endpoints and the `internal/config` package behind them. They were never connected to tunnels (custom domains now work through `-domain`), registered domains from an `account_id` in the request body, and their "verify" step only became real recently. Unknown `/api/...` paths now return 404 JSON instead of the web UI page.

### Fixed
- A TCP-tunnel request that asks for a custom domain is rejected instead of silently ignored
- Integration tests use distinct TCP port ranges so packages can run in parallel without colliding

## [1.8.0] - 2026-10-18

### Added
- **Local HTTPS development**: `wirerift-server -dev` serves trusted HTTPS for `*.localhost` / `.test` on loopback with a persistent local CA; `wirerift-server ca trust|untrust|status|path` manages it (system store, Chrome/Firefox NSS). The CA is restricted by X.509 name constraints to `.localhost`, `.test` and loopback IPs, so a leaked CA key cannot impersonate real sites.
- **Tunnel time limits**: `wirerift http|tcp|serve -ttl 30m` (library: `client.WithTTL`). The server enforces the deadline, frees the subdomain/port, and reports `expires_at` in the tunnel API; reconnects keep the original deadline and never revive an expired tunnel
- **`wirerift doctor`**: step-by-step connectivity check (DNS, TCP, TLS certificate and expiry, login) with a fix hint for each failure
- **Helpful error pages**: browsers get a clear HTML page when a tunnel does not exist, its client is gone, or the local app is not responding (the local port is never shown to visitors); API clients still receive plain-text bodies, plus an `X-WireRift-Error` header for local-app failures
- `Config.PublicScheme` / `PublicPort`: tunnel URLs reflect the scheme and port clients must use (e.g. `https://app.localhost:8443`)

## [1.7.0] - 2026-10-16

### Security
- Optional TLS for the control plane: server `-control-tls-cert/-control-tls-key`, client `tls://host:port` addresses (`WIRERIFT_TLS_CA` for private CAs)
- Forwarded headers (`X-Forwarded-*`) are no longer duplicated or spoofable; `X-WireRift-PIN` is not forwarded to the local app
- TLS: SNI is validated (no path traversal / arbitrary file writes), limited to the base domain; expiring certs are re-issued; ACME fallback certs are no longer persisted
- PIN brute-force lockout (5 failures per tunnel+IP, 5 min); PIN form accepts `; charset=` content types
- Inspector redacts `Authorization`, `Cookie`, `Set-Cookie`, `X-WireRift-PIN`; replay log is bounded
- Mux: receive window enforced, window credit saturates (no int32 wrap), duplicate/control stream IDs and `MaxStreams` enforced; frames no longer pre-allocate the claimed payload size
- Disabled accounts can no longer authenticate
- Dashboard binds to `127.0.0.1` by default (`-dashboard-bind`); failed-auth lockout (10 bad tokens per IP, 5 min); optional HTTPS via `-dashboard-tls-cert/-key`
- Startup banner no longer prints a token the operator supplied (only auto-generated ones)

### Changed
- HTTP responses are streamed to the visitor instead of fully buffered: SSE, long polling and downloads larger than 64 MB now work; unknown-length bodies are flushed per chunk; the local app's stalled response is bounded (2 min to first byte) and a visitor disconnect releases the stream

### Fixed
- CI lint job is green again (it had been failing): unchecked errors handled explicitly, `noctx`/Slowloris (`ReadHeaderTimeout` on `wirerift serve`) fixed, linter version pinned, `.golangci.yml` tuned with documented exceptions
- Custom domain verification now checks the DNS TXT record (`_wirerift.<domain>`) instead of marking any domain verified; domains are case-insensitive and labels are validated
- HEAD responses no longer fail with "unexpected EOF"
- Chunked request bodies were forwarded empty; oversized bodies now get 413
- Closing a TCP tunnel left its public port listening; bind errors are now reported to the client
- Nil-map panic when a session was removed during tunnel creation
- Mixed-case subdomains were unreachable; `/healthz` no longer shadows tunnels
- Stream half-close dropped the peer's remaining data
- Client: redirects no longer followed locally, no 30 s cap on response bodies, TCP half-close leak, tunnels retried after reconnect, dead-peer detection via heartbeat acks
- CLI: `--flag=value` no longer swallows the next argument; YAML inline comments; malformed `auth` in `start` is an error
- ACME JWK coordinates are zero-padded
- Release workflow publishes raw binaries and runs the correct test packages

## [1.6.0] - 2026-04-02

### Added
- **Persistent Tunnels**: Tunnels now survive server restarts with automatic reconnection
- **Dashboard Session Heartbeat**: Real-time session status with uptime and last seen tracking
- **Comprehensive Test Coverage**: 95-100% test coverage across all packages
- **Additional CLI Tests**: Complete coverage for edge cases in argument parsing

### Fixed
- Defensive error checks for `crypto/rand` operations
- Safe type assertions throughout the codebase
- Benchmark thread exhaustion on Windows with shared HTTP client pool
- Cleaned up unused webhook functionality

### Security
- Improved error handling in cryptographic operations
- Safe type assertions to prevent panics

## [1.5.0] - 2026-03-20

### Added
- Let's Encrypt ACME support with HTTP-01 challenge
- Self-signed TLS certificate generation
- Web Dashboard with traffic inspection
- Request replay functionality
- cURL export for captured requests
- Rate limiting support
- IP whitelist (CIDR) protection
- Basic Auth for tunnels
- PIN protection for tunnel access
- HTTP and TCP tunneling
- WebSocket passthrough
- Stream multiplexing with flow control
- Graceful shutdown
- Auto-reconnect with exponential backoff
- Health check endpoint (`/healthz`)
- X-Request-ID tracing
- Dark/light theme for dashboard

## [1.4.3] - 2026-03-16

### Fixed
- Auto-reconnect enabled on all CLI commands (was disabled, client exited on connection loss)
- Dashboard CSS rendering (double-percent escape in Go raw string)

### Changed
- README updated with v1.4.x features: token auth, JSON config, dashboard, healthz, X-Request-ID
- Full codebase audit: 0 bugs found, all 15 packages pass, 97-100% coverage

## [1.4.2] - 2026-03-16

### Added
- **Advanced Dashboard UI** — complete rewrite of the monitoring dashboard
  - Dark/Light theme toggle with localStorage persistence
  - Tabbed navigation: Tunnels / Sessions / Inspector with live count badges
  - Animated byte counters with smooth interpolation between polls
  - Live uptime counter ticking every second
  - Keyboard shortcuts: R=refresh, T=tunnels, S=sessions, I=inspector
  - Tunnel URL copy-to-clipboard with visual feedback
  - Traffic Inspector with request/response headers, JSON syntax highlighting
  - Search/filter across all tables, cURL export, request replay
  - Toast notification system, responsive layout (480px-1440px+)
  - CSP nonce-based script security, no external dependencies

## [1.4.1] - 2026-03-16

### Fixed
- **Token auth not working** — `auth.NewManager` now accepts user-defined token (`-token` flag > `WIRERIFT_TOKEN` env > auto-random)
- **`--double-dash` flags** — both `-token` and `--token` now work
- Server banner quick start command address formatting

### Added
- `-token` flag on server CLI to set a persistent auth token
- Server banner shows full connection info + copy-paste quick start command

## [1.4.0] - 2026-03-16

### Added
- **Health check endpoint** (`/healthz`) for load balancer and orchestrator integration
- **X-Request-ID header** for distributed request tracing (auto-generated or preserved)
- **JSON config file support** (`wirerift.json`) alongside YAML, with auto-fallback
- **CSP nonce-based security** on dashboard
- E2E tests for healthz, X-Request-ID; 2500+ lines of new tests

### Security
- Replaced hardcoded HMAC key with per-instance `crypto/rand` secret for PIN cookies
- Added HTTP server timeouts (Slowloris DoS prevention)
- Fixed `sync.Map` race — atomic `LoadOrStore` of real tunnel
- Fixed `mux.Close()` not called on auth failure — goroutine leak
- CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy headers
- CSRF protection, `Secure` flag on PIN cookies, `MaxBytesReader` on POST

### Fixed
- Reconnect mux race — handlers receive mux as parameter instead of shared field
- Old mux goroutine leak on reconnect — explicit close before creating new
- `inspectResponseWriter` implements `http.Flusher` and `http.Hijacker`
- Request log slice memory leak — backing array released via copy
- Nil map panic in `handleTunnelClose` and `handleTunnelRequest`
- Silent `Close()` errors on TLS writes — `writeFileAtomic` checks close error
- ACME `io.ReadAll` bounded to 4MB; 6 ignored `json.Unmarshal` errors fixed
- DNS case-insensitive subdomain matching
- `time.After` leak replaced with `time.NewTimer` + `Stop()`

### Changed
- Server split: `server.go` → `pin.go`, `inspect.go`, `http_edge.go`
- ACME operations accept `context.Context` for cancellation
- Client uses shared `http.Client` with connection pooling
- `recover()` added to all production goroutines
- Graceful shutdown for HTTP/HTTPS edge servers

### Infrastructure
- Dockerfile: `scratch` → `alpine:3.20` with CA certs, non-root user, healthcheck
- docker-compose.yml: V2 format, TCP port range, healthcheck
- CI: `golangci-lint`, coverage artifact upload, 90% threshold
- Makefile: `test-race`, `fuzz`, `docker` targets
- `.golangci.yml`: `gosec`, `bodyclose`, `noctx`, `exportloopref` linters

## [1.3.0] - 2026-03-16

### Added
- **Let's Encrypt ACME** — automatic HTTPS via HTTP-01 challenge, zero external dependencies
- ACME account key management (ECDSA P-256, persisted to disk)
- JWS signed requests per RFC 8555
- HTTP-01 challenge solver with automatic token serving
- Certificate auto-renewal (12h check, 30-day pre-expiry renewal)
- Certificate bundle storage with metadata
- Fallback chain: disk → ACME → self-signed
- CLI flags: `-acme-email`, `-acme-staging`

## [1.2.0] - 2026-03-16

### Added
- **Basic Auth** for HTTP tunnels (`-auth user:pass`) with constant-time comparison
- **Custom Response Headers** (`-header "X-Robots:noindex,Cache-Control:no-store"`)
- **Traffic Inspector** — real-time request/response capture with dashboard UI
- **Request Replay** — replay any captured request from dashboard or API
- **File Server Mode** (`wirerift serve ./dist`) — serve static files through tunnel
- **Webhook Relay** — fan-out incoming requests to multiple local endpoints

## [1.1.1] - 2026-03-15

### Added
- Fuzz test suite: 6 fuzzers (~52M inputs, 0 crashes)
- Advanced test suite: security (16), stress (5), reconnect (5), soak (4) = 30 tests
- Benchmark suite: HTTP latency/throughput/concurrency, TCP throughput, tunnel creation
- CI: race detector, fuzz tests, advanced tests, coverage threshold enforcement

## [1.1.0] - 2026-03-15

### Added
- IP whitelist for HTTP tunnels (`-whitelist`) — IPv4/IPv6/CIDR per-tunnel
- PIN protection for HTTP tunnels (`-pin`) — browser form, header, or query param
- TCP tunnel whitelist enforcement
- Rate limiter eviction to prevent memory leak
- Server-side bytes_in/bytes_out traffic tracking

### Security
- Constant-time comparison in BasicAuth and PIN
- Modulo bias eliminated in random string generation
- TLS certificates written with 0600 permissions
- PIN cookie uses HMAC instead of raw value
- Stream ID 0 collision with ControlStreamID fixed

### Fixed
- Dashboard graceful shutdown timeout (was unbounded)
- Ring buffer growth capped at 16 MB
- `io.ReadAll` calls bounded (64 MB responses, 32 MB request bodies)
- Port allocation race condition fixed with modulo wrap-around
- Unique request IDs via `crypto/rand`

### Removed
- ~3,100 lines of dead code (unused packages, types, error sentinels, utilities)

## [1.0.1] - 2026-03-01

### Added
- Initial project scaffolding

## [1.0.0] - 2026-02-15

### Added
- Initial release
