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
  <img src="wirerift.jpeg" alt="WireRift Overview" width="100%">
</p>

Open-source, zero-dependency tunnel server and client written in Go. Expose any local service to the internet through a secure tunnel — like ngrok, but fully self-hosted.

---

## Table of Contents

- [Features](#features)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Server Reference](#server-reference)
- [Client Reference](#client-reference)
- [Dashboard](#dashboard)
- [Configuration](#configuration)
- [Access Control](#access-control)
- [Traffic Inspector](#traffic-inspector)
- [Docker](#docker)
- [API Reference](#api-reference)
- [Architecture](#architecture)
- [Production Operations](#production-operations)
- [Benchmarks](#benchmarks)
- [Development](#development)
- [License](#license)

---

## Features

| Category | Features |
|----------|----------|
| **Tunneling** | HTTP tunnels, TCP tunnels, WebSocket passthrough, stream multiplexing, flow control |
| **Security** | Let's Encrypt ACME, self-signed TLS, Basic Auth, IP whitelist (CIDR), PIN protection, HMAC cookies, CSP nonce |
| **Monitoring** | Prometheus metrics, web dashboard (dark/light theme), traffic inspector, request replay, cURL export, JSON highlighting |
| **Operations** | Liveness (`/healthz`), readiness (`/health/ready`), X-Request-ID tracing, graceful shutdown, auto-reconnect, rate limiting |
| **Config** | YAML and JSON config files, CLI flags, environment variables, user-defined tokens |
| **Platform** | Zero dependencies, single binary, Linux/macOS/Windows/FreeBSD, amd64/arm64 |

---

## Installation

### Download Binary (Recommended)

Download the latest release for your platform from [GitHub Releases](https://github.com/WireRift/WireRift/releases/latest).

<details>
<summary><strong>Linux (amd64)</strong></summary>

```bash
curl -Lo wirerift-server https://github.com/WireRift/WireRift/releases/latest/download/wirerift-server-linux-amd64
curl -Lo wirerift https://github.com/WireRift/WireRift/releases/latest/download/wirerift-linux-amd64
chmod +x wirerift-server wirerift
sudo mv wirerift-server wirerift /usr/local/bin/
```
</details>

<details>
<summary><strong>Linux (arm64 / Raspberry Pi)</strong></summary>

```bash
curl -Lo wirerift-server https://github.com/WireRift/WireRift/releases/latest/download/wirerift-server-linux-arm64
curl -Lo wirerift https://github.com/WireRift/WireRift/releases/latest/download/wirerift-linux-arm64
chmod +x wirerift-server wirerift
sudo mv wirerift-server wirerift /usr/local/bin/
```
</details>

<details>
<summary><strong>macOS (Apple Silicon / M1+)</strong></summary>

```bash
curl -Lo wirerift-server https://github.com/WireRift/WireRift/releases/latest/download/wirerift-server-darwin-arm64
curl -Lo wirerift https://github.com/WireRift/WireRift/releases/latest/download/wirerift-darwin-arm64
chmod +x wirerift-server wirerift
sudo mv wirerift-server wirerift /usr/local/bin/
```
</details>

<details>
<summary><strong>macOS (Intel)</strong></summary>

```bash
curl -Lo wirerift-server https://github.com/WireRift/WireRift/releases/latest/download/wirerift-server-darwin-amd64
curl -Lo wirerift https://github.com/WireRift/WireRift/releases/latest/download/wirerift-darwin-amd64
chmod +x wirerift-server wirerift
sudo mv wirerift-server wirerift /usr/local/bin/
```
</details>

<details>
<summary><strong>Windows (amd64)</strong></summary>

Download from [Releases](https://github.com/WireRift/WireRift/releases/latest):
- `wirerift-server-windows-amd64.exe`
- `wirerift-windows-amd64.exe`

Or via PowerShell:
```powershell
Invoke-WebRequest -Uri "https://github.com/WireRift/WireRift/releases/latest/download/wirerift-server-windows-amd64.exe" -OutFile "wirerift-server.exe"
Invoke-WebRequest -Uri "https://github.com/WireRift/WireRift/releases/latest/download/wirerift-windows-amd64.exe" -OutFile "wirerift.exe"
```
</details>

<details>
<summary><strong>Windows (arm64)</strong></summary>

Download from [Releases](https://github.com/WireRift/WireRift/releases/latest):
- `wirerift-server-windows-arm64.exe`
- `wirerift-windows-arm64.exe`
</details>

Verify downloaded release files before installing them:

```bash
curl -LO https://github.com/WireRift/WireRift/releases/latest/download/checksums.txt
sha256sum --ignore-missing -c checksums.txt
gh attestation verify wirerift-linux-amd64 --repo WireRift/WireRift
```

Release checksums are published with every release, and release artifacts carry
GitHub/Sigstore build-provenance attestations.

### Build from Source

Requires Go 1.23+:

```bash
git clone https://github.com/WireRift/WireRift.git
cd WireRift
go build -o wirerift-server ./cmd/wirerift-server
go build -o wirerift ./cmd/wirerift
```

Or with Make:
```bash
make build          # builds both server and client to bin/
make test           # run all tests
make test-race      # run tests with race detector
make fuzz           # run fuzz tests
make bench          # run benchmarks
make docker         # build Docker image
make release        # cross-compile all platforms to dist/
```

---

## Quick Start

### 1. Start the Server

```bash
# With a fixed token (recommended)
wirerift-server --token my-secret-token

# Or let the server generate a random token (shown on startup)
wirerift-server
```

The server prints a connection banner:
```
╔══════════════════════════════════════════════╗
║              WireRift Server                 ║
╠══════════════════════════════════════════════╣
  Control:   :4443
  HTTP:      :80
  Dashboard: http://localhost:4040
  Domain:    wirerift.com
╠══════════════════════════════════════════════╣
  Token (-token flag):
  my-secret-token
╠══════════════════════════════════════════════╣
  Quick start:
  wirerift http 8080 -server localhost:4443 -token my-secret-token
╚══════════════════════════════════════════════╝
```

### 2. Connect a Client

```bash
# Expose local port 8080 via HTTP tunnel
wirerift http 8080 --token my-secret-token

# With custom subdomain
wirerift http 8080 myapp --token my-secret-token

# TCP tunnel (e.g., PostgreSQL)
wirerift tcp 5432 --token my-secret-token

# Serve static files
wirerift serve ./dist --token my-secret-token
```

### 3. Open Dashboard

Visit **http://localhost:4040** and enter your token to see:
- Active tunnels and sessions
- Live traffic inspector
- Request replay and cURL export

---

## Server Reference

```
wirerift-server [options]

Options:
  --token string        Auth token (default: auto-generated random)
  --domain string       Base domain for tunnels (default: wirerift.com)
  --control string      Control plane address (default: :4443)
  --http string         HTTP edge address (default: :80)
  --https string        HTTPS edge address (default: :443)
  --dashboard-port int  Dashboard port (default: 4040)
  --dashboard-bind str  Dashboard bind address (default: 127.0.0.1)
  --dashboard-host str  Also serve the dashboard on the HTTPS edge at this host (label or full name; needs HTTPS)
  --dashboard-tls-cert  PEM certificate for the dashboard (with --dashboard-tls-key serves HTTPS)
  --dashboard-tls-key   PEM private key for the dashboard
  --dns-server string   DNS server for custom-domain TXT checks (default: system resolver)
  --trusted-proxy-cidrs Comma-separated proxy CIDRs trusted to supply X-Forwarded-For (default: none)
  --dev                 Local development: loopback + trusted HTTPS for *.localhost (see "Local HTTPS development")
  --ca-dir str          Local CA directory for --dev (default: per-user config dir)
  --control-tls-cert    PEM certificate for the control plane (enables TLS on :4443)
  --control-tls-key     PEM private key for the control plane
  --tcp-ports string    TCP tunnel port range (default: 20000-29999)
  --auto-cert           Generate self-signed certificates
  --cert-dir string     Certificate directory (default: certs)
  --acme-email string   Email for Let's Encrypt (enables ACME)
  --acme-staging        Use Let's Encrypt staging server
  --v                   Verbose logging
  --json                JSON log format
  --version             Show version

Environment Variables:
  WIRERIFT_TOKEN         Auth token (flag takes precedence)
  WIRERIFT_DOMAIN        Base domain
  WIRERIFT_CONTROL_ADDR  Control plane address
  WIRERIFT_HTTP_ADDR     HTTP edge address
```

### Checking a server before you start it

`wirerift-server doctor` takes the same address/domain flags as the server and checks, without starting anything, whether this machine can run it: whether each port is free (with the `setcap` / `-dev` hint for ports below 1024), the TCP tunnel range, certificate directory permissions, the domain secret, expiring certificates, whether `*.your-domain` resolves in DNS, and the local dev CA. It exits non-zero on failure.

```bash
wirerift-server doctor -domain tunnel.example.com -acme-email me@example.com
```

### Examples

```bash
# Development (localhost, self-signed TLS)
wirerift-server --token dev123 --auto-cert

# Production (Let's Encrypt)
wirerift-server --domain mytunnel.com --acme-email admin@mytunnel.com --token prod-secret

# Custom ports
wirerift-server --control :8443 --http :8080 --dashboard-port 9090 --token mytoken

# Via environment
openssl rand -hex 32 > .wirerift-token
chmod 600 .wirerift-token
export WIRERIFT_TOKEN_FILE="$PWD/.wirerift-token"
export WIRERIFT_DOMAIN=tunnel.example.com
wirerift-server --acme-email admin@example.com
```

---

## Client Reference

```
wirerift <command> [options]

Commands:
  http <port> [subdomain]   Create an HTTP tunnel
  tcp <port>                Create a TCP tunnel
  serve <directory>         Serve static files via HTTP tunnel
  start [config-file]       Start tunnels from config file
  list                      List active tunnels
  doctor                    Check connectivity, TLS and login to a server
  config                    Show/edit configuration
  version                   Show version info

Common Options (all commands):
  --server string     Server address (default: localhost:4443)
  --token string      Auth token (or set WIRERIFT_TOKEN env var)
  --v                 Verbose output

HTTP/TCP/Serve Options:
  --ttl duration      Close the tunnel automatically after this long (e.g. 30m, 2h; max 1 year)

HTTP/Serve Options:
  --subdomain string  Requested subdomain
  --domain string     Also serve on your own domain (needs a DNS TXT proof, see "Custom domains")
  --auth string       Basic auth "user:password"
  --pin string        PIN protection
  --whitelist string  IP whitelist "ip1,ip2,cidr"
  --header string     Response headers "Key:Val,Key:Val"
  --inspect           Enable traffic inspector
```

> **Note:** Both `--flag` and `-flag` syntax work. Flags can appear before or after positional arguments.

### Troubleshooting a connection

`wirerift doctor` walks from DNS to login and says which step is broken and what to try:

```
$ wirerift doctor -server tls://tunnel.example.com:4443 -token $WIRERIFT_TOKEN
  ✓  Server address   tunnel.example.com:4443 (TLS)
  ✓  DNS              tunnel.example.com → 203.0.113.5 (12ms)
  ✓  TCP connect      tunnel.example.com:4443 (34ms)
  ✓  TLS              TLS 1.3, certificate valid, expires in 61 days
  ✓  Authentication   logged in (80ms)
```

It warns when the control plane is unencrypted on a non-loopback address and never prints your token. Exit status is non-zero when a step fails.

### Examples

```bash
# Simple HTTP tunnel
wirerift http 3000 --token mytoken

# HTTP tunnel with all features
wirerift http 8080 myapp \
  --token mytoken \
  --auth "admin:pass" \
  --pin 1234 \
  --whitelist "10.0.0.0/8,192.168.1.0/24" \
  --header "X-Frame-Options:DENY,X-Robots-Tag:noindex" \
  --inspect

# Temporary tunnel: the server closes it after 30 minutes (subdomain/port are freed)
wirerift http 3000 --ttl 30m --token mytoken

# TCP tunnel (database, game server, SSH, etc.)
wirerift tcp 5432 --token mytoken
wirerift tcp 25565 --token mytoken   # Minecraft
wirerift tcp 22 --token mytoken      # SSH

# Serve a directory
wirerift serve ./build --subdomain mysite --token mytoken

# Start from config file
wirerift start wirerift.yaml
wirerift start wirerift.json
```

---

## Dashboard

The built-in dashboard at `http://localhost:4040` provides:

- **Dark/Light theme** — toggle with button or persisted preference
- **Tabbed navigation** — Tunnels / Connect / Sessions / Inspector / Activity (and Admin for administrators) with live count badges
- **Keyboard shortcuts** — `R` refresh, `T` tunnels, `C` connect, `S` sessions, `I` inspector, `A` activity, `D` admin
- **Tunnel management** — copy URL to clipboard, status indicators
- **Connect** — fill in what to publish (web or TCP, local port, subdomain, inspect, basic auth, PIN, IP allow-list, auto-close) and where it runs (Linux, macOS, Windows); the page writes the install command and the exact `wirerift` command for this server, with your token (hidden on screen, copied in full), and shows "Connected" as soon as the tunnel is up
- **Traffic Inspector** — real-time request/response log with:
  - Method badges (GET=green, POST=blue, PUT=amber, DELETE=red)
  - Status code coloring (2xx=green, 4xx=red, 5xx=red)
  - Expandable request/response headers
  - JSON syntax highlighting
  - cURL command export
  - Request replay
- **Animated counters** — bytes and uptime update smoothly
- **Search/filter** — filter across all tables
- **Toast notifications** — action feedback
- **Activity** — what just happened: clients connecting and dropping, tunnels created and closed, failed logins, sessions closed because their token was revoked. An account sees its own events, an administrator everyone's.
- **Admin** (administrator accounts only) — the whole server at a glance:
  - health cards: readiness, version, uptime, sessions, tunnels, TCP ports in use, traffic, memory, goroutines, open files, earliest certificate expiry, persistent-state write errors;
  - one hour of history (10 s samples) as charts: requests/s, 4xx/5xx per second, throughput in and out, sessions, tunnels, heap, goroutines, open files;
  - response-time distribution (average, p50/p95/p99 bounds) and responses by status class;
  - every account with its role, limits and live usage; every session with a **Disconnect** button; subdomains held for a dropped client; every certificate with days left; the limits in effect.

### Administrator accounts

Administrators also manage tokens in the **Admin** tab (no shell on the server needed): the *Access tokens* table lists every token (account, label, role, limits, expiry, status) and *Create a token* makes a new one for a new or existing account, with a label, a lifetime, a role and limits. Each create gives its own secret, shown once with a ready `wirerift` command; **Revoke** disables one token and disconnects its clients at once while the account's other tokens keep working. Changes apply immediately and are written to the same `tokens.json` the `token` command uses (the activity log records who created or revoked what, never a secret).

Make an account an administrator when creating its token (`-admin=false` takes the role away again; the bootstrap token is always an administrator):

```bash
wirerift-server token create -account ops -name laptop -admin
```

When a token file with tokens exists and no bootstrap token is given, the random first-run token is disabled, so the administrator is whoever holds an `-admin` token.

### Reaching the dashboard remotely

By default the dashboard listens on `127.0.0.1:4040` only. Two ways to use it from elsewhere:

```bash
# 1. SSH tunnel (nothing new is exposed)
ssh -L 4040:127.0.0.1:4040 you@your-server      # then open http://localhost:4040

# 2. Publish it on the HTTPS edge under its own name
wirerift-server -domain tunnel.example.com -acme-email you@example.com -dashboard-host dashboard
# -> https://dashboard.tunnel.example.com  (certificate issued automatically)
```

`-dashboard-host` takes a label (`dashboard` -> `dashboard.<domain>`) or a full host name and refuses to start without HTTPS. Plain HTTP is redirected to HTTPS, responses carry HSTS and `no-store`, the edge rate limit applies, and every API call still needs a token (ten failed logins from one IP lock it out). `dashboard` is a reserved subdomain, so no tunnel can take the name. Publishing a login page is a choice: prefer the SSH tunnel when a handful of people reach it from fixed machines.

---

## Configuration

### YAML Format

```yaml
# wirerift.yaml
server: localhost:4443
token: my-secret-token

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

### JSON Format

```json
{
  "server": "localhost:4443",
  "token": "my-secret-token",
  "tunnels": [
    {
      "type": "http",
      "local_port": 8080,
      "subdomain": "myapp"
    },
    {
      "type": "http",
      "local_port": 9090,
      "subdomain": "admin",
      "auth": "admin:secret",
      "pin": "mysecret",
      "whitelist": "10.0.0.0/8",
      "inspect": true,
      "headers": "X-Robots-Tag:noindex"
    },
    {
      "type": "tcp",
      "local_port": 5432
    }
  ]
}
```

```bash
wirerift start wirerift.yaml    # YAML
wirerift start wirerift.json    # JSON (auto-fallback if .yaml not found)
wirerift config init            # generate sample wirerift.yaml
```

### Token Configuration

Token is resolved in order: `--token` flag > `WIRERIFT_TOKEN` env > auto-generated.

```bash
# Flag (highest priority)
wirerift-server --token my-secret
wirerift http 8080 --token my-secret

# Environment variable
export WIRERIFT_TOKEN=my-secret
wirerift-server              # reads from env
wirerift http 8080           # reads from env

# Auto-generated (shown on server startup banner)
wirerift-server              # generates random token, prints to stderr
```

### Multiple tokens and accounts

The token above is the server's bootstrap token. To give several people or
machines their own access, create tokens in the token file (default
`<cert-dir>/tokens.json`, reloaded while the server runs; only a SHA-256 digest of each token
is stored):

```bash
wirerift-server token create -account acme -name ci -max-tunnels 5 -expires 30d
wirerift-server token list
wirerift-server token revoke tok_ab12cd34
```

The secret is printed once. Tokens of the same account share its limits.
The server notices changes to the file within five seconds (or immediately on `SIGHUP`): new tokens work at once, and a revoked, expired or removed token also has its open connections and tunnels closed. A file that fails to parse is logged and the previous tokens stay in force. Changed account limits apply to connections made afterwards. A token may also be refused on its own account's limits: at most `-max-sessions` simultaneous connections and `-max-tunnels` tunnels over all of them, and `-rate` tunnel creations per second shared by every connection of the account (reconnecting does not reset it). The dashboard shows an account's own token only its own tunnels, sessions, captured requests and counts (replaying another account's request is refused); the bootstrap token sees everything. Ten failed logins from one IP exhaust its allowance, after which that IP is refused (even with a valid token) until it refills at one attempt per five seconds.

---

## Encrypted control plane

Without ACME or an explicit control certificate, the control plane (:4443) is plain TCP and the auth token is sent in cleartext. `-acme-email` secures both the HTTPS edge and the control plane automatically; clients must use the `tls://` scheme. To supply a separate control certificate instead:

```bash
# Server
wirerift-server -control-tls-cert cert.pem -control-tls-key key.pem ...

# Client: use the tls:// scheme
wirerift http 8080 -server tls://tunnel.example.com:4443 -token TOKEN
# Private/self-signed CA: export WIRERIFT_TLS_CA=/path/to/ca.pem
```

## Custom domains

Serve a tunnel on a domain you own (`app.example.com`) in addition to its `<name>.<your-domain>` address.

```bash
# 1. Point the domain at your server (CNAME to the server's base domain, or an A record)
#    app.example.com.  CNAME  tunnel.mydomain.com.

# 2. Ask for it. The first time, the server tells you which TXT record proves you own the domain:
wirerift http 3000 -domain app.example.com
#   custom domain not verified (no matching TXT record found): add a DNS TXT record
#   _wirerift.app.example.com with the value wirerift-verification=3cf2f6d... 

# 3. Add that TXT record, wait for DNS, run the same command again:
wirerift http 3000 -domain app.example.com
# HTTP tunnel created: https://app.example.com -> http://localhost:3000
```

How it stays safe:
- **Ownership is proven in DNS.** The expected value is `HMAC(server secret, account|domain)`: only the domain's DNS owner can publish it and only your server can compute it, so nobody can claim a domain they do not control. The secret lives in `<cert-dir>/domain-secret` (mode 0600), so published records stay valid across restarts; back it up with your certificates.
- **One tunnel per domain.** While a tunnel serves a domain, no other client can take it over.
- **HTTPS only for live, verified domains.** With `-acme-email`, the certificate is requested on the first HTTPS visit (HTTP-01, so port 80 must reach the server) and only for a domain a verified tunnel is serving right now, so random SNI names cannot burn your Let's Encrypt quota.
- HTTP tunnels only; wildcards, IP addresses and names under the server's own domain are rejected. `-dns-server 1.1.1.1:53` makes the server verify against a specific resolver instead of the system one. In `wirerift start` files use `domain: app.example.com`.

## Local HTTPS development

`-dev` runs the whole stack on your machine with **trusted HTTPS and fake domains**, no public domain or Let's Encrypt needed:

```bash
wirerift-server ca trust      # once: create the local CA and trust it (asks for sudo)
wirerift-server -dev          # control 127.0.0.1:4443, http :8080, https :8443

wirerift http 3000 -server 127.0.0.1:4443 -token TOKEN -subdomain myapp
# HTTP tunnel created: https://myapp.localhost:8443 -> http://localhost:3000
```

- `*.localhost` resolves to loopback in browsers and curl, so no `/etc/hosts` edits. `.test` domains work too (`-domain myapp.test`, then add them to `/etc/hosts`).
- Everything listens on loopback with unprivileged ports; nothing is exposed to the network.
- **The CA is name-constrained.** It can only issue for `.localhost`, `.test` and loopback IPs, enforced by X.509 name constraints. Even if its key (`~/.config/wirerift/local-ca/rootCA-key.pem`, mode 0600) leaks, certificates for real sites are rejected by Go, OpenSSL/curl, Chrome, Firefox and Safari.
- `wirerift-server ca status` shows the CA and whether this machine trusts it; `ca untrust [-purge]` undoes `ca trust` completely; `ca path` prints the certificate path for tools that need it (`curl --cacert`, `NODE_EXTRA_CA_CERTS`).
- `ca trust` installs into the system store (`update-ca-certificates` / `update-ca-trust` on Linux, keychain on macOS, Root store on Windows) and, if `certutil` (libnss3-tools / nss-tools) is installed, into Chrome/Chromium and Firefox profiles, which do not read the system store on Linux. Restart the browser afterwards. Verified end to end on Linux (Debian/Ubuntu: real `update-ca-certificates`, real `certutil` NSS databases, curl/OpenSSL and Firefox accepting `https://app.localhost`, OpenSSL rejecting a certificate for a real site signed with the CA key). The RHEL/Fedora/Arch, macOS and Windows code paths are implemented and unit-tested but have not been run on real machines yet.

## Access Control

### Basic Auth

```bash
wirerift http 8080 --auth "user:password"
```

Returns `401 Unauthorized` with `WWW-Authenticate: Basic` header. Uses constant-time comparison.

### IP Whitelist

```bash
wirerift http 8080 --whitelist "203.0.113.50,10.0.0.0/8,192.168.0.0/16"
```

Supports IPv4, IPv6, CIDR notation. HTTP returns `403 Forbidden`, TCP silently drops.

### PIN Protection

```bash
wirerift http 8080 --pin mysecret
```

Three ways to provide PIN:
| Method | Example |
|--------|---------|
| Browser form | Dark-themed PIN page, sets HttpOnly HMAC cookie (24h) |
| HTTP header | `X-WireRift-PIN: mysecret` |
| Query parameter | `https://myapp.tunnel.com/?pin=mysecret` (redirects to clean URL) |

---

## Traffic Inspector

Enable inspection on any tunnel:

```bash
wirerift http 8080 --inspect --token mytoken
```

Dashboard shows live traffic at `http://localhost:4040` (Inspector tab):
- Method, path, status, duration, client IP
- Expandable request/response headers
- JSON body with syntax highlighting
- **Replay** — resend any captured request
- **cURL export** — copy request as curl command

### API Access

```bash
# List captured requests
curl -H "Authorization: Bearer TOKEN" http://localhost:4040/api/requests?limit=50

# Filter by tunnel
curl -H "Authorization: Bearer TOKEN" http://localhost:4040/api/requests?tunnel_id=tun_abc

# Replay a request
curl -X POST -H "Authorization: Bearer TOKEN" http://localhost:4040/api/requests/req_xyz/replay
```

---

## Docker

### Docker Run

Tagged releases publish an image to GitHub Container Registry
(`ghcr.io/wirerift/wirerift:<version>` and `:latest`; from v1.13.0 on). To build it yourself:

```bash
docker build -t wirerift-server .
openssl rand -hex 32 > .wirerift-token
chmod 600 .wirerift-token

# The dashboard serves plain HTTP inside the container, so publish it on
# loopback only (or put TLS in front of it with -dashboard-tls-cert/-key).
docker run -d \
  --init \
  --read-only \
  --tmpfs /tmp:size=16m,mode=1777 \
  --cap-drop ALL \
  --security-opt no-new-privileges \
  --stop-timeout 30 \
  -p 4443:4443 \
  -p 80:80 \
  -p 443:443 \
  -p 127.0.0.1:4040:4040 \
  -e WIRERIFT_TOKEN_FILE=/run/secrets/wirerift_token \
  -v "$PWD/.wirerift-token:/run/secrets/wirerift_token:ro" \
  -v wirerift-certs:/data/certs \
  wirerift-server \
  -domain mytunnel.com -acme-email admin@mytunnel.com
```

With ACME enabled the control plane also requires TLS; clients connect to
`tls://mytunnel.com:4443`. Port 80 must be publicly reachable for HTTP-01.
The ACME identity (`acme-account.key`) is never rotated automatically when it
is corrupt: restore it from backup or perform an explicit account recovery.
During a temporary ACME directory outage, restart is allowed only when that
identity and a currently valid base-domain certificate are already cached; the
server logs degraded mode and retries ACME initialization every five minutes.

### Docker Compose

```bash
export WIRERIFT_DOMAIN=mytunnel.com
export WIRERIFT_ACME_EMAIL=admin@mytunnel.com
export WIRERIFT_TOKEN_FILE=/etc/wirerift/token
export WIRERIFT_IMAGE=ghcr.io/your-org/wirerift@sha256:<approved-digest>
sh scripts/check-compose-security.sh
docker compose up -d
```

The included `docker-compose.yml` provides:
- Server with control, HTTP, HTTPS, dashboard ports
- TCP tunnel port range (20000-20099)
- Example upstream published on loopback only when the `example` profile is enabled
- Certificate volume persistence
- Container readiness check via `/health/ready`
- Non-root container
- Read-only root filesystem, dropped capabilities, and privilege escalation prevention
- Measured default ceilings of 2 CPUs, 1 GiB memory, and 512 PIDs
- Fail-closed required domain, ACME email, and read-only auth-token secret file
- Required operator-supplied image reference; production uses an approved immutable digest

---

## API Reference

Operational endpoints are served only when the request host does not belong to
an active tunnel. `/healthz` and `/health/ready` are public. `/metrics` is not:
a direct loopback peer (a local Prometheus, `curl`) reads it freely, everyone
else must send `Authorization: Bearer TOKEN` with a valid token. A same-host
reverse proxy that forwards visitors (it sets `X-Forwarded-For`/`Forwarded`) is
treated like any other remote caller.

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/healthz` | GET, HEAD | Process liveness |
| `/health/ready` | GET, HEAD | Listener and maintenance-loop readiness; returns 503 while draining/not started |
| `/metrics` | GET, HEAD | Loopback or Bearer token. Prometheus-format readiness/topology/bytes, fixed-cardinality HTTP status and latency, earliest loaded-certificate expiry, and persistence-write errors |

Dashboard API endpoints require an `Authorization: Bearer TOKEN` header:

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/stats` | GET | Server statistics |
| `/api/tunnels` | GET | List active tunnels |
| `/api/sessions` | GET | List connected sessions |
| `/api/requests` | GET | List captured requests |
| `/api/requests/{id}/replay` | POST | Replay a captured request |

### Response Headers

Every proxied request includes:
- `X-Request-ID` — unique trace ID (preserved if sent by client)
- canonical `X-Forwarded-For`, `X-Forwarded-Proto`, and `X-Forwarded-Host` values. By default visitor-supplied forwarding headers are discarded and the socket peer is the client. When WireRift is intentionally placed behind sanitizing L7 proxies, pass only their networks with `--trusted-proxy-cidrs 10.0.0.0/8,2001:db8:1234::/48`; the client chain is resolved right-to-left, while malformed or oversized chains fall back to the socket peer.

---

## Production Operations

Use [the production operations runbook](docs/OPERATIONS.md) for release
verification, firewall and DNS prerequisites, secret handling, staging/canary,
monitoring, backup and restore, incident recovery, and rollback.

---

## Architecture

### Wire Protocol

```
+--------+--------+----------+-----------+
| Version|  Type  | StreamID |  Length   |
| 1 byte | 1 byte | 3 bytes  |  4 bytes  |
+--------+--------+----------+-----------+
|            Payload (variable)          |
+----------------------------------------+

Magic: 0x57 0x52 0x46 0x01 ("WRF\x01")
Header: 9 bytes | Max payload: 16 MB | Max streams: 16M
```

### Connection Flow

```
Client                              Server
  |------- Magic + AUTH_REQ -------->|
  |<------------- AUTH_RES ----------|
  |------- TUNNEL_REQ -------------->|  http://myapp.tunnel.com
  |<------------- TUNNEL_RES -------|
  |                                  |
  |   [ Browser hits myapp.tunnel.com ]
  |                                  |
  |<------ STREAM_OPEN(1) ----------|  New HTTP request
  |<------ STREAM_DATA(1) ----------|
  |------- STREAM_DATA(1) --------->|  Response from local service
  |------- STREAM_CLOSE(1) -------->|
  |                                  |
  |<------ STREAM_OPEN(2) ----------|  Concurrent request!
  |------- HEARTBEAT --------------->|  Keep-alive
  |<------------- HEARTBEAT_ACK ----|
```

### Project Structure

```
wirerift/
├── cmd/
│   ├── wirerift/              # Client CLI
│   └── wirerift-server/       # Server CLI
├── internal/
│   ├── auth/                  # Token authentication
│   ├── client/                # Client implementation
│   ├── config/                # Configuration & domains
│   ├── dashboard/             # Web dashboard & traffic inspector
│   ├── mux/                   # Stream multiplexing & flow control
│   ├── proto/                 # Wire protocol (frame encoding)
│   ├── ratelimit/             # Token bucket & sliding window
│   ├── server/
│   │   ├── server.go          # Core server, session & tunnel management
│   │   ├── http_edge.go       # HTTP request routing & proxying
│   │   ├── pin.go             # PIN protection
│   │   ├── inspect.go         # Traffic inspection & replay
│   │   ├── http_proxy.go      # Request serialization
│   │   ├── tcp_proxy.go       # TCP stream helpers
│   │   └── webhook.go         # Webhook fan-out relay
│   ├── tls/                   # ACME (Let's Encrypt) & certificate management
│   └── utils/                 # Subdomain validation
├── test/
│   ├── advanced/              # Security, stress, reconnect, soak tests (34 tests)
│   ├── benchmark/             # Throughput & latency benchmarks
│   └── integration/           # End-to-end integration tests
├── Dockerfile                 # Multi-stage build (alpine, non-root, healthcheck)
├── docker-compose.yml         # Production-ready compose file
├── Makefile                   # Build, test, lint, fuzz, release targets
└── .golangci.yml              # Linter config (gosec, bodyclose, noctx, etc.)
```

---

## Benchmarks

Benchmark results are environment-specific and are therefore generated rather
than copied into this README. The suite fails on setup errors, transport errors,
or any non-2xx response; rate-limit responses are never counted as capacity.

```bash
go run ./test/benchmark/                         # Full local capacity baseline
WIRERIFT_BENCH_QUICK=1 go run ./test/benchmark/ # CI integrity smoke
go run ./test/advanced/        # Security, stress, and short load smokes
go run ./test/fault/           # Latency, drop, partition, half-open recovery
go run ./test/soak/ -duration 30m -window 1m    # Sustained tail/resource drift
go test -bench=. ./internal/   # Micro-benchmarks
```

See [docs/BENCHMARKING.md](docs/BENCHMARKING.md) for methodology, controlled
runner requirements, covered targets, and the result-record template. Launch
objectives and error-budget policy are in [docs/SLO.md](docs/SLO.md).

---

## Development

### Prerequisites

- Go 1.23+
- Git

### Running Tests

```bash
go test ./cmd/... ./internal/... ./test/integration/   # All unit + integration tests
go test -race ./cmd/... ./internal/...                 # With race detector
go test -cover ./cmd/... ./internal/...                # With coverage
go run ./test/advanced/          # Security, stress, and short load smokes
go run ./test/fault/             # Deterministic network fault recovery
go run ./test/soak/ -duration 30m -window 1m   # Long soak (scheduled in CI)
go run ./test/benchmark/         # Benchmark suite
```

### Test Coverage

CI requires at least 90% total statement coverage. Per-package numbers:
`go test -cover ./cmd/... ./internal/...`

### Linting

```bash
go vet ./cmd/... ./internal/...
golangci-lint run ./cmd/... ./internal/...   # uses .golangci.yml config
```

---

## Security

| Protection | Implementation |
|------------|---------------|
| Authentication | Token-based, constant-time comparison |
| TLS | Let's Encrypt ACME (HTTP-01) or self-signed |
| Basic Auth | Per-tunnel, constant-time comparison |
| IP Whitelist | IPv4/IPv6/CIDR per-tunnel |
| PIN Protection | HMAC cookies (per-instance secret), HttpOnly, Secure, SameSite=Strict |
| Rate Limiting | Per-IP HTTP requests, per-session tunnel creation |
| CSP | Nonce-based Content-Security-Policy on dashboard |
| Headers | X-Frame-Options: DENY, X-Content-Type-Options: nosniff, Referrer-Policy |
| CSRF | Cookie auth restricted to GET requests on dashboard |
| Request Tracing | X-Request-ID auto-generated or preserved |
| Graceful Shutdown | HTTP server drain on SIGTERM/SIGINT |
| Panic Recovery | All production goroutines protected |

---

## Troubleshooting

### Connection refused
Make sure the server is running and the port matches:
```bash
wirerift http 8080 --server localhost:4443 --token YOUR_TOKEN
```

### Invalid token
Token must match between server and client:
```bash
wirerift-server --token abc123          # server
wirerift http 8080 --token abc123       # client — same token
```

### Port already in use
Change the server ports:
```bash
wirerift-server --control :8443 --http :8080 --dashboard-port 9090
```

### Auto-reconnect
Client automatically reconnects with exponential backoff (1s → 30s max) and re-creates all tunnels. No action needed.

The URL survives the drop: the server keeps a lost connection's subdomains reserved for its account for `-offline-grace` (default 2 minutes; `0` releases them at once). Visitors see `503 Tunnel offline` meanwhile, nobody else can take the name, and a tunnel you did not name yourself asks for the same random name again, so the public URL stays the same. If the name was taken after the grace period, the client falls back to a new one.

The same goes for **TCP tunnels**: the public port is reserved for the account for `-offline-grace` as well, nobody else is given it, and the reconnecting client asks for the same port again, so an SSH or database endpoint keeps its address. Closing a tunnel (or exiting) on purpose frees the port at once; if the port was taken after the grace period, the client settles for a new one. The reservation also survives a server restart (`held.json`). A client may ask for a fixed port inside `-tcp-ports` as well (`TunnelRequest.RemotePort`); it is refused with "port already taken" when the port is in use or reserved for another account.

---

## License

MIT License — see [LICENSE](LICENSE)
