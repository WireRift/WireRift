import { Link } from 'react-router'
import { CodeBlock } from '@/components/ui/CodeBlock'
import { Callout } from '@/components/ui/Callout'

export const architecture = {
  title: 'Architecture',
  description: 'Deep dive into WireRift internals: the wire protocol, stream multiplexing, and flow control.',
  content: (
    <>
      <h2>Overview</h2>
      <p>
        WireRift uses a custom binary protocol to multiplex multiple streams over a single TCP
        connection. This allows efficient use of network resources while supporting many
        concurrent tunnels and connections.
      </p>

      <CodeBlock
        code={`┌──────────────┐                    ┌──────────────────┐
│   Client     │    Control Conn    │     Server       │
│              ├───────────────────►│                  │
│  wirerift    │    (TLS/TCP)       │  wirerift-server │
│              │                    │                  │
│  local:8080 ◄├─── Mux Stream ───►├─► HTTP Edge :80  │
│  local:3000 ◄├─── Mux Stream ───►├─► HTTPS Edge:443 │
│  local:5432 ◄├─── Mux Stream ───►├─► TCP Port:2xxxx │
│              │                    │                  │
└──────────────┘                    │  Dashboard :4040 │
                                    └──────────────────┘`}
        language="text"
        filename="architecture-overview"
      />

      <h2>Wire Protocol</h2>
      <p>
        Every message in WireRift is a <strong>frame</strong> with a 9-byte binary header followed
        by an optional payload.
      </p>

      <h3>Frame Format</h3>

      <CodeBlock
        code={`Frame Header (9 bytes):
┌─────────┬──────┬─────────────┬──────────────┐
│ Version │ Type │  Stream ID  │ Payload Len  │
│ 1 byte  │ 1 B  │   3 bytes   │   4 bytes    │
└─────────┴──────┴─────────────┴──────────────┘

Total: 9 bytes header + N bytes payload

Magic Bytes (connection init):
  0x57 0x52 0x46 0x01 → "WRF" + version 1`}
        language="text"
        filename="frame-format"
      />

      <h3>Frame Types</h3>
      <p>WireRift defines 14 frame types across four categories:</p>

      <table>
        <thead>
          <tr>
            <th>Category</th>
            <th>Frame Type</th>
            <th>Description</th>
          </tr>
        </thead>
        <tbody>
          <tr>
            <td rowSpan={2}><strong>Auth</strong></td>
            <td><code>AUTH_REQ</code></td>
            <td>Client sends authentication credentials</td>
          </tr>
          <tr>
            <td><code>AUTH_RES</code></td>
            <td>Server responds with auth result</td>
          </tr>
          <tr>
            <td rowSpan={3}><strong>Tunnel</strong></td>
            <td><code>TUNNEL_REQ</code></td>
            <td>Client requests a new tunnel</td>
          </tr>
          <tr>
            <td><code>TUNNEL_RES</code></td>
            <td>Server responds with tunnel details</td>
          </tr>
          <tr>
            <td><code>TUNNEL_CLOSE</code></td>
            <td>Either side closes a tunnel</td>
          </tr>
          <tr>
            <td rowSpan={5}><strong>Stream</strong></td>
            <td><code>STREAM_OPEN</code></td>
            <td>Open a new data stream</td>
          </tr>
          <tr>
            <td><code>STREAM_DATA</code></td>
            <td>Transfer data on a stream</td>
          </tr>
          <tr>
            <td><code>STREAM_CLOSE</code></td>
            <td>Gracefully close a stream</td>
          </tr>
          <tr>
            <td><code>STREAM_RST</code></td>
            <td>Abruptly reset a stream</td>
          </tr>
          <tr>
            <td><code>STREAM_WINDOW</code></td>
            <td>Update flow control window</td>
          </tr>
          <tr>
            <td rowSpan={4}><strong>Control</strong></td>
            <td><code>HEARTBEAT</code></td>
            <td>Keep-alive ping</td>
          </tr>
          <tr>
            <td><code>HEARTBEAT_ACK</code></td>
            <td>Keep-alive pong</td>
          </tr>
          <tr>
            <td><code>GO_AWAY</code></td>
            <td>Graceful shutdown signal</td>
          </tr>
          <tr>
            <td><code>ERROR</code></td>
            <td>Error notification</td>
          </tr>
        </tbody>
      </table>

      <h2>Stream Multiplexing</h2>
      <p>
        The multiplexer (mux) allows multiple logical streams over a single TCP connection.
        Each stream has a unique 3-byte ID (supporting up to 16.7 million concurrent streams).
      </p>

      <CodeBlock
        code={`// Conceptual flow of multiplexed streams:
//
// Single TCP Connection
// ┌─────────────────────────────────────┐
// │  Stream 1: HTTP request /api/users  │
// │  Stream 2: HTTP request /api/posts  │
// │  Stream 3: WebSocket connection     │
// │  Stream 4: TCP data (postgres)      │
// │  Control:  Heartbeat, tunnel mgmt   │
// └─────────────────────────────────────┘
//
// Each stream gets its own:
//  - Flow control window
//  - Backpressure handling
//  - Independent close/reset`}
        language="go"
        filename="mux-concept"
      />

      <Callout variant="info" title="Ring Buffer">
        Each stream uses a ring buffer for efficient data buffering. This avoids memory allocation
        during data transfer and provides predictable memory usage.
      </Callout>

      <h2>Flow Control</h2>
      <p>
        WireRift implements window-based flow control similar to HTTP/2. Each stream has a
        receive window that limits how much data the sender can transmit before receiving
        an acknowledgment.
      </p>

      <CodeBlock
        code={`Flow Control:

Sender                          Receiver
  │                                │
  │──── STREAM_DATA (1024 B) ─────►│  window: 65536 → 64512
  │──── STREAM_DATA (1024 B) ─────►│  window: 64512 → 63488
  │──── STREAM_DATA (1024 B) ─────►│  window: 63488 → 62464
  │                                │
  │◄── STREAM_WINDOW (+3072) ──────│  window: 62464 → 65536
  │                                │
  │  (sender can continue)         │

When window reaches 0:
  - Sender pauses (backpressure)
  - Receiver processes data
  - Receiver sends STREAM_WINDOW
  - Sender resumes`}
        language="text"
        filename="flow-control"
      />

      <h2>Go Packages</h2>
      <p>The codebase is organized into focused internal packages:</p>

      <table>
        <thead>
          <tr>
            <th>Package</th>
            <th>Description</th>
          </tr>
        </thead>
        <tbody>
          <tr>
            <td><code>internal/proto</code></td>
            <td>Wire protocol: Frame, FrameReader, FrameWriter</td>
          </tr>
          <tr>
            <td><code>internal/mux</code></td>
            <td>Stream multiplexing: Mux, Stream, RingBuffer</td>
          </tr>
          <tr>
            <td><code>internal/client</code></td>
            <td>Client: Connect, HTTP/TCP tunnels, stream handling</td>
          </tr>
          <tr>
            <td><code>internal/server</code></td>
            <td>Server: Auth, tunnel requests, HTTP/WS forwarding</td>
          </tr>
          <tr>
            <td><code>internal/auth</code></td>
            <td>Token authentication: Manager, Token, Account</td>
          </tr>
          <tr>
            <td><code>internal/tls</code></td>
            <td>TLS certificate management and generation</td>
          </tr>
          <tr>
            <td><code>internal/config</code></td>
            <td>Custom domain management: DomainManager</td>
          </tr>
          <tr>
            <td><code>internal/dashboard</code></td>
            <td>Web dashboard UI and REST API</td>
          </tr>
          <tr>
            <td><code>internal/ratelimit</code></td>
            <td>Token bucket and sliding window rate limiting</td>
          </tr>
          <tr>
            <td><code>internal/utils</code></td>
            <td>Subdomain validation utilities</td>
          </tr>
        </tbody>
      </table>

      <h2>Connection Lifecycle</h2>

      <CodeBlock
        code={`Connection Lifecycle:

1. TCP Connect     → Client connects to server control port
2. TLS Handshake   → Encrypted channel established
3. Magic Bytes     → Client sends 0x57 0x52 0x46 0x01
4. AUTH_REQ        → Client sends token (if configured)
5. AUTH_RES        → Server validates and responds
6. TUNNEL_REQ      → Client requests HTTP/TCP tunnel
7. TUNNEL_RES      → Server allocates subdomain/port
8. HEARTBEAT loop  → Keep-alive every 30 seconds
9. STREAM lifecycle → Open/Data/Close for each connection
10. TUNNEL_CLOSE   → Client or server closes tunnel
11. GO_AWAY        → Graceful connection shutdown`}
        language="text"
        filename="lifecycle"
      />

      <h2>Next Steps</h2>
      <ul>
        <li><Link to="/docs/security">Security</Link> - TLS, auth, and rate limiting details</li>
        <li><Link to="/docs/api-reference">API Reference</Link> - Dashboard REST API</li>
      </ul>
    </>
  ),
}
