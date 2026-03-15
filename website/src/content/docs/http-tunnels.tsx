import { Link } from 'react-router'
import { CodeBlock } from '@/components/ui/CodeBlock'
import { Callout } from '@/components/ui/Callout'

export const httpTunnels = {
  title: 'HTTP Tunnels',
  description: 'Expose local HTTP services with subdomain routing, custom domains, and WebSocket support.',
  content: (
    <>
      <h2>Basic Usage</h2>
      <p>
        HTTP tunnels expose local HTTP services through the server with automatic subdomain routing.
        Each tunnel gets a unique subdomain on the server's base domain.
      </p>

      <CodeBlock
        code={`# Expose port 8080 with auto-generated subdomain
wirerift http 8080
# => https://a7x9k2.mytunnel.com → localhost:8080

# Expose port 3000 with custom subdomain
wirerift http 3000 myapi
# => https://myapi.mytunnel.com → localhost:3000`}
        language="bash"
        filename="http-basic"
      />

      <h2>Subdomain Routing</h2>
      <p>
        The server routes incoming HTTP requests based on the <code>Host</code> header. When a
        request arrives at <code>myapp.mytunnel.com</code>, the server looks up the tunnel
        registered for the <code>myapp</code> subdomain and forwards the request through
        the multiplexed connection.
      </p>

      <CodeBlock
        code={`# Request flow:
#
# Browser → https://myapp.mytunnel.com/api/users
#         ↓
# Server receives request, extracts subdomain "myapp"
#         ↓
# Looks up tunnel for "myapp" subdomain
#         ↓
# Opens mux stream, forwards HTTP request
#         ↓
# Client receives on mux stream
#         ↓
# Client forwards to localhost:8080/api/users
#         ↓
# Response travels back the same path`}
        language="text"
        filename="routing-flow"
      />

      <h2>Custom Domains</h2>
      <p>
        You can use your own domains instead of subdomains. First, add the domain through the
        dashboard API, then configure DNS to point to your server.
      </p>

      <CodeBlock
        code={`# Add a custom domain via the API
curl -X POST http://your-server:4040/api/domains \\
  -H "Content-Type: application/json" \\
  -d '{"domain": "app.example.com"}'

# Check required DNS records
curl http://your-server:4040/api/domains/app.example.com/dns

# Verify DNS configuration
curl -X POST http://your-server:4040/api/domains/app.example.com/verify`}
        language="bash"
        filename="custom-domains"
      />

      <Callout variant="info" title="DNS Records">
        You need to add a CNAME record pointing your custom domain to the server's base domain,
        or an A record pointing directly to the server's IP address.
      </Callout>

      <h2>WebSocket Support</h2>
      <p>
        WireRift fully supports WebSocket connections. When the server detects a WebSocket
        upgrade request, it automatically handles the protocol upgrade and proxies the
        bidirectional WebSocket frames.
      </p>

      <CodeBlock
        code={`# Local WebSocket server on port 8080
# No special configuration needed - just create the tunnel
wirerift http 8080 ws-app

# Clients can connect via:
# wss://ws-app.mytunnel.com/ws`}
        language="bash"
      />

      <h2>Request Headers</h2>
      <p>
        WireRift adds forwarding headers to proxied requests so your application knows
        the original client information:
      </p>

      <table>
        <thead>
          <tr>
            <th>Header</th>
            <th>Description</th>
          </tr>
        </thead>
        <tbody>
          <tr>
            <td><code>X-Forwarded-For</code></td>
            <td>Original client IP address</td>
          </tr>
          <tr>
            <td><code>X-Forwarded-Proto</code></td>
            <td>Original protocol (http or https)</td>
          </tr>
          <tr>
            <td><code>X-Forwarded-Host</code></td>
            <td>Original Host header value</td>
          </tr>
        </tbody>
      </table>

      <h2>Multiple HTTP Tunnels</h2>
      <p>
        You can run multiple HTTP tunnels simultaneously, each on a different subdomain:
      </p>

      <CodeBlock
        code={`# Using a config file for multiple tunnels
# wirerift.yaml
server: mytunnel.com:4443
token: ""
tunnels:
  - type: http
    local_port: 3000
    subdomain: frontend
  - type: http
    local_port: 8080
    subdomain: api
  - type: http
    local_port: 9090
    subdomain: admin`}
        language="yaml"
        filename="multi-tunnel.yaml"
      />

      <CodeBlock
        code={`# Start all tunnels
wirerift start wirerift.yaml

# Results:
# https://frontend.mytunnel.com → localhost:3000
# https://api.mytunnel.com      → localhost:8080
# https://admin.mytunnel.com    → localhost:9090`}
        language="bash"
      />

      <h2>Access Control</h2>
      <p>
        HTTP tunnels support two access control mechanisms that can be used independently or combined.
      </p>

      <h3>PIN Protection</h3>
      <p>
        Require visitors to enter a PIN code before accessing the tunnel:
      </p>
      <CodeBlock
        code={`# Create a PIN-protected tunnel
wirerift http 8080 -pin mysecret`}
        language="bash"
      />
      <p>
        Visitors see a PIN entry form on first access. After entering the correct PIN,
        an HttpOnly cookie is set for 24 hours. API clients can pass the PIN via the{' '}
        <code>X-WireRift-PIN</code> header or <code>?pin=</code> query parameter.
      </p>

      <h3>IP Whitelist</h3>
      <p>
        Restrict tunnel access to specific IP addresses or CIDR ranges:
      </p>
      <CodeBlock
        code={`# Single IP
wirerift http 8080 -whitelist 203.0.113.50

# Multiple IPs and CIDR ranges
wirerift http 8080 -whitelist "203.0.113.50,10.0.0.0/8,192.168.1.0/24"

# Combine with PIN
wirerift http 8080 -whitelist "10.0.0.0/8" -pin secret`}
        language="bash"
      />
      <p>
        Non-whitelisted requests receive <code>403 Forbidden</code>.
        IPv6 addresses and CIDR notation are both supported.
      </p>

      <h2>Basic Auth</h2>
      <p>
        Protect your tunnel with HTTP Basic Authentication. Visitors must provide valid credentials
        before accessing the tunneled service.
      </p>

      <CodeBlock
        code={`# Create a tunnel with Basic Auth
wirerift http 8080 -auth "admin:pass"

# In a config file:
# tunnels:
#   - type: http
#     local_port: 8080
#     subdomain: staging
#     auth: "admin:pass"`}
        language="bash"
        filename="basic-auth"
      />

      <p>
        When Basic Auth is enabled, the server returns a <code>401 Unauthorized</code> response
        with a <code>WWW-Authenticate</code> header for unauthenticated requests. API clients can
        pass credentials via the standard <code>Authorization: Basic ...</code> header.
      </p>

      <h2>Traffic Inspector</h2>
      <p>
        The <code>-inspect</code> flag enables a live traffic inspector that captures all HTTP
        requests and responses flowing through the tunnel. This is useful for debugging webhooks,
        API integrations, and frontend development.
      </p>

      <CodeBlock
        code={`# Enable the traffic inspector
wirerift http 8080 -inspect

# Inspector dashboard available at:
# http://127.0.0.1:4040/inspect
#
# Features:
# - Live request/response stream
# - Full headers and body inspection
# - Request timing and status codes
# - Replay captured requests`}
        language="bash"
        filename="traffic-inspector"
      />

      <Callout variant="info" title="Request Replay">
        Captured requests can be replayed from the inspector dashboard or via the API using{' '}
        <code>POST /api/requests/&#123;id&#125;/replay</code>. See the{' '}
        <Link to="/docs/api-reference">API Reference</Link> for details.
      </Callout>

      <h2>Custom Response Headers</h2>
      <p>
        Inject custom headers into every response returned through the tunnel. This is useful for
        adding CORS headers, security headers, or custom metadata without modifying your application.
      </p>

      <CodeBlock
        code={`# Add custom response headers
wirerift http 8080 -headers "Access-Control-Allow-Origin:*,X-Frame-Options:DENY"

# In a config file:
# tunnels:
#   - type: http
#     local_port: 8080
#     subdomain: api
#     headers: "Access-Control-Allow-Origin:*,X-Custom-Header:value"`}
        language="bash"
        filename="custom-headers"
      />

      <h2>Next Steps</h2>
      <ul>
        <li><Link to="/docs/tcp-tunnels">TCP Tunnels</Link> - Forward raw TCP connections</li>
        <li><Link to="/docs/api-reference">API Reference</Link> - Custom domain management API</li>
        <li><Link to="/docs/security">Security</Link> - TLS and authentication</li>
      </ul>
    </>
  ),
}
