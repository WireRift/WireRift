import { Link } from 'react-router'
import { CodeBlock } from '@/components/ui/CodeBlock'
import { Callout } from '@/components/ui/Callout'

export const security = {
  title: 'Security',
  description: 'TLS encryption, token authentication, and rate limiting configuration.',
  content: (
    <>
      <h2>TLS Encryption</h2>
      <p>
        All control plane connections between the client and server are encrypted with TLS.
        WireRift can automatically generate self-signed certificates, or you can provide
        your own.
      </p>

      <h3>Auto-Generated Certificates</h3>
      <p>
        The simplest option is to let WireRift generate self-signed certificates:
      </p>

      <CodeBlock
        code={`# Auto-generate certificates
wirerift-server -domain mytunnel.com -auto-cert

# Certificates are stored in the cert directory (default: ./certs)
wirerift-server -domain mytunnel.com -auto-cert -cert-dir /etc/wirerift/certs`}
        language="bash"
        filename="auto-tls"
      />

      <Callout variant="info" title="Self-signed certificates">
        The auto-generated certificates are self-signed. The client is configured to accept
        self-signed certificates when connecting to the control plane. For HTTP/HTTPS edges,
        you may want to use certificates from a proper CA (e.g., Let's Encrypt).
      </Callout>

      <h3>Certificate Management</h3>
      <p>
        The TLS manager (<code>internal/tls</code>) handles certificate generation, storage,
        and rotation. Certificates include the base domain and wildcard subdomain.
      </p>

      <CodeBlock
        code={`# Generated certificate covers:
# - mytunnel.com
# - *.mytunnel.com
#
# Certificate files:
# certs/
# ├── server.crt    (certificate)
# └── server.key    (private key)`}
        language="text"
        filename="cert-structure"
      />

      <h2>Authentication</h2>
      <p>
        WireRift supports token-based authentication. When configured, clients must provide
        a valid token to connect and create tunnels.
      </p>

      <h3>Token Configuration</h3>

      <CodeBlock
        code={`# Client config with authentication token
# wirerift.yaml
server: mytunnel.com:4443
token: "your-secret-token-here"
tunnels:
  - type: http
    local_port: 8080
    subdomain: myapp`}
        language="yaml"
        filename="auth-config.yaml"
      />

      <p>
        The authentication flow uses the <code>AUTH_REQ</code> and <code>AUTH_RES</code> frame
        types in the wire protocol. The client sends the token immediately after the TLS
        handshake, and the server validates it before allowing tunnel creation.
      </p>

      <CodeBlock
        code={`Authentication Flow:

Client                              Server
  │                                    │
  │──── TLS Handshake ────────────────►│
  │                                    │
  │──── AUTH_REQ (token) ─────────────►│
  │                                    │  ← Validates token
  │◄──── AUTH_RES (ok/denied) ─────────│
  │                                    │
  │  (if ok, proceed to TUNNEL_REQ)    │
  │  (if denied, connection closed)    │`}
        language="text"
        filename="auth-flow"
      />

      <h2>Rate Limiting</h2>
      <p>
        WireRift implements two types of rate limiting to prevent abuse:
      </p>

      <h3>Per-IP HTTP Rate Limiting</h3>
      <p>
        Limits the number of HTTP requests from a single IP address using a token bucket
        algorithm. This prevents individual clients from overwhelming the server.
      </p>

      <h3>Per-Session Tunnel Rate Limiting</h3>
      <p>
        Limits the rate of tunnel creation per client session using a sliding window
        algorithm. This prevents clients from rapidly creating and destroying tunnels.
      </p>

      <CodeBlock
        code={`Rate Limiting Algorithms:

Token Bucket (per-IP HTTP):
  - Bucket fills at a constant rate
  - Each request consumes one token
  - Requests rejected when bucket is empty
  - Allows short bursts of traffic

Sliding Window (per-session tunnel):
  - Tracks requests in a time window
  - Counts requests in the current window
  - Rejects when window limit exceeded
  - Smooth rate enforcement`}
        language="text"
        filename="rate-limiting"
      />

      <h2>Network Security Best Practices</h2>

      <h3>Firewall Configuration</h3>

      <CodeBlock
        code={`# Restrict dashboard to localhost only
wirerift-server -dashboard-port 127.0.0.1:4040 ...

# Or use firewall rules
# Allow only your IP to access the dashboard
sudo ufw allow from 203.0.113.1 to any port 4040
sudo ufw deny 4040

# Restrict control port to known IPs (optional)
sudo ufw allow from 203.0.113.0/24 to any port 4443`}
        language="bash"
        filename="firewall"
      />

      <h3>Reverse Proxy</h3>
      <p>
        For production deployments, consider placing the HTTP edge behind a reverse proxy
        like nginx or Caddy for proper TLS termination with Let's Encrypt certificates:
      </p>

      <CodeBlock
        code={`# Caddyfile example
*.mytunnel.com {
  reverse_proxy localhost:80
  tls {
    dns cloudflare {env.CF_API_TOKEN}
  }
}

mytunnel.com {
  reverse_proxy localhost:80
  tls {
    dns cloudflare {env.CF_API_TOKEN}
  }
}`}
        language="text"
        filename="Caddyfile"
      />

      <Callout variant="warning" title="Production TLS">
        For production use, it is strongly recommended to use proper TLS certificates from a
        certificate authority like Let's Encrypt, rather than self-signed certificates.
        Use a reverse proxy for automated certificate management.
      </Callout>

      <h2>Tunnel Access Control</h2>
      <p>
        WireRift provides per-tunnel access control in addition to server-level authentication.
      </p>

      <h3>PIN Protection</h3>
      <p>
        PIN-protected tunnels require a secret code before granting access.
        Security measures include:
      </p>
      <ul>
        <li>PIN comparisons use <strong>constant-time</strong> algorithms to prevent timing attacks</li>
        <li>Cookies store an <strong>HMAC digest</strong>, never the raw PIN value</li>
        <li>Cookies are <code>HttpOnly</code> and <code>SameSite=Strict</code> to mitigate XSS</li>
        <li>Cookie lifetime is 24 hours with automatic expiration</li>
      </ul>

      <h3>Basic Auth</h3>
      <p>
        HTTP tunnels can be protected with Basic Authentication. When enabled, the server
        challenges unauthenticated requests with a <code>401 Unauthorized</code> response
        and <code>WWW-Authenticate</code> header. Credentials are validated on the server
        side before traffic is forwarded.
      </p>

      <CodeBlock
        code={`# Enable Basic Auth on a tunnel
wirerift http 8080 -auth "admin:secretpass"

# In a config file:
# tunnels:
#   - type: http
#     local_port: 8080
#     auth: "admin:secretpass"`}
        language="bash"
        filename="basic-auth-security"
      />

      <Callout variant="warning" title="Use with TLS">
        Basic Auth transmits credentials encoded in Base64, not encrypted. Always use TLS
        (the default for WireRift tunnels) to protect credentials in transit.
      </Callout>

      <h3>IP Whitelist</h3>
      <p>
        IP whitelisting restricts tunnel access to specific addresses or CIDR ranges.
        Works for both HTTP tunnels (returns <code>403 Forbidden</code>) and
        TCP tunnels (silently drops non-whitelisted connections).
        Supports IPv4, IPv6, and CIDR notation.
      </p>

      <h2>Next Steps</h2>
      <ul>
        <li><Link to="/docs/architecture">Architecture</Link> - Understanding the protocol</li>
        <li><Link to="/docs/troubleshooting">Troubleshooting</Link> - Common issues and solutions</li>
      </ul>
    </>
  ),
}
