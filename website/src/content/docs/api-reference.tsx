import { Link } from 'react-router'
import { CodeBlock } from '@/components/ui/CodeBlock'
import { Callout } from '@/components/ui/Callout'

export const apiReference = {
  title: 'Dashboard API',
  description: 'REST API reference for the WireRift dashboard on port 4040.',
  content: (
    <>
      <h2>Overview</h2>
      <p>
        WireRift includes a built-in dashboard with a REST API accessible on port 4040 (configurable
        with <code>-dashboard-port</code>). The API provides endpoints for monitoring tunnels,
        sessions, and managing custom domains.
      </p>

      <Callout variant="info" title="Base URL">
        All API endpoints are relative to <code>http://your-server:4040</code>.
      </Callout>

      <h2>Tunnels</h2>

      <h3>List Active Tunnels</h3>
      <p>Returns all currently active tunnels.</p>

      <CodeBlock
        code={`GET /api/tunnels`}
        language="text"
      />

      <CodeBlock
        code={`curl http://your-server:4040/api/tunnels | jq .

# Response:
{
  "tunnels": [
    {
      "id": "tun_a7x9k2",
      "type": "http",
      "subdomain": "myapp",
      "url": "https://myapp.mytunnel.com",
      "local_port": 8080,
      "allowed_ips": ["10.0.0.0/8"],
      "has_pin": true,
      "created_at": "2025-01-15T10:30:00Z"
    },
    {
      "id": "tun_b3m8p1",
      "type": "tcp",
      "port": 20847,
      "url": "tcp://mytunnel.com:20847",
      "local_port": 25565,
      "created_at": "2025-01-15T10:32:00Z"
    }
  ]
}`}
        language="bash"
        filename="list-tunnels"
      />

      <h2>Sessions</h2>

      <h3>List Connected Sessions</h3>
      <p>Returns all currently connected client sessions.</p>

      <CodeBlock
        code={`GET /api/sessions`}
        language="text"
      />

      <CodeBlock
        code={`curl http://your-server:4040/api/sessions | jq .

# Response:
{
  "sessions": [
    {
      "id": "ses_x9k2a7",
      "remote_addr": "203.0.113.42:51234",
      "connected_at": "2025-01-15T10:29:00Z",
      "tunnel_count": 2,
      "streams_active": 5
    }
  ]
}`}
        language="bash"
        filename="list-sessions"
      />

      <h2>Statistics</h2>

      <h3>Server Statistics</h3>
      <p>Returns overall server statistics and metrics.</p>

      <CodeBlock
        code={`GET /api/stats`}
        language="text"
      />

      <CodeBlock
        code={`curl http://your-server:4040/api/stats | jq .

# Response:
{
  "uptime": "72h15m30s",
  "total_connections": 1542,
  "active_sessions": 3,
  "active_tunnels": 7,
  "bytes_in": 15728640,
  "bytes_out": 52428800,
  "requests_total": 28493
}`}
        language="bash"
        filename="stats"
      />

      <h2>Custom Domains</h2>

      <h3>List Domains</h3>

      <CodeBlock
        code={`GET /api/domains`}
        language="text"
      />

      <CodeBlock
        code={`curl http://your-server:4040/api/domains | jq .

# Response:
{
  "domains": [
    {
      "domain": "app.example.com",
      "verified": true,
      "created_at": "2025-01-10T08:00:00Z"
    }
  ]
}`}
        language="bash"
        filename="list-domains"
      />

      <h3>Add Domain</h3>

      <CodeBlock
        code={`POST /api/domains
Content-Type: application/json

{"domain": "app.example.com"}`}
        language="text"
      />

      <CodeBlock
        code={`curl -X POST http://your-server:4040/api/domains \\
  -H "Content-Type: application/json" \\
  -d '{"domain": "app.example.com"}'

# Response:
{
  "domain": "app.example.com",
  "verified": false,
  "dns_records": [
    {
      "type": "CNAME",
      "name": "app.example.com",
      "value": "mytunnel.com"
    }
  ]
}`}
        language="bash"
        filename="add-domain"
      />

      <h3>Get Domain Details</h3>

      <CodeBlock
        code={`GET /api/domains/{domain}`}
        language="text"
      />

      <CodeBlock
        code={`curl http://your-server:4040/api/domains/app.example.com | jq .`}
        language="bash"
      />

      <h3>Get DNS Records</h3>
      <p>Returns the DNS records that need to be configured for a domain.</p>

      <CodeBlock
        code={`GET /api/domains/{domain}/dns`}
        language="text"
      />

      <CodeBlock
        code={`curl http://your-server:4040/api/domains/app.example.com/dns | jq .

# Response:
{
  "records": [
    {
      "type": "CNAME",
      "name": "app.example.com",
      "value": "mytunnel.com",
      "status": "configured"
    }
  ]
}`}
        language="bash"
        filename="dns-records"
      />

      <h3>Verify Domain</h3>
      <p>Triggers DNS verification for a domain.</p>

      <CodeBlock
        code={`POST /api/domains/{domain}/verify`}
        language="text"
      />

      <CodeBlock
        code={`curl -X POST http://your-server:4040/api/domains/app.example.com/verify

# Response:
{
  "domain": "app.example.com",
  "verified": true
}`}
        language="bash"
        filename="verify-domain"
      />

      <h3>Remove Domain</h3>

      <CodeBlock
        code={`DELETE /api/domains/{domain}`}
        language="text"
      />

      <CodeBlock
        code={`curl -X DELETE http://your-server:4040/api/domains/app.example.com

# Response: 204 No Content`}
        language="bash"
        filename="delete-domain"
      />

      <Callout variant="warning" title="Security Note">
        The dashboard API does not currently require authentication. In production, use
        firewall rules to restrict access to port 4040, or bind it to localhost only.
      </Callout>

      <h2>Next Steps</h2>
      <ul>
        <li><Link to="/docs/architecture">Architecture</Link> - Understanding the protocol</li>
        <li><Link to="/docs/security">Security</Link> - Securing the dashboard</li>
      </ul>
    </>
  ),
}
