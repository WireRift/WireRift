import { CodeBlock } from '@/components/ui/CodeBlock'
import { Callout } from '@/components/ui/Callout'

export const quickStart = {
  title: 'Quick Start',
  description: 'Create your first tunnel in under a minute with this step-by-step guide.',
  content: (
    <>
      <h2>Step 1: Start the Server</h2>
      <p>
        On your VPS or cloud instance with a public IP and domain, start the WireRift server:
      </p>

      <CodeBlock
        code={`# Basic server start with auto TLS
wirerift-server -domain mytunnel.com -auto-cert -v`}
        language="bash"
      />

      <p>
        The <code>-auto-cert</code> flag generates self-signed TLS certificates automatically.
        The <code>-v</code> flag enables verbose logging so you can see what is happening.
      </p>

      <Callout variant="info" title="Default Ports">
        The server listens on: control plane (<code>:4443</code>), HTTP (<code>:80</code>),
        HTTPS (<code>:443</code>), and dashboard (<code>:4040</code>).
      </Callout>

      <h2>Step 2: Create an HTTP Tunnel</h2>
      <p>
        On your local machine, start a local HTTP service (or use an existing one), then create
        a tunnel:
      </p>

      <CodeBlock
        code={`# Start a local web server (example)
python3 -m http.server 8080 &

# Create an HTTP tunnel to port 8080
wirerift http 8080

# Output:
# Connected to mytunnel.com:4443
# Tunnel created: https://a7x9k2.mytunnel.com → localhost:8080`}
        language="bash"
        filename="http-tunnel"
      />

      <p>
        Your local service is now accessible at the assigned subdomain. Anyone on the internet
        can access it.
      </p>

      <h2>Step 3: Use a Custom Subdomain</h2>
      <p>
        Instead of a random subdomain, specify your own:
      </p>

      <CodeBlock
        code={`# With a custom subdomain
wirerift http 8080 myapp

# Output:
# Tunnel created: https://myapp.mytunnel.com → localhost:8080`}
        language="bash"
      />

      <h2>Step 4: Create a TCP Tunnel</h2>
      <p>
        TCP tunnels forward raw TCP connections. Useful for databases, game servers, SSH, etc:
      </p>

      <CodeBlock
        code={`# Forward a Minecraft server
wirerift tcp 25565

# Output:
# Tunnel created: tcp://mytunnel.com:20847 → localhost:25565

# Forward a PostgreSQL database
wirerift tcp 5432

# Output:
# Tunnel created: tcp://mytunnel.com:21053 → localhost:5432`}
        language="bash"
        filename="tcp-tunnel"
      />

      <h2>Step 5: Use a Config File</h2>
      <p>
        For multiple tunnels or persistent configuration, use a YAML config file:
      </p>

      <CodeBlock
        code={`# wirerift.yaml
server: mytunnel.com:4443
token: ""
tunnels:
  - type: http
    local_port: 8080
    subdomain: myapp
  - type: http
    local_port: 3000
    subdomain: api
  - type: tcp
    local_port: 25565`}
        language="yaml"
        filename="wirerift.yaml"
      />

      <CodeBlock
        code={`# Start all tunnels from config
wirerift start wirerift.yaml

# List active tunnels
wirerift list`}
        language="bash"
      />

      <h2>Step 6: Check the Dashboard</h2>
      <p>
        Open the built-in dashboard to monitor your tunnels:
      </p>

      <CodeBlock
        code={`# Open in your browser
# http://your-server:4040

# Or use the API
curl http://your-server:4040/api/tunnels | jq .
curl http://your-server:4040/api/sessions | jq .
curl http://your-server:4040/api/stats | jq .`}
        language="bash"
        filename="dashboard"
      />

      <Callout variant="success" title="You are all set">
        Your tunnels are running. The client automatically reconnects if the connection drops,
        and re-creates all tunnels.
      </Callout>

      <h2>Next Steps</h2>
      <ul>
        <li><a href="/docs/configuration">Configuration</a> - All server and client options</li>
        <li><a href="/docs/http-tunnels">HTTP Tunnels</a> - Advanced HTTP tunnel features</li>
        <li><a href="/docs/tcp-tunnels">TCP Tunnels</a> - TCP tunnel details</li>
        <li><a href="/docs/security">Security</a> - TLS, auth, and rate limiting</li>
      </ul>
    </>
  ),
}
