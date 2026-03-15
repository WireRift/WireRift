import { Link } from 'react-router'
import { CodeBlock } from '@/components/ui/CodeBlock'
import { Callout } from '@/components/ui/Callout'

export const configuration = {
  title: 'Configuration',
  description: 'Complete reference for all server and client configuration options.',
  content: (
    <>
      <h2>Server Options</h2>
      <p>
        The <code>wirerift-server</code> binary accepts the following command-line flags:
      </p>

      <table>
        <thead>
          <tr>
            <th>Flag</th>
            <th>Default</th>
            <th>Description</th>
          </tr>
        </thead>
        <tbody>
          <tr>
            <td><code>-control</code></td>
            <td><code>:4443</code></td>
            <td>Control plane listen address</td>
          </tr>
          <tr>
            <td><code>-http</code></td>
            <td><code>:80</code></td>
            <td>HTTP listen address</td>
          </tr>
          <tr>
            <td><code>-https</code></td>
            <td><code>:443</code></td>
            <td>HTTPS listen address</td>
          </tr>
          <tr>
            <td><code>-dashboard-port</code></td>
            <td><code>4040</code></td>
            <td>Dashboard web UI port</td>
          </tr>
          <tr>
            <td><code>-domain</code></td>
            <td><code>wirerift.com</code></td>
            <td>Base domain for tunnel subdomains</td>
          </tr>
          <tr>
            <td><code>-tcp-ports</code></td>
            <td><code>20000-29999</code></td>
            <td>TCP port range for tunnel allocation</td>
          </tr>
          <tr>
            <td><code>-auto-cert</code></td>
            <td><code>false</code></td>
            <td>Auto-generate self-signed TLS certificates</td>
          </tr>
          <tr>
            <td><code>-cert-dir</code></td>
            <td><code>certs</code></td>
            <td>Directory for TLS certificate storage</td>
          </tr>
          <tr>
            <td><code>-v</code></td>
            <td><code>false</code></td>
            <td>Enable verbose logging</td>
          </tr>
          <tr>
            <td><code>-json</code></td>
            <td><code>false</code></td>
            <td>Output logs in JSON format</td>
          </tr>
        </tbody>
      </table>

      <h3>Example Server Configurations</h3>

      <CodeBlock
        code={`# Development: minimal setup
wirerift-server -domain localhost -auto-cert -v

# Production: full configuration
wirerift-server \\
  -domain mytunnel.com \\
  -control :4443 \\
  -http :80 \\
  -https :443 \\
  -dashboard-port 4040 \\
  -tcp-ports 20000-29999 \\
  -auto-cert \\
  -cert-dir /etc/wirerift/certs \\
  -json

# Custom ports (non-privileged)
wirerift-server \\
  -domain mytunnel.com \\
  -control :8443 \\
  -http :8080 \\
  -https :8443 \\
  -auto-cert`}
        language="bash"
        filename="server-examples.sh"
      />

      <h2>Client CLI</h2>
      <p>
        The <code>wirerift</code> client binary supports the following commands:
      </p>

      <CodeBlock
        code={`# HTTP tunnel
wirerift http <local_port> [subdomain]

# HTTP tunnel with access control
wirerift http <local_port> -pin <secret>
wirerift http <local_port> -whitelist <ip1,ip2,cidr>

# TCP tunnel
wirerift tcp <local_port>

# Start from config file
wirerift start <config_file>

# List active tunnels
wirerift list`}
        language="bash"
        filename="client-commands"
      />

      <h2>Config File</h2>
      <p>
        Create a <code>wirerift.yaml</code> file for persistent tunnel configuration:
      </p>

      <CodeBlock
        code={`# wirerift.yaml
server: mytunnel.com:4443
token: ""

tunnels:
  # HTTP tunnel with custom subdomain
  - type: http
    local_port: 8080
    subdomain: myapp

  # HTTP tunnel with auto-generated subdomain
  - type: http
    local_port: 3000

  # PIN-protected tunnel
  - type: http
    local_port: 9090
    subdomain: admin
    pin: "mysecret"

  # IP-restricted tunnel
  - type: http
    local_port: 8081
    whitelist: "10.0.0.0/8,192.168.1.100"

  # TCP tunnel
  - type: tcp
    local_port: 25565

  # Another TCP tunnel
  - type: tcp
    local_port: 5432`}
        language="yaml"
        filename="wirerift.yaml"
      />

      <h3>Config File Fields</h3>

      <table>
        <thead>
          <tr>
            <th>Field</th>
            <th>Type</th>
            <th>Description</th>
          </tr>
        </thead>
        <tbody>
          <tr>
            <td><code>server</code></td>
            <td>string</td>
            <td>Server address in <code>host:port</code> format</td>
          </tr>
          <tr>
            <td><code>token</code></td>
            <td>string</td>
            <td>Authentication token (empty for no auth)</td>
          </tr>
          <tr>
            <td><code>tunnels</code></td>
            <td>array</td>
            <td>List of tunnel definitions</td>
          </tr>
          <tr>
            <td><code>tunnels[].type</code></td>
            <td>string</td>
            <td><code>http</code> or <code>tcp</code></td>
          </tr>
          <tr>
            <td><code>tunnels[].local_port</code></td>
            <td>number</td>
            <td>Local port to forward traffic to</td>
          </tr>
          <tr>
            <td><code>tunnels[].subdomain</code></td>
            <td>string</td>
            <td>Requested subdomain (HTTP only, optional)</td>
          </tr>
          <tr>
            <td><code>tunnels[].whitelist</code></td>
            <td>string</td>
            <td>Comma-separated IP whitelist with CIDR support (optional)</td>
          </tr>
          <tr>
            <td><code>tunnels[].pin</code></td>
            <td>string</td>
            <td>PIN code required to access the tunnel (HTTP only, optional)</td>
          </tr>
        </tbody>
      </table>

      <Callout variant="info" title="Server connection">
        The client connects to the server's control port (default <code>:4443</code>).
        Make sure the server address in your config includes the correct port.
      </Callout>

      <h2>Running as a Service</h2>
      <p>
        For production deployments, run the server as a systemd service:
      </p>

      <CodeBlock
        code={`# /etc/systemd/system/wirerift.service
[Unit]
Description=WireRift Tunnel Server
After=network.target

[Service]
Type=simple
User=wirerift
Group=wirerift
ExecStart=/usr/local/bin/wirerift-server \\
  -domain mytunnel.com \\
  -auto-cert \\
  -cert-dir /etc/wirerift/certs \\
  -json
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target`}
        language="ini"
        filename="wirerift.service"
      />

      <CodeBlock
        code={`# Enable and start the service
sudo systemctl enable wirerift
sudo systemctl start wirerift

# Check status
sudo systemctl status wirerift

# View logs
sudo journalctl -u wirerift -f`}
        language="bash"
      />

      <h2>Next Steps</h2>
      <ul>
        <li><Link to="/docs/http-tunnels">HTTP Tunnels</Link> - HTTP tunnel features in detail</li>
        <li><Link to="/docs/tcp-tunnels">TCP Tunnels</Link> - TCP tunnel features in detail</li>
        <li><Link to="/docs/security">Security</Link> - TLS and authentication setup</li>
      </ul>
    </>
  ),
}
