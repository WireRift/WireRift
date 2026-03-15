import { Link } from 'react-router'
import { CodeBlock } from '@/components/ui/CodeBlock'
import { Callout } from '@/components/ui/Callout'

export const tcpTunnels = {
  title: 'TCP Tunnels',
  description: 'Forward raw TCP connections for databases, game servers, SSH, and any TCP-based protocol.',
  content: (
    <>
      <h2>Basic Usage</h2>
      <p>
        TCP tunnels forward raw TCP connections from a server-allocated port to your local service.
        Unlike HTTP tunnels, TCP tunnels work with any protocol that runs over TCP.
      </p>

      <CodeBlock
        code={`# Forward local port 5432 (PostgreSQL)
wirerift tcp 5432
# => tcp://mytunnel.com:21053 → localhost:5432

# Forward local port 25565 (Minecraft)
wirerift tcp 25565
# => tcp://mytunnel.com:20847 → localhost:25565

# Forward local port 22 (SSH)
wirerift tcp 22
# => tcp://mytunnel.com:20123 → localhost:22`}
        language="bash"
        filename="tcp-basic"
      />

      <h2>Port Allocation</h2>
      <p>
        The server allocates ports from a configurable range (default <code>20000-29999</code>).
        Each TCP tunnel gets a random available port from this range.
      </p>

      <CodeBlock
        code={`# Server-side configuration for port range
wirerift-server -tcp-ports 30000-39999 -domain mytunnel.com -auto-cert`}
        language="bash"
      />

      <Callout variant="warning" title="Firewall">
        Make sure the TCP port range is open in your server's firewall. The entire range needs
        to be accessible for TCP tunnel clients to connect.
      </Callout>

      <h2>Use Cases</h2>

      <h3>Database Access</h3>
      <p>
        Expose a local database for remote access during development:
      </p>

      <CodeBlock
        code={`# Expose local PostgreSQL
wirerift tcp 5432

# Connect from anywhere:
psql -h mytunnel.com -p 21053 -U myuser mydb

# Expose local MySQL
wirerift tcp 3306

# Connect from anywhere:
mysql -h mytunnel.com -P 20891 -u myuser -p mydb`}
        language="bash"
        filename="database-tunnel"
      />

      <h3>Game Servers</h3>
      <p>
        Host game servers on your local machine and let players connect:
      </p>

      <CodeBlock
        code={`# Minecraft server
wirerift tcp 25565
# Players connect to: mytunnel.com:20847

# Terraria server
wirerift tcp 7777
# Players connect to: mytunnel.com:21234`}
        language="bash"
        filename="game-tunnel"
      />

      <h3>SSH Access</h3>
      <p>
        Expose your local SSH server for remote access:
      </p>

      <CodeBlock
        code={`# Expose SSH
wirerift tcp 22

# Connect remotely:
ssh -p 20123 user@mytunnel.com`}
        language="bash"
        filename="ssh-tunnel"
      />

      <h2>How TCP Tunnels Work</h2>
      <p>
        When a TCP tunnel is created, the server starts listening on the allocated port. When a
        remote client connects to that port, the server opens a mux stream to the tunnel client,
        which then connects to the local port and proxies data bidirectionally.
      </p>

      <CodeBlock
        code={`TCP Tunnel Flow:

Remote Client                 Server                    Local Client
     │                          │                           │
     │── TCP connect :20847 ──►│                           │
     │                          │── STREAM_OPEN ──────────►│
     │                          │                           │── connect localhost:25565
     │                          │                           │
     │── data ─────────────────►│── STREAM_DATA ──────────►│── data ──►
     │◄── data ─────────────────│◄── STREAM_DATA ──────────│◄── data ──
     │                          │                           │
     │── TCP close ────────────►│── STREAM_CLOSE ─────────►│── close
     │                          │                           │`}
        language="text"
        filename="tcp-flow"
      />

      <h2>Multiple TCP Tunnels</h2>
      <p>
        Use a config file to set up multiple TCP tunnels:
      </p>

      <CodeBlock
        code={`# wirerift.yaml
server: mytunnel.com:4443
token: ""
tunnels:
  - type: tcp
    local_port: 5432   # PostgreSQL
  - type: tcp
    local_port: 6379   # Redis
  - type: tcp
    local_port: 27017  # MongoDB`}
        language="yaml"
        filename="multi-tcp.yaml"
      />

      <Callout variant="info" title="Performance">
        TCP tunnels add minimal latency since data is forwarded as raw bytes through the
        multiplexed connection. There is no protocol parsing or header rewriting.
      </Callout>

      <h2>Next Steps</h2>
      <ul>
        <li><Link to="/docs/http-tunnels">HTTP Tunnels</Link> - HTTP tunnel features</li>
        <li><Link to="/docs/architecture">Architecture</Link> - How the protocol works</li>
        <li><Link to="/docs/security">Security</Link> - Securing your tunnels</li>
      </ul>
    </>
  ),
}
