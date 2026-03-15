import { CodeBlock } from '@/components/ui/CodeBlock'
import { Callout } from '@/components/ui/Callout'

export const gettingStarted = {
  title: 'Introduction',
  description: 'Learn what WireRift is, why it exists, and how it can help you expose local services to the internet.',
  content: (
    <>
      <h2>What is WireRift?</h2>
      <p>
        WireRift is a self-hosted tunnel server that lets you expose local services running on your
        machine to the internet. Think of it as your own private ngrok - you control the server,
        the domain, and the data.
      </p>

      <p>
        WireRift is written in Go using <strong>only the standard library</strong>. No third-party
        dependencies, no supply chain risk. It compiles to a single binary for both the client and
        the server.
      </p>

      <h2>Why WireRift?</h2>
      <p>Here is what makes WireRift different from other tunnel solutions:</p>
      <ul>
        <li><strong>Zero Dependencies</strong> - Built entirely with the Go standard library. No external packages.</li>
        <li><strong>Self-Hosted</strong> - Run your own server on your infrastructure. No SaaS vendor, no usage limits.</li>
        <li><strong>Single Binary</strong> - One binary per component. No Docker, no runtimes, no setup wizards.</li>
        <li><strong>HTTP & TCP</strong> - Tunnel any protocol. HTTP with subdomain routing, or raw TCP for databases, game servers, SSH.</li>
        <li><strong>Auto TLS</strong> - Automatic self-signed certificate generation for encrypted connections.</li>
        <li><strong>Custom Domains</strong> - Bring your own domains with DNS verification and automatic routing.</li>
        <li><strong>Built-in Dashboard</strong> - Monitor tunnels, sessions, and statistics through a web UI.</li>
        <li><strong>Production Ready</strong> - Rate limiting, flow control, auto-reconnect, 100% test coverage.</li>
      </ul>

      <h2>How It Works</h2>
      <p>
        WireRift uses a custom binary protocol to multiplex multiple streams over a single TCP
        connection. When you create a tunnel, the client establishes a control connection to the
        server and negotiates tunnel parameters. The server then routes incoming traffic through
        the multiplexed connection to your local service.
      </p>

      <CodeBlock
        code={`# The basic flow:
#
# 1. Client connects to server over TLS
# 2. Client authenticates (if tokens configured)
# 3. Client requests a tunnel (HTTP or TCP)
# 4. Server allocates subdomain or port
# 5. External traffic arrives at server
# 6. Server forwards through mux to client
# 7. Client forwards to local service
# 8. Response travels back the same path`}
        language="bash"
        filename="how-it-works"
      />

      <h2>Architecture Overview</h2>
      <p>WireRift consists of two binaries:</p>
      <ul>
        <li>
          <strong><code>wirerift</code></strong> - The client CLI. Runs on your local machine and connects to the server.
        </li>
        <li>
          <strong><code>wirerift-server</code></strong> - The server. Runs on a VPS or cloud instance with a public IP.
        </li>
      </ul>

      <Callout variant="info" title="Prerequisites">
        You need Go 1.21 or later installed to build WireRift from source. The server needs a
        machine with a public IP address and a domain name pointing to it.
      </Callout>

      <h2>Quick Example</h2>
      <p>
        Here is the simplest way to get started. Start the server on your VPS, then create a
        tunnel from your local machine:
      </p>

      <CodeBlock
        code={`# On your server (VPS with public IP)
wirerift-server -domain mytunnel.com -auto-cert

# On your local machine
wirerift http 8080
# => Tunnel created: https://abc123.mytunnel.com`}
        language="bash"
        filename="quick-example"
      />

      <p>
        That is it. Your local service on port 8080 is now accessible from the internet through
        the assigned subdomain.
      </p>

      <h2>Next Steps</h2>
      <ul>
        <li><a href="/docs/installation">Installation</a> - Install WireRift on your system</li>
        <li><a href="/docs/quick-start">Quick Start</a> - Step-by-step first tunnel guide</li>
        <li><a href="/docs/configuration">Configuration</a> - Explore all options</li>
        <li><a href="/docs/architecture">Architecture</a> - Understand the internals</li>
      </ul>
    </>
  ),
}
