import { Link } from 'react-router'
import { CodeBlock } from '@/components/ui/CodeBlock'
import { Callout } from '@/components/ui/Callout'

export const installation = {
  title: 'Installation',
  description: 'Install WireRift from source using Go, or download pre-built binaries.',
  content: (
    <>
      <h2>Requirements</h2>
      <ul>
        <li><strong>Go 1.21+</strong> - Required for building from source</li>
        <li><strong>Server</strong> - A machine with a public IP address (VPS, cloud instance, etc.)</li>
        <li><strong>Domain</strong> - A domain name pointing to your server (for HTTP tunnels)</li>
      </ul>

      <h2>Install with Go</h2>
      <p>The easiest way to install WireRift is with <code>go install</code>:</p>

      <CodeBlock
        code={`# Install the client
go install github.com/wirerift/wirerift/cmd/wirerift@latest

# Install the server
go install github.com/wirerift/wirerift/cmd/wirerift-server@latest`}
        language="bash"
        filename="install.sh"
      />

      <p>
        This downloads, compiles, and installs the binaries to your <code>$GOPATH/bin</code> directory.
        Make sure <code>$GOPATH/bin</code> is in your <code>PATH</code>.
      </p>

      <h2>Build from Source</h2>
      <p>Clone the repository and build manually:</p>

      <CodeBlock
        code={`# Clone the repository
git clone https://github.com/wirerift/wirerift.git
cd wirerift

# Build both binaries
go build -o wirerift ./cmd/wirerift
go build -o wirerift-server ./cmd/wirerift-server

# Or build with version information
go build -ldflags "-X main.version=1.0.0" -o wirerift ./cmd/wirerift
go build -ldflags "-X main.version=1.0.0" -o wirerift-server ./cmd/wirerift-server`}
        language="bash"
        filename="build.sh"
      />

      <h2>Cross-Compilation</h2>
      <p>
        Go makes it easy to cross-compile for different platforms. Build for Linux on any OS:
      </p>

      <CodeBlock
        code={`# Build for Linux (amd64)
GOOS=linux GOARCH=amd64 go build -o wirerift-linux-amd64 ./cmd/wirerift
GOOS=linux GOARCH=amd64 go build -o wirerift-server-linux-amd64 ./cmd/wirerift-server

# Build for Linux (arm64)
GOOS=linux GOARCH=arm64 go build -o wirerift-linux-arm64 ./cmd/wirerift
GOOS=linux GOARCH=arm64 go build -o wirerift-server-linux-arm64 ./cmd/wirerift-server

# Build for macOS (arm64 - Apple Silicon)
GOOS=darwin GOARCH=arm64 go build -o wirerift-darwin-arm64 ./cmd/wirerift

# Build for Windows
GOOS=windows GOARCH=amd64 go build -o wirerift.exe ./cmd/wirerift`}
        language="bash"
        filename="cross-compile.sh"
      />

      <h2>Verify Installation</h2>
      <p>After installation, verify that both binaries are available:</p>

      <CodeBlock
        code={`# Check client
wirerift --help

# Check server
wirerift-server --help`}
        language="bash"
      />

      <Callout variant="info" title="No runtime dependencies">
        WireRift compiles to a static binary. There are no runtime dependencies to install -
        no Docker, no Node.js, no Java. Just copy the binary and run it.
      </Callout>

      <h2>Server Setup</h2>
      <p>
        On your server, you will also want to configure DNS and open the necessary ports:
      </p>

      <CodeBlock
        code={`# DNS Records (at your DNS provider)
# A record: mytunnel.com → <your-server-ip>
# A record: *.mytunnel.com → <your-server-ip>

# Firewall rules (example with ufw)
sudo ufw allow 80/tcp     # HTTP
sudo ufw allow 443/tcp    # HTTPS
sudo ufw allow 4443/tcp   # Control plane
sudo ufw allow 4040/tcp   # Dashboard
sudo ufw allow 20000:29999/tcp  # TCP tunnel ports`}
        language="bash"
        filename="server-setup.sh"
      />

      <Callout variant="warning" title="Wildcard DNS">
        For HTTP tunnels with subdomain routing, you need a wildcard DNS record
        (<code>*.mytunnel.com</code>) pointing to your server. Without this, only custom
        domain tunnels will work.
      </Callout>

      <h2>Next Steps</h2>
      <ul>
        <li><Link to="/docs/quick-start">Quick Start</Link> - Create your first tunnel</li>
        <li><Link to="/docs/configuration">Configuration</Link> - Configure the server</li>
      </ul>
    </>
  ),
}
