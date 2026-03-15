import { CodeBlock } from '@/components/ui/CodeBlock'
import { Callout } from '@/components/ui/Callout'

export const troubleshooting = {
  title: 'Troubleshooting',
  description: 'Common issues, FAQ, and debugging tips for WireRift.',
  content: (
    <>
      <h2>Connection Issues</h2>

      <h3>Cannot connect to server</h3>
      <p>
        If the client cannot connect to the server, check the following:
      </p>
      <ul>
        <li>Verify the server is running and listening on the control port (default <code>:4443</code>)</li>
        <li>Check that the server's firewall allows connections on port 4443</li>
        <li>Verify DNS resolves correctly: <code>dig mytunnel.com</code></li>
        <li>Try connecting directly to the IP address instead of the domain</li>
      </ul>

      <CodeBlock
        code={`# Check if server is listening
ss -tlnp | grep 4443

# Test TCP connectivity
nc -zv mytunnel.com 4443

# Check DNS resolution
dig mytunnel.com
nslookup mytunnel.com

# Run client with verbose output
wirerift http 8080 -v`}
        language="bash"
        filename="connection-debug"
      />

      <h3>TLS handshake errors</h3>
      <p>
        TLS errors usually indicate certificate issues:
      </p>
      <ul>
        <li>Make sure <code>-auto-cert</code> is enabled on the server, or valid certificates are provided</li>
        <li>Check that the certificate directory is writable</li>
        <li>Delete old certificates and let the server regenerate them</li>
      </ul>

      <CodeBlock
        code={`# Remove old certificates
rm -rf certs/
# Restart server - new certificates will be generated
wirerift-server -domain mytunnel.com -auto-cert -v`}
        language="bash"
      />

      <h2>Tunnel Issues</h2>

      <h3>HTTP tunnel returns 502 Bad Gateway</h3>
      <p>
        This means the tunnel is connected but the local service is not responding:
      </p>
      <ul>
        <li>Verify your local service is running on the specified port</li>
        <li>Check that the local service accepts connections on <code>localhost</code></li>
        <li>Try accessing the local service directly: <code>curl http://localhost:8080</code></li>
      </ul>

      <h3>Subdomain already in use</h3>
      <p>
        Each subdomain can only be used by one tunnel at a time. If the subdomain is taken:
      </p>
      <ul>
        <li>Choose a different subdomain name</li>
        <li>Let the server assign a random subdomain by omitting the subdomain argument</li>
        <li>Check if you have a stale session: <code>curl http://server:4040/api/sessions</code></li>
      </ul>

      <h3>TCP tunnel port unreachable</h3>
      <p>
        If remote clients cannot connect to the TCP tunnel port:
      </p>
      <ul>
        <li>Verify the TCP port range is open in the server's firewall</li>
        <li>Check the allocated port is within the configured range</li>
      </ul>

      <CodeBlock
        code={`# Check firewall rules
sudo ufw status

# Ensure TCP port range is open
sudo ufw allow 20000:29999/tcp`}
        language="bash"
      />

      <h2>Performance Issues</h2>

      <h3>High latency</h3>
      <ul>
        <li>Choose a server location close to your users</li>
        <li>Check server resource usage (CPU, memory, network)</li>
        <li>Verify no rate limiting is being triggered</li>
      </ul>

      <h3>Connection drops</h3>
      <p>
        WireRift includes automatic reconnection. If connections drop frequently:
      </p>
      <ul>
        <li>Check for network instability between client and server</li>
        <li>Verify the server has enough resources (file descriptors, memory)</li>
        <li>Check server logs for error messages</li>
      </ul>

      <CodeBlock
        code={`# Increase file descriptor limit
ulimit -n 65536

# Check current connections
ss -s

# Monitor server logs
journalctl -u wirerift -f`}
        language="bash"
        filename="performance-debug"
      />

      <h2>Dashboard Issues</h2>

      <h3>Dashboard not accessible</h3>
      <ul>
        <li>Check that the dashboard port (default 4040) is open in the firewall</li>
        <li>Verify the server started successfully</li>
        <li>Try accessing from the server itself: <code>curl http://localhost:4040</code></li>
      </ul>

      <h2>FAQ</h2>

      <h3>Can I use WireRift without a domain?</h3>
      <p>
        Yes, but only for TCP tunnels. HTTP tunnels require a domain for subdomain routing.
        You can use an IP address directly for TCP tunnels.
      </p>

      <h3>Is there a limit on the number of tunnels?</h3>
      <p>
        There is no hard-coded limit. The practical limit depends on your server's resources.
        Each tunnel uses minimal memory and CPU.
      </p>

      <h3>Does WireRift support HTTPS?</h3>
      <p>
        Yes. With <code>-auto-cert</code>, the server generates TLS certificates for the HTTPS
        edge. For production use, place a reverse proxy (nginx, Caddy) in front with Let's
        Encrypt certificates.
      </p>

      <h3>Can multiple clients connect simultaneously?</h3>
      <p>
        Yes. Each client gets its own session with independent tunnels. Multiple clients can
        run different subdomains on the same server.
      </p>

      <h3>What happens when the client disconnects?</h3>
      <p>
        The server detects the disconnection through heartbeat timeouts and cleans up all
        tunnels associated with that session. When the client reconnects (with auto-reconnect),
        it re-creates the tunnels.
      </p>

      <h3>How do I see traffic going through my tunnel?</h3>
      <p>
        Use the <code>-inspect</code> flag to enable the traffic inspector. All requests and responses
        are captured and viewable in the dashboard at <code>http://localhost:4040</code>. You can also
        replay any request from the dashboard.
      </p>

      <h3>Basic Auth returns 401 even with correct credentials</h3>
      <p>
        Make sure the format is <code>-auth "user:password"</code> (with colon separator).
        When using <code>curl</code>, pass credentials with <code>-u user:password</code>.
        If combining with PIN, the auth check runs first.
      </p>

      <h3>PIN cookie is not working across subdomains</h3>
      <p>
        PIN cookies are scoped to each subdomain (<code>wirerift_pin_&lt;subdomain&gt;</code>).
        Each tunnel has its own independent PIN session. Cookies use <code>SameSite=Strict</code>
        and <code>HttpOnly</code> for security.
      </p>

      <h3>Whitelist blocks my IP even though it should be allowed</h3>
      <p>
        Check if you are behind a NAT or proxy. The server sees the connecting IP, not your internal IP.
        Use <code>-v</code> on the server to see which IP is being checked. CIDR notation
        like <code>10.0.0.0/8</code> covers the entire range.
      </p>

      <Callout variant="info" title="Need more help?">
        If your issue is not covered here, open an issue on{' '}
        <a href="https://github.com/wirerift/wirerift/issues" target="_blank" rel="noopener noreferrer" className="underline">
          GitHub
        </a>.
      </Callout>
    </>
  ),
}
