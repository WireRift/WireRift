import { motion } from 'framer-motion'
import { Badge } from '@/components/ui/Badge'

interface ChangelogEntry {
  version: string
  date: string
  title: string
  changes: {
    type: 'added' | 'changed' | 'fixed' | 'removed'
    description: string
  }[]
}

const changelog: ChangelogEntry[] = [
  {
    version: '1.2.0',
    date: '2026-03-16',
    title: 'Traffic Inspector, Auth & Developer Tools',
    changes: [
      { type: 'added', description: 'Traffic Inspector - real-time request/response capture in dashboard' },
      { type: 'added', description: 'Request Replay - replay any captured request from dashboard or API' },
      { type: 'added', description: 'Basic Auth - HTTP Basic Authentication per tunnel with constant-time comparison' },
      { type: 'added', description: 'Custom Response Headers - inject headers into tunnel responses' },
      { type: 'added', description: 'File Server Mode - wirerift serve ./dist to serve static files' },
      { type: 'added', description: 'Webhook Relay - fan-out incoming requests to multiple local endpoints' },
      { type: 'added', description: 'Dashboard Traffic Inspector panel with auto-refresh and filtering' },
      { type: 'added', description: 'API: GET /api/requests and POST /api/requests/{id}/replay' },
      { type: 'added', description: 'CLI flags: -auth, -inspect, -header for HTTP tunnels' },
      { type: 'added', description: 'Config file support for auth, inspect, and headers per tunnel' },
    ],
  },
  {
    version: '1.1.0',
    date: '2026-03-15',
    title: 'Access Control & Security Hardening',
    changes: [
      { type: 'added', description: 'IP Whitelist - restrict tunnel access by IP address or CIDR range' },
      { type: 'added', description: 'PIN Protection - require PIN via browser form, header, or query param' },
      { type: 'added', description: 'TCP tunnel whitelist enforcement' },
      { type: 'added', description: 'Dashboard Protection column showing IP/PIN indicators' },
      { type: 'added', description: 'Gzip compression middleware' },
      { type: 'added', description: 'Server-side bytes tracking in Stats API' },
      { type: 'fixed', description: 'PIN comparison uses constant-time to prevent timing attacks' },
      { type: 'fixed', description: 'PIN cookie stores HMAC instead of raw PIN value' },
      { type: 'fixed', description: 'Stream ID 0 collision with control stream' },
      { type: 'fixed', description: 'Ring buffer stale pointer corruption on grow' },
      { type: 'fixed', description: 'Port allocation race condition and off-by-one' },
      { type: 'fixed', description: 'Mask dev token in server startup logs' },
      { type: 'fixed', description: 'Unbiased random string generation (rejection sampling)' },
      { type: 'fixed', description: 'Subdomain validation against injection attacks' },
      { type: 'fixed', description: 'TLS certificate files written with 0600 permissions' },
      { type: 'fixed', description: 'Graceful shutdown timeout (was unbounded)' },
      { type: 'removed', description: '3,100 lines of dead code removed (~15% reduction)' },
      { type: 'removed', description: 'Unused packages: metrics, middleware, version' },
    ],
  },
  {
    version: '1.0.0',
    date: '2026-03-15',
    title: 'Initial Release',
    changes: [
      { type: 'added', description: 'HTTP tunnel support with subdomain routing' },
      { type: 'added', description: 'TCP tunnel support with dynamic port allocation (20000-29999)' },
      { type: 'added', description: 'Custom binary protocol with 9-byte frame header' },
      { type: 'added', description: 'Stream multiplexing over single TCP connection' },
      { type: 'added', description: 'Window-based flow control with per-stream backpressure' },
      { type: 'added', description: 'Auto TLS with self-signed certificate generation' },
      { type: 'added', description: 'WebSocket passthrough with protocol upgrade handling' },
      { type: 'added', description: 'Custom domain support with DNS verification' },
      { type: 'added', description: 'Built-in web dashboard on port 4040' },
      { type: 'added', description: 'REST API for tunnel management and monitoring' },
      { type: 'added', description: 'Token-based authentication system' },
      { type: 'added', description: 'Rate limiting (per-IP HTTP, per-session tunnel)' },
      { type: 'added', description: 'Automatic reconnection with exponential backoff' },
      { type: 'added', description: 'Session timeout cleanup for idle connections' },
      { type: 'added', description: 'YAML configuration file support' },
      { type: 'added', description: 'Heartbeat/keepalive mechanism' },
      { type: 'added', description: 'Comprehensive test suite with CI coverage enforcement' },
      { type: 'added', description: 'Zero external dependencies - Go stdlib only' },
    ],
  },
]

const typeColors: Record<string, string> = {
  added: 'text-emerald-600 dark:text-emerald-400',
  changed: 'text-blue-600 dark:text-blue-400',
  fixed: 'text-amber-600 dark:text-amber-400',
  removed: 'text-red-600 dark:text-red-400',
}

const typeLabels: Record<string, string> = {
  added: 'Added',
  changed: 'Changed',
  fixed: 'Fixed',
  removed: 'Removed',
}

const containerVariants = {
  hidden: { opacity: 0 },
  visible: {
    opacity: 1,
    transition: { staggerChildren: 0.1 },
  },
}

const itemVariants = {
  hidden: { opacity: 0, x: -20 },
  visible: { opacity: 1, x: 0, transition: { duration: 0.4 } },
}

export default function ChangelogPage() {
  return (
    <div className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8 py-16 md:py-24">
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.5 }}
      >
        <h1 className="text-3xl md:text-4xl font-bold text-[var(--color-text-heading)] mb-4">
          Changelog
        </h1>
        <p className="text-lg text-[var(--color-text-muted)] mb-12">
          All notable changes to WireRift are documented here.
        </p>
      </motion.div>

      <motion.div
        variants={containerVariants}
        initial="hidden"
        animate="visible"
        className="space-y-12"
      >
        {changelog.map((entry) => (
          <motion.div
            key={entry.version}
            variants={itemVariants}
            className="relative pl-8 border-l-2 border-[var(--color-border)]"
          >
            {/* Timeline dot */}
            <div className="absolute left-[-9px] top-0 w-4 h-4 rounded-full bg-gradient-to-r from-primary-500 to-accent-500 ring-4 ring-[var(--color-bg)]" />

            {/* Header */}
            <div className="flex flex-wrap items-center gap-3 mb-4">
              <Badge variant="version">v{entry.version}</Badge>
              <span className="text-sm text-[var(--color-text-muted)]">{entry.date}</span>
            </div>
            <h2 className="text-xl font-semibold text-[var(--color-text-heading)] mb-4">
              {entry.title}
            </h2>

            {/* Changes grouped by type */}
            {(['added', 'changed', 'fixed', 'removed'] as const).map((type) => {
              const items = entry.changes.filter((c) => c.type === type)
              if (items.length === 0) return null
              return (
                <div key={type} className="mb-4">
                  <h3 className={`text-sm font-semibold uppercase tracking-wider mb-2 ${typeColors[type]}`}>
                    {typeLabels[type]}
                  </h3>
                  <ul className="space-y-1.5">
                    {items.map((change, i) => (
                      <li
                        key={i}
                        className="text-sm text-[var(--color-text)] leading-relaxed flex items-start gap-2"
                      >
                        <span className="mt-2 w-1.5 h-1.5 rounded-full bg-[var(--color-text-muted)] shrink-0" />
                        {change.description}
                      </li>
                    ))}
                  </ul>
                </div>
              )
            })}
          </motion.div>
        ))}
      </motion.div>
    </div>
  )
}
