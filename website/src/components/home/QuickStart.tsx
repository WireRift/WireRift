import { motion } from 'framer-motion'
import { Download, Server, Zap, Shield, Eye } from 'lucide-react'
import { CodeBlock } from '@/components/ui/CodeBlock'

const steps = [
  {
    icon: Download,
    number: '01',
    title: 'Install',
    description: 'Install the WireRift client and server binaries with Go.',
    code: `go install github.com/wirerift/wirerift/cmd/wirerift@latest
go install github.com/wirerift/wirerift/cmd/wirerift-server@latest`,
    language: 'bash',
    filename: 'install.sh',
  },
  {
    icon: Server,
    number: '02',
    title: 'Start Server',
    description: 'Run the tunnel server on your VPS or cloud instance.',
    code: `wirerift-server -domain mytunnel.com -auto-cert`,
    language: 'bash',
    filename: 'server.sh',
  },
  {
    icon: Zap,
    number: '03',
    title: 'Create Tunnel',
    description: 'Expose your local service or serve static files.',
    code: `# HTTP tunnel
wirerift http 8080 myapp

# Serve static files
wirerift serve ./dist -subdomain mysite

# TCP tunnel (databases, SSH, games)
wirerift tcp 5432`,
    language: 'bash',
    filename: 'tunnel.sh',
  },
  {
    icon: Shield,
    number: '04',
    title: 'Secure It',
    description: 'Add access control with auth, PIN, or IP whitelist.',
    code: `# Basic Auth
wirerift http 8080 -auth "admin:secret"

# PIN protection
wirerift http 8080 -pin mysecret

# IP whitelist + custom headers
wirerift http 8080 -whitelist "10.0.0.0/8" \\
  -header "X-Frame-Options:DENY"`,
    language: 'bash',
    filename: 'secure.sh',
  },
  {
    icon: Eye,
    number: '05',
    title: 'Inspect Traffic',
    description: 'Enable the traffic inspector and replay requests from the dashboard.',
    code: `# Enable traffic inspector
wirerift http 8080 -inspect

# Dashboard at http://localhost:4040
# → Live request/response log
# → One-click request replay
# → Header inspection`,
    language: 'bash',
    filename: 'inspect.sh',
  },
]

const containerVariants = {
  hidden: { opacity: 0 },
  visible: {
    opacity: 1,
    transition: { staggerChildren: 0.15 },
  },
} as const

const itemVariants = {
  hidden: { opacity: 0, y: 30 },
  visible: { opacity: 1, y: 0, transition: { duration: 0.5, ease: 'easeOut' as const } },
}

export function QuickStart() {
  return (
    <section className="py-20 md:py-28">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        {/* Section header */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true, margin: '-100px' }}
          transition={{ duration: 0.5 }}
          className="text-center mb-16"
        >
          <h2 className="text-3xl md:text-4xl font-bold text-[var(--color-text-heading)]">
            Up and running in minutes
          </h2>
          <p className="mt-4 text-lg text-[var(--color-text-muted)] max-w-2xl mx-auto">
            Five steps from install to production-ready tunnels with full access control.
          </p>
        </motion.div>

        {/* Steps */}
        <motion.div
          variants={containerVariants}
          initial="hidden"
          whileInView="visible"
          viewport={{ once: true, margin: '-50px' }}
          className="space-y-12 max-w-3xl mx-auto"
        >
          {steps.map((step) => {
            const Icon = step.icon
            return (
              <motion.div
                key={step.number}
                variants={itemVariants}
                className="relative"
              >
                <div className="flex items-start gap-6">
                  {/* Step indicator */}
                  <div className="shrink-0 flex flex-col items-center">
                    <div className="w-12 h-12 rounded-2xl bg-gradient-to-br from-primary-500 to-accent-500 flex items-center justify-center text-white shadow-md">
                      <Icon className="w-5 h-5" />
                    </div>
                    <span className="mt-2 text-xs font-mono font-bold text-[var(--color-text-muted)]">
                      {step.number}
                    </span>
                  </div>

                  {/* Content */}
                  <div className="flex-1 min-w-0">
                    <h3 className="text-xl font-semibold text-[var(--color-text-heading)] mb-1">
                      {step.title}
                    </h3>
                    <p className="text-[var(--color-text-muted)] mb-4">
                      {step.description}
                    </p>
                    <CodeBlock
                      code={step.code}
                      language={step.language}
                      filename={step.filename}
                      lineNumbers={true}
                    />
                  </div>
                </div>
              </motion.div>
            )
          })}
        </motion.div>
      </div>
    </section>
  )
}
