import { motion } from 'framer-motion'
import { Download, Server, Zap } from 'lucide-react'
import { CodeBlock } from '@/components/ui/CodeBlock'

const steps = [
  {
    icon: Download,
    number: '01',
    title: 'Install',
    description: 'Install the WireRift client and server binaries with Go.',
    code: `# Install the client
go install github.com/wirerift/wirerift/cmd/wirerift@latest

# Install the server
go install github.com/wirerift/wirerift/cmd/wirerift-server@latest`,
    language: 'bash',
  },
  {
    icon: Server,
    number: '02',
    title: 'Start Server',
    description: 'Run the tunnel server on your VPS or cloud instance.',
    code: `# Start with auto TLS on your domain
wirerift-server \\
  -domain mytunnel.com \\
  -auto-cert \\
  -v`,
    language: 'bash',
  },
  {
    icon: Zap,
    number: '03',
    title: 'Create Tunnel',
    description: 'Expose your local service to the internet instantly.',
    code: `# Expose local HTTP server on port 8080
wirerift http 8080

# Your service is now available at:
# https://<random-id>.mytunnel.com`,
    language: 'bash',
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
            Three steps to expose your local services to the internet. No configuration files needed.
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
