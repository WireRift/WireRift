import { Link } from 'react-router'
import { motion } from 'framer-motion'
import { ArrowRight, Github, Terminal } from 'lucide-react'
import { Button } from '@/components/ui/Button'
import { Badge } from '@/components/ui/Badge'
import { CodeBlock } from '@/components/ui/CodeBlock'
import { CopyButton } from '@/components/ui/CopyButton'
import { SITE } from '@/lib/constants'

const containerVariants = {
  hidden: { opacity: 0 },
  visible: {
    opacity: 1,
    transition: { staggerChildren: 0.1, delayChildren: 0.1 },
  },
} as const

const itemVariants = {
  hidden: { opacity: 0, y: 20 },
  visible: { opacity: 1, y: 0, transition: { duration: 0.5, ease: 'easeOut' as const } },
}

const pills = [
  'Zero Deps',
  'Single Binary',
  '100% Tested',
  'Auto TLS',
]

const heroCode = `# Start the server
wirerift-server -domain mytunnel.com -auto-cert

# Expose local HTTP service
wirerift http 8080

# With custom subdomain
wirerift http 8080 myapp
# => https://myapp.mytunnel.com

# TCP tunnel for game servers
wirerift tcp 25565`

export function Hero() {
  const installCmd = SITE.installCommand

  return (
    <section className="hero-gradient-bg relative">
      {/* Grid background */}
      <div className="hero-grid" />

      {/* Particles */}
      <div className="particle" style={{ top: '15%', left: '10%' }} />
      <div className="particle" style={{ top: '25%', left: '85%' }} />
      <div className="particle" style={{ top: '60%', left: '20%' }} />
      <div className="particle" style={{ top: '70%', left: '75%' }} />
      <div className="particle" style={{ top: '40%', left: '50%' }} />
      <div className="particle" style={{ top: '80%', left: '40%' }} />
      <div className="particle" style={{ top: '10%', left: '65%' }} />
      <div className="particle" style={{ top: '50%', left: '5%' }} />

      <div className="relative max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-20 md:py-28 lg:py-36">
        <motion.div
          variants={containerVariants}
          initial="hidden"
          animate="visible"
          className="text-center"
        >
          {/* Version badge */}
          <motion.div variants={itemVariants} className="mb-6">
            <Badge variant="version">v{SITE.version}</Badge>
          </motion.div>

          {/* Title */}
          <motion.h1
            variants={itemVariants}
            className="text-5xl sm:text-6xl md:text-7xl lg:text-8xl font-bold tracking-tight"
          >
            <span className="gradient-text">{SITE.name}</span>
          </motion.h1>

          {/* Tagline */}
          <motion.p
            variants={itemVariants}
            className="mt-4 md:mt-6 text-lg md:text-xl text-[var(--color-text-muted)] max-w-2xl mx-auto leading-relaxed"
          >
            {SITE.tagline}
          </motion.p>

          {/* CTA Buttons */}
          <motion.div
            variants={itemVariants}
            className="mt-8 md:mt-10 flex flex-col sm:flex-row items-center justify-center gap-3"
          >
            <Link to="/docs/getting-started">
              <Button size="lg">
                Get Started
                <ArrowRight className="w-4 h-4" />
              </Button>
            </Link>
            <a href={SITE.repo} target="_blank" rel="noopener noreferrer">
              <Button variant="secondary" size="lg">
                <Github className="w-4 h-4" />
                GitHub
              </Button>
            </a>
          </motion.div>

          {/* Install command */}
          <motion.div
            variants={itemVariants}
            className="mt-6 flex items-center justify-center"
          >
            <div className="inline-flex items-center gap-2 px-4 py-2.5 rounded-xl bg-[var(--color-bg-code)] border border-[var(--color-border)] font-mono text-sm text-[var(--color-text-muted)]">
              <Terminal className="w-4 h-4 shrink-0" />
              <span className="truncate max-w-[300px] sm:max-w-none">{installCmd}</span>
              <CopyButton text={installCmd} />
            </div>
          </motion.div>

          {/* Feature pills */}
          <motion.div
            variants={itemVariants}
            className="mt-8 flex flex-wrap items-center justify-center gap-2"
          >
            {pills.map((pill) => (
              <span
                key={pill}
                className="inline-flex items-center px-3 py-1 rounded-full text-xs font-medium bg-[var(--color-bg-tertiary)] text-[var(--color-text-muted)] border border-[var(--color-border)]"
              >
                {pill}
              </span>
            ))}
          </motion.div>

          {/* Hero code block */}
          <motion.div
            variants={itemVariants}
            className="mt-12 md:mt-16 max-w-2xl mx-auto text-left"
          >
            <div className="relative rounded-2xl overflow-hidden shadow-2xl" style={{ boxShadow: 'var(--shadow-glow)' }}>
              <CodeBlock
                code={heroCode}
                language="bash"
                filename="terminal"
              />
            </div>
          </motion.div>
        </motion.div>
      </div>
    </section>
  )
}
