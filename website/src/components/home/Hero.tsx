import { Link } from 'react-router'
import { motion } from 'framer-motion'
import { ArrowRight, Github, Copy, Check, Apple, Monitor } from 'lucide-react'
import { CodeBlock } from '@/components/ui/CodeBlock'
import { SITE } from '@/lib/constants'
import { useState, useCallback } from 'react'

const stagger = {
  hidden: { opacity: 0 },
  visible: { opacity: 1, transition: { staggerChildren: 0.1, delayChildren: 0.2 } },
} as const

const fadeUp = {
  hidden: { opacity: 0, y: 20 },
  visible: {
    opacity: 1, y: 0,
    transition: { duration: 0.6, ease: [0.25, 0.46, 0.45, 0.94] as const },
  },
}

const heroCode = `# Start your tunnel server
wirerift-server -domain mytunnel.com -auto-cert -v

# Expose any local service instantly
wirerift http 8080 myapp
# => https://myapp.mytunnel.com

# Forward raw TCP (databases, games, SSH...)
wirerift tcp 5432`

type Platform = 'mac' | 'linux' | 'windows'

const installCommands: Record<Platform, string> = {
  mac: 'brew install wirerift/tap/wirerift',
  linux: 'go install github.com/wirerift/wirerift/cmd/wirerift@latest',
  windows: 'scoop install wirerift',
}

function InstallBlock() {
  const [platform, setPlatform] = useState<Platform>('linux')
  const [copied, setCopied] = useState(false)

  const copy = useCallback(() => {
    navigator.clipboard.writeText(installCommands[platform])
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }, [platform])

  return (
    <div className="w-full max-w-md mx-auto">
      {/* Platform tabs */}
      <div className="flex items-center justify-center gap-3 mb-4">
        <PlatformTab icon={<Apple className="w-4 h-4" />} label="macOS" active={platform === 'mac'} onClick={() => setPlatform('mac')} />
        <PlatformTab icon={<Monitor className="w-4 h-4" />} label="Windows" active={platform === 'windows'} onClick={() => setPlatform('windows')} />
        <PlatformTab icon={<svg viewBox="0 0 24 24" className="w-4 h-4" fill="currentColor"><path d="M12.504 0c-.155 0-.311.004-.466.013-2.614.137-5.156 1.27-7.105 3.22C2.984 5.182 1.85 7.724 1.713 10.338c-.137 2.614.583 5.155 2.001 7.105 1.42 1.95 3.539 3.346 5.885 3.891.455.106.77-.195.77-.555v-2.013c0-.344-.002-.866-.002-1.647-3.32.68-4.03-1.423-4.03-1.423-.544-1.384-1.328-1.752-1.328-1.752-1.086-.743.082-.728.082-.728 1.2.084 1.833 1.233 1.833 1.233 1.067 1.827 2.8 1.299 3.48.993.108-.773.418-1.299.762-1.598-2.665-.303-5.466-1.332-5.466-5.93 0-1.311.469-2.381 1.236-3.221-.124-.303-.535-1.524.117-3.176 0 0 1.008-.322 3.3 1.23a11.5 11.5 0 013.006-.404c1.02.005 2.047.138 3.006.404 2.29-1.552 3.297-1.23 3.297-1.23.653 1.653.242 2.874.118 3.176.77.84 1.235 1.911 1.235 3.221 0 4.609-2.807 5.624-5.479 5.921.43.372.823 1.102.823 2.222v3.293c0 .322.218.694.825.577 4.765-1.588 8.199-6.084 8.199-11.386C24 5.377 18.627 0 12.504 0z"/></svg>} label="Linux" active={platform === 'linux'} onClick={() => setPlatform('linux')} />
      </div>

      {/* Command */}
      <div className="relative flex items-center gap-3 px-4 py-3 rounded-xl bg-[#0d1117] border border-[#30363d] font-mono text-sm">
        <span className="text-[#8b949e] select-none">$</span>
        <span className="text-[#e6edf3] flex-1 truncate">{installCommands[platform]}</span>
        <button
          onClick={copy}
          className="shrink-0 p-1 rounded text-[#8b949e] hover:text-[#e6edf3] transition-colors cursor-pointer"
          aria-label="Copy command"
        >
          {copied ? <Check className="w-4 h-4 text-emerald-400" /> : <Copy className="w-4 h-4" />}
        </button>
      </div>

      <div className="mt-3 text-center">
        <Link to="/download" className="text-xs text-[var(--color-text-muted)] hover:text-[var(--color-text-heading)] transition-colors uppercase tracking-widest font-medium">
          Download and setup instructions <ArrowRight className="w-3 h-3 inline" />
        </Link>
      </div>
    </div>
  )
}

function PlatformTab({ icon, label, active, onClick }: { icon: React.ReactNode; label: string; active: boolean; onClick: () => void }) {
  return (
    <button
      onClick={onClick}
      className={`inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium transition-all cursor-pointer ${
        active
          ? 'bg-[#21262d] text-[#e6edf3] border border-[#30363d]'
          : 'text-[#8b949e] hover:text-[#e6edf3]'
      }`}
    >
      {icon}
      {label}
    </button>
  )
}

export function Hero() {
  return (
    <section className="relative overflow-hidden bg-[#010409]">
      {/* Background effects */}
      <div className="absolute inset-0">
        {/* Center glow */}
        <div className="absolute top-0 left-1/2 -translate-x-1/2 w-[900px] h-[600px] bg-gradient-to-b from-blue-500/[0.07] via-violet-500/[0.05] to-transparent rounded-full blur-[80px]" />
        {/* Side accents */}
        <div className="absolute top-1/3 left-0 w-[300px] h-[300px] bg-blue-500/[0.03] rounded-full blur-[60px]" />
        <div className="absolute top-1/2 right-0 w-[300px] h-[300px] bg-violet-500/[0.03] rounded-full blur-[60px]" />
        {/* Grid */}
        <div className="absolute inset-0 opacity-[0.03]" style={{
          backgroundImage: 'linear-gradient(#fff 1px, transparent 1px), linear-gradient(90deg, #fff 1px, transparent 1px)',
          backgroundSize: '64px 64px',
          maskImage: 'radial-gradient(ellipse 70% 50% at 50% 30%, black 0%, transparent 70%)',
          WebkitMaskImage: 'radial-gradient(ellipse 70% 50% at 50% 30%, black 0%, transparent 70%)',
        }} />
      </div>

      {/* Content */}
      <div className="relative max-w-5xl mx-auto px-5 sm:px-8 pt-28 pb-12 md:pt-36 md:pb-20 lg:pt-44 lg:pb-24">
        <motion.div variants={stagger} initial="hidden" animate="visible">

          {/* Announcement pill */}
          <motion.div variants={fadeUp} className="flex justify-center mb-8">
            <Link to="/changelog" className="group inline-flex items-center gap-2 px-4 py-2 rounded-full bg-[#161b22] border border-[#30363d] hover:border-[#484f58] transition-colors">
              <span className="px-2 py-0.5 rounded-full bg-emerald-500/20 text-emerald-400 text-[10px] font-bold uppercase tracking-wider">New</span>
              <span className="text-sm text-[#8b949e] group-hover:text-[#e6edf3] transition-colors">v{SITE.version} — Open Source Release</span>
              <ArrowRight className="w-3 h-3 text-[#484f58] group-hover:text-[#8b949e] transition-colors" />
            </Link>
          </motion.div>

          {/* Main headline */}
          <motion.h1 variants={fadeUp} className="text-center">
            <span className="block text-[2.5rem] sm:text-5xl md:text-6xl lg:text-[4.5rem] font-bold tracking-tight text-[#e6edf3] leading-[1.1]">
              Tear a rift through the wire.
            </span>
            <span className="block mt-2 sm:mt-3 text-[2.5rem] sm:text-5xl md:text-6xl lg:text-[4.5rem] font-bold tracking-tight leading-[1.1]" style={{
              background: 'linear-gradient(135deg, #58a6ff 0%, #a78bfa 50%, #f472b6 100%)',
              WebkitBackgroundClip: 'text',
              WebkitTextFillColor: 'transparent',
              backgroundClip: 'text',
            }}>
              Expose localhost to the world.
            </span>
          </motion.h1>

          {/* Subtitle */}
          <motion.p variants={fadeUp} className="mt-6 md:mt-8 text-center text-base sm:text-lg md:text-xl text-[#8b949e] max-w-2xl mx-auto leading-relaxed">
            Self-hosted tunnel server written in Go —{' '}
            with built-in security, stream multiplexing, and traffic management.
          </motion.p>

          {/* CTA Buttons */}
          <motion.div variants={fadeUp} className="mt-10 flex flex-col sm:flex-row items-center justify-center gap-3 sm:gap-4">
            <Link to="/docs/getting-started" className="w-full sm:w-auto">
              <button className="w-full sm:w-auto inline-flex items-center justify-center gap-2 px-8 py-3.5 text-sm font-bold uppercase tracking-wider rounded-xl text-white bg-[#e6edf3] text-[#010409] hover:bg-white transition-all duration-200 cursor-pointer">
                Get Started
              </button>
            </Link>
            <Link to="/docs/quick-start" className="w-full sm:w-auto">
              <button className="w-full sm:w-auto inline-flex items-center justify-center gap-2 px-8 py-3.5 text-sm font-bold uppercase tracking-wider rounded-xl text-[#e6edf3] border border-[#30363d] hover:border-[#484f58] hover:bg-[#161b22] transition-all duration-200 cursor-pointer">
                Deploy in 5 Minutes
              </button>
            </Link>
          </motion.div>

          {/* Install section */}
          <motion.div variants={fadeUp} className="mt-14 md:mt-16">
            <p className="text-center text-[10px] uppercase tracking-[0.2em] text-[#484f58] font-medium mb-4">
              Try WireRift by exposing a local app. Right now.
            </p>
            <InstallBlock />
          </motion.div>

          {/* Code showcase */}
          <motion.div
            variants={fadeUp}
            className="mt-16 md:mt-20 max-w-2xl mx-auto"
          >
            <div className="relative">
              {/* Glow */}
              <div className="absolute -inset-px rounded-2xl bg-gradient-to-b from-[#30363d] to-transparent opacity-50" />
              <div className="absolute -inset-4 rounded-3xl bg-gradient-to-b from-blue-500/5 via-violet-500/5 to-transparent blur-xl" />
              <div className="relative rounded-2xl overflow-hidden border border-[#30363d] bg-[#0d1117]">
                <CodeBlock
                  code={heroCode}
                  language="bash"
                  filename="terminal"
                  lineNumbers={true}
                  showLanguageBadge={false}
                />
              </div>
            </div>
          </motion.div>

          {/* Stats bar */}
          <motion.div variants={fadeUp} className="mt-14 md:mt-16 flex flex-wrap items-center justify-center gap-x-8 gap-y-3 text-sm text-[#484f58]">
            <span>Zero dependencies</span>
            <span className="hidden sm:inline">·</span>
            <span>Single binary</span>
            <span className="hidden sm:inline">·</span>
            <span>Auto TLS</span>
            <span className="hidden sm:inline">·</span>
            <span>100% test coverage</span>
            <span className="hidden sm:inline">·</span>
            <a href={SITE.repo} target="_blank" rel="noopener noreferrer" className="inline-flex items-center gap-1 hover:text-[#8b949e] transition-colors">
              <Github className="w-3.5 h-3.5" />
              Open Source
            </a>
          </motion.div>

        </motion.div>
      </div>

      {/* Bottom fade */}
      <div className="absolute bottom-0 inset-x-0 h-32 bg-gradient-to-t from-[var(--color-bg)] to-transparent pointer-events-none" />
    </section>
  )
}
