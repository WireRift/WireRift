import { Link } from 'react-router'
import { motion } from 'framer-motion'
import { ArrowRight, Copy, Check, Download } from 'lucide-react'
import { CodeBlock } from '@/components/ui/CodeBlock'
import { SITE } from '@/lib/constants'
import { useState, useCallback } from 'react'

/* ─── animation ─── */
const stagger = {
  hidden: { opacity: 0 },
  visible: { opacity: 1, transition: { staggerChildren: 0.12, delayChildren: 0.3 } },
} as const

const rise = {
  hidden: { opacity: 0, y: 30 },
  visible: { opacity: 1, y: 0, transition: { duration: 0.7, ease: [0.22, 1, 0.36, 1] as const } },
}

const scaleIn = {
  hidden: { opacity: 0, y: 40, scale: 0.96 },
  visible: { opacity: 1, y: 0, scale: 1, transition: { duration: 0.8, ease: [0.22, 1, 0.36, 1] as const, delay: 0.5 } },
}

/* ─── data ─── */
const heroCode = `# Start your tunnel server
wirerift-server -domain mytunnel.com -auto-cert -v

# Expose any local service instantly
wirerift http 8080 myapp
# → https://myapp.mytunnel.com

# Forward raw TCP (databases, games, SSH...)
wirerift tcp 5432`

const goInstallCmd = 'go install github.com/wirerift/wirerift/cmd/wirerift@latest'

/* ─── install bar ─── */
function InstallBar() {
  const [copied, setCopied] = useState(false)
  const copy = useCallback(() => {
    navigator.clipboard.writeText(goInstallCmd)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }, [])

  return (
    <div className="w-full max-w-lg mx-auto">
      <div className="flex items-center gap-3 px-4 py-3 rounded-xl bg-white/[0.04] border border-white/[0.08] backdrop-blur-sm font-mono text-sm">
        <span className="text-white/30 select-none shrink-0">$</span>
        <span className="text-white/80 flex-1 truncate">{goInstallCmd}</span>
        <button onClick={copy} className="shrink-0 p-1.5 rounded-md text-white/30 hover:text-white hover:bg-white/10 transition-all cursor-pointer" aria-label="Copy">
          {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
        </button>
      </div>
      <div className="mt-3 flex items-center justify-center gap-4">
        <Link to="/download" className="text-[11px] uppercase tracking-[0.15em] font-medium text-white/25 hover:text-white/50 transition-colors inline-flex items-center gap-1">
          <Download className="w-3 h-3" />
          Download binaries
        </Link>
        <span className="text-white/10">|</span>
        <a href={SITE.repo} target="_blank" rel="noopener noreferrer" className="text-[11px] uppercase tracking-[0.15em] font-medium text-white/25 hover:text-white/50 transition-colors">
          View on GitHub <ArrowRight className="w-3 h-3 inline ml-0.5" />
        </a>
      </div>
    </div>
  )
}

/* ─── main hero ─── */
export function Hero() {
  return (
    <section className="relative overflow-hidden" style={{ background: '#050a15' }}>

      {/* ── background ── */}
      <div className="absolute top-[-200px] left-1/2 -translate-x-1/2 w-[1000px] h-[600px] rounded-full opacity-40"
        style={{ background: 'radial-gradient(ellipse, rgba(99,102,241,0.15) 0%, rgba(59,130,246,0.08) 40%, transparent 70%)' }} />
      <div className="absolute top-[30%] left-[-100px] w-[500px] h-[500px] rounded-full opacity-30"
        style={{ background: 'radial-gradient(circle, rgba(59,130,246,0.12) 0%, transparent 60%)' }} />
      <div className="absolute top-[40%] right-[-100px] w-[400px] h-[400px] rounded-full opacity-25"
        style={{ background: 'radial-gradient(circle, rgba(168,85,247,0.12) 0%, transparent 60%)' }} />
      <div className="absolute inset-0 opacity-[0.04]" style={{
        backgroundImage: 'radial-gradient(circle, rgba(255,255,255,0.8) 1px, transparent 1px)',
        backgroundSize: '32px 32px',
        maskImage: 'radial-gradient(ellipse 60% 50% at 50% 30%, black, transparent 70%)',
        WebkitMaskImage: 'radial-gradient(ellipse 60% 50% at 50% 30%, black, transparent 70%)',
      }} />

      {/* ── content ── */}
      <div className="relative max-w-5xl mx-auto px-5 sm:px-8 pt-24 pb-8 md:pt-32 md:pb-16 lg:pt-40 lg:pb-20">
        <motion.div variants={stagger} initial="hidden" animate="visible">

          {/* Announcement */}
          <motion.div variants={rise} className="flex justify-center mb-10">
            <Link to="/changelog"
              className="group inline-flex items-center gap-2.5 pl-1 pr-4 py-1 rounded-full border border-white/[0.06] bg-white/[0.03] hover:bg-white/[0.06] hover:border-white/[0.1] transition-all backdrop-blur-sm">
              <span className="px-2.5 py-1 rounded-full bg-emerald-500/15 text-emerald-400 text-[10px] font-bold uppercase tracking-wider leading-none">New</span>
              <span className="text-[13px] text-white/50 group-hover:text-white/70 transition-colors">v{SITE.version} — Open Source Release</span>
              <ArrowRight className="w-3 h-3 text-white/20 group-hover:text-white/40 group-hover:translate-x-0.5 transition-all" />
            </Link>
          </motion.div>

          {/* Headline */}
          <motion.h1 variants={rise} className="text-center max-w-4xl mx-auto">
            <span className="block text-[2.75rem] sm:text-[3.5rem] md:text-[4.25rem] lg:text-[5rem] font-extrabold tracking-[-0.025em] text-white leading-[1.05]">
              Tear a rift
            </span>
            <span className="block text-[2.75rem] sm:text-[3.5rem] md:text-[4.25rem] lg:text-[5rem] font-extrabold tracking-[-0.025em] text-white leading-[1.05]">
              through the wire.
            </span>
            <span className="block mt-1 text-[2.75rem] sm:text-[3.5rem] md:text-[4.25rem] lg:text-[5rem] font-extrabold tracking-[-0.025em] leading-[1.05]"
              style={{
                background: 'linear-gradient(135deg, #60a5fa 0%, #a78bfa 35%, #f472b6 65%, #fb923c 100%)',
                WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent', backgroundClip: 'text',
              }}>
              Expose localhost.
            </span>
          </motion.h1>

          {/* Subtitle */}
          <motion.p variants={rise} className="mt-6 md:mt-8 text-center text-[15px] sm:text-base md:text-lg text-white/40 max-w-xl mx-auto leading-relaxed">
            Connect any local service to the internet in one line —
            with built-in security, stream multiplexing, and traffic management.
          </motion.p>

          {/* CTA */}
          <motion.div variants={rise} className="mt-10 md:mt-12 flex flex-col sm:flex-row items-center justify-center gap-3">
            <Link to="/docs/getting-started" className="w-full sm:w-auto">
              <button className="w-full sm:w-auto px-8 py-3.5 text-[13px] font-bold uppercase tracking-[0.08em] rounded-xl bg-white text-[#050a15] hover:bg-white/90 shadow-lg shadow-white/5 transition-all cursor-pointer">
                Get Started
              </button>
            </Link>
            <Link to="/docs/quick-start" className="w-full sm:w-auto">
              <button className="w-full sm:w-auto px-8 py-3.5 text-[13px] font-bold uppercase tracking-[0.08em] rounded-xl text-white/80 border border-white/[0.1] hover:bg-white/[0.05] hover:border-white/[0.15] transition-all cursor-pointer">
                Deploy in 5 Minutes
              </button>
            </Link>
          </motion.div>

          {/* Install */}
          <motion.div variants={rise} className="mt-16 md:mt-20">
            <InstallBar />
          </motion.div>

          {/* Code */}
          <motion.div variants={scaleIn} className="mt-14 md:mt-18 max-w-2xl mx-auto">
            <div className="relative group">
              <div className="absolute -inset-[1px] rounded-2xl bg-gradient-to-b from-white/[0.08] via-white/[0.03] to-transparent" />
              <div className="absolute -inset-8 rounded-3xl opacity-0 group-hover:opacity-100 transition-opacity duration-700"
                style={{ background: 'radial-gradient(circle, rgba(99,102,241,0.06) 0%, transparent 70%)' }} />
              <div className="relative rounded-2xl overflow-hidden bg-[#0d1117]">
                <CodeBlock code={heroCode} language="bash" filename="terminal" lineNumbers={true} showLanguageBadge={false} forceDark={true} />
              </div>
            </div>
          </motion.div>

          {/* Stats */}
          <motion.div variants={rise} className="mt-14 md:mt-16 flex flex-wrap items-center justify-center gap-x-6 gap-y-2 text-[13px] text-white/20">
            {['Zero dependencies', 'Single binary', 'Auto TLS', '100% test coverage', 'MIT License'].map((s, i) => (
              <span key={s} className="flex items-center gap-6">
                {i > 0 && <span className="hidden sm:inline text-white/10">·</span>}
                {s}
              </span>
            ))}
          </motion.div>

        </motion.div>
      </div>

      {/* Bottom fade */}
      <div className="h-24 md:h-32 bg-gradient-to-b from-[#050a15] to-[var(--color-bg)]" />
    </section>
  )
}
