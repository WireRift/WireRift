import { Link } from 'react-router'
import { motion } from 'framer-motion'
import { ArrowRight, Copy, Check, Apple, Monitor } from 'lucide-react'
import { CodeBlock } from '@/components/ui/CodeBlock'
import { SITE } from '@/lib/constants'
import { useState, useCallback } from 'react'

/* ─── animation presets ─── */
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

type Platform = 'mac' | 'linux' | 'windows'
const cmds: Record<Platform, string> = {
  mac: 'brew install wirerift/tap/wirerift',
  linux: 'go install github.com/wirerift/wirerift/cmd/wirerift@latest',
  windows: 'scoop install wirerift',
}

/* ─── sub-components ─── */
function PlatformPicker() {
  const [p, setP] = useState<Platform>('linux')
  const [copied, setCopied] = useState(false)
  const copy = useCallback(() => {
    navigator.clipboard.writeText(cmds[p]); setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }, [p])

  return (
    <div className="w-full max-w-lg mx-auto">
      <div className="flex items-center justify-center gap-1 mb-3">
        {([
          { id: 'mac' as Platform, icon: <Apple className="w-3.5 h-3.5" />, label: 'macOS' },
          { id: 'windows' as Platform, icon: <Monitor className="w-3.5 h-3.5" />, label: 'Windows' },
          { id: 'linux' as Platform, icon: <LinuxIcon />, label: 'Linux / Go' },
        ]).map(t => (
          <button key={t.id} onClick={() => setP(t.id)}
            className={`inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium transition-all cursor-pointer
              ${p === t.id ? 'bg-white/10 text-white' : 'text-white/40 hover:text-white/70'}`}
          >{t.icon}{t.label}</button>
        ))}
      </div>
      <div className="flex items-center gap-3 px-4 py-3 rounded-xl bg-white/[0.04] border border-white/[0.08] backdrop-blur-sm font-mono text-sm">
        <span className="text-white/30 select-none shrink-0">$</span>
        <span className="text-white/80 flex-1 truncate">{cmds[p]}</span>
        <button onClick={copy} className="shrink-0 p-1.5 rounded-md text-white/30 hover:text-white hover:bg-white/10 transition-all cursor-pointer" aria-label="Copy">
          {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
        </button>
      </div>
      <div className="mt-2.5 text-center">
        <Link to="/download" className="text-[11px] uppercase tracking-[0.15em] font-medium text-white/25 hover:text-white/50 transition-colors">
          Download and setup instructions <ArrowRight className="w-3 h-3 inline ml-0.5" />
        </Link>
      </div>
    </div>
  )
}

function LinuxIcon() {
  return <svg viewBox="0 0 24 24" className="w-3.5 h-3.5" fill="currentColor"><path d="M12.504 0c-.155 0-.311.004-.466.013-2.614.137-5.156 1.27-7.105 3.22C2.984 5.182 1.85 7.724 1.713 10.338c-.137 2.614.583 5.155 2.001 7.105 1.42 1.95 3.539 3.346 5.885 3.891.455.106.77-.195.77-.555v-2.013c0-.344-.002-.866-.002-1.647-3.32.68-4.03-1.423-4.03-1.423-.544-1.384-1.328-1.752-1.328-1.752-1.086-.743.082-.728.082-.728 1.2.084 1.833 1.233 1.833 1.233 1.067 1.827 2.8 1.299 3.48.993.108-.773.418-1.299.762-1.598-2.665-.303-5.466-1.332-5.466-5.93 0-1.311.469-2.381 1.236-3.221-.124-.303-.535-1.524.117-3.176 0 0 1.008-.322 3.3 1.23a11.5 11.5 0 013.006-.404c1.02.005 2.047.138 3.006.404 2.29-1.552 3.297-1.23 3.297-1.23.653 1.653.242 2.874.118 3.176.77.84 1.235 1.911 1.235 3.221 0 4.609-2.807 5.624-5.479 5.921.43.372.823 1.102.823 2.222v3.293c0 .322.218.694.825.577 4.765-1.588 8.199-6.084 8.199-11.386C24 5.377 18.627 0 12.504 0z"/></svg>
}

/* ─── main hero ─── */
export function Hero() {
  return (
    <section className="relative overflow-hidden" style={{ background: '#050a15' }}>

      {/* ── animated background layers ── */}
      {/* Top center glow */}
      <div className="absolute top-[-200px] left-1/2 -translate-x-1/2 w-[1000px] h-[600px] rounded-full opacity-40"
        style={{ background: 'radial-gradient(ellipse, rgba(99,102,241,0.15) 0%, rgba(59,130,246,0.08) 40%, transparent 70%)' }} />
      {/* Left accent */}
      <div className="absolute top-[30%] left-[-100px] w-[500px] h-[500px] rounded-full opacity-30"
        style={{ background: 'radial-gradient(circle, rgba(59,130,246,0.12) 0%, transparent 60%)' }} />
      {/* Right accent */}
      <div className="absolute top-[40%] right-[-100px] w-[400px] h-[400px] rounded-full opacity-25"
        style={{ background: 'radial-gradient(circle, rgba(168,85,247,0.12) 0%, transparent 60%)' }} />
      {/* Noise texture overlay */}
      <div className="absolute inset-0 opacity-[0.015]"
        style={{ backgroundImage: `url("data:image/svg+xml,%3Csvg viewBox='0 0 256 256' xmlns='http://www.w3.org/2000/svg'%3E%3Cfilter id='n'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='.9' numOctaves='4' stitchTiles='stitch'/%3E%3C/filter%3E%3Crect width='100%25' height='100%25' filter='url(%23n)'/%3E%3C/svg%3E")` }} />
      {/* Dot grid */}
      <div className="absolute inset-0 opacity-[0.04]"
        style={{
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
              className="group inline-flex items-center gap-2.5 pl-1 pr-4 py-1 rounded-full border border-white/[0.06] bg-white/[0.03] hover:bg-white/[0.06] hover:border-white/[0.1] transition-all backdrop-blur-sm"
            >
              <span className="px-2.5 py-1 rounded-full bg-emerald-500/15 text-emerald-400 text-[10px] font-bold uppercase tracking-wider leading-none">New</span>
              <span className="text-[13px] text-white/50 group-hover:text-white/70 transition-colors">
                v{SITE.version} — Open Source Release
              </span>
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
                Get Started (Free)
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
            <p className="text-center text-[10px] uppercase tracking-[0.25em] text-white/20 font-medium mb-5">
              Try WireRift by exposing a local app. Right now.
            </p>
            <PlatformPicker />
          </motion.div>

          {/* Code showcase */}
          <motion.div variants={scaleIn} className="mt-14 md:mt-18 max-w-2xl mx-auto">
            <div className="relative group">
              {/* Outer glow */}
              <div className="absolute -inset-[1px] rounded-2xl bg-gradient-to-b from-white/[0.08] via-white/[0.03] to-transparent" />
              <div className="absolute -inset-8 rounded-3xl opacity-0 group-hover:opacity-100 transition-opacity duration-700"
                style={{ background: 'radial-gradient(circle, rgba(99,102,241,0.06) 0%, transparent 70%)' }} />
              {/* Code */}
              <div className="relative rounded-2xl overflow-hidden bg-[#0d1117]">
                <CodeBlock
                  code={heroCode}
                  language="bash"
                  filename="terminal"
                  lineNumbers={true}
                  showLanguageBadge={false}
                  forceDark={true}
                />
              </div>
            </div>
          </motion.div>

          {/* Bottom stats */}
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

      {/* Bottom fade to page bg */}
      <div className="h-24 md:h-32 bg-gradient-to-b from-[#050a15] to-[var(--color-bg)]" />
    </section>
  )
}
