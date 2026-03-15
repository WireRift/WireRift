import { Link } from 'react-router'
import { motion } from 'framer-motion'
import { ArrowRight, Copy, Check, Download } from 'lucide-react'
import { CodeBlock } from '@/components/ui/CodeBlock'
import { useThemeStore } from '@/hooks/useTheme'
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

const heroCode = `# Start your tunnel server
wirerift-server -domain mytunnel.com -auto-cert -v

# Expose any local service instantly
wirerift http 8080 myapp
# → https://myapp.mytunnel.com

# Forward raw TCP (databases, games, SSH...)
wirerift tcp 5432`

const goInstallCmd = 'go install github.com/wirerift/wirerift/cmd/wirerift@latest'

/* ─── install bar ─── */
function InstallBar({ isDark }: { isDark: boolean }) {
  const [copied, setCopied] = useState(false)
  const copy = useCallback(() => {
    navigator.clipboard.writeText(goInstallCmd)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }, [])

  return (
    <div className="w-full max-w-lg mx-auto">
      <div className="flex items-center gap-3 px-4 py-3 rounded-xl font-mono text-sm"
        style={{
          backgroundColor: isDark ? 'rgba(255,255,255,0.04)' : 'rgba(0,0,0,0.04)',
          border: `1px solid ${isDark ? 'rgba(255,255,255,0.08)' : 'rgba(0,0,0,0.08)'}`,
        }}>
        <span style={{ color: isDark ? 'rgba(255,255,255,0.3)' : 'rgba(0,0,0,0.3)' }} className="select-none shrink-0">$</span>
        <span style={{ color: isDark ? 'rgba(255,255,255,0.8)' : 'rgba(0,0,0,0.7)' }} className="flex-1 truncate">{goInstallCmd}</span>
        <button onClick={copy} className="shrink-0 p-1.5 rounded-md transition-all cursor-pointer"
          style={{ color: isDark ? 'rgba(255,255,255,0.3)' : 'rgba(0,0,0,0.3)' }} aria-label="Copy">
          {copied ? <Check className="w-3.5 h-3.5 text-emerald-500" /> : <Copy className="w-3.5 h-3.5" />}
        </button>
      </div>
      <div className="mt-3 flex items-center justify-center gap-4">
        <Link to="/download" className="text-[11px] uppercase tracking-[0.15em] font-medium transition-colors inline-flex items-center gap-1"
          style={{ color: isDark ? 'rgba(255,255,255,0.25)' : 'rgba(0,0,0,0.3)' }}>
          <Download className="w-3 h-3" /> Download binaries
        </Link>
        <span style={{ color: isDark ? 'rgba(255,255,255,0.1)' : 'rgba(0,0,0,0.1)' }}>|</span>
        <a href={SITE.repo} target="_blank" rel="noopener noreferrer" className="text-[11px] uppercase tracking-[0.15em] font-medium transition-colors"
          style={{ color: isDark ? 'rgba(255,255,255,0.25)' : 'rgba(0,0,0,0.3)' }}>
          View on GitHub <ArrowRight className="w-3 h-3 inline ml-0.5" />
        </a>
      </div>
    </div>
  )
}

/* ─── main ─── */
export function Hero() {
  const isDark = useThemeStore((s) => s.resolved) === 'dark'

  const bg = isDark ? '#050a15' : '#f8fafc'
  const headingColor = isDark ? '#ffffff' : '#0f172a'
  const subColor = isDark ? 'rgba(255,255,255,0.4)' : 'rgba(15,23,42,0.5)'
  const statColor = isDark ? 'rgba(255,255,255,0.2)' : 'rgba(15,23,42,0.25)'
  const dotColor = isDark ? 'rgba(255,255,255,0.08)' : 'rgba(15,23,42,0.06)'

  return (
    <section className="relative overflow-hidden" style={{ background: bg }}>

      {/* ── background ── */}
      {isDark && (
        <>
          <div className="absolute top-[-200px] left-1/2 -translate-x-1/2 w-[1000px] h-[600px] rounded-full opacity-40"
            style={{ background: 'radial-gradient(ellipse, rgba(99,102,241,0.15) 0%, rgba(59,130,246,0.08) 40%, transparent 70%)' }} />
          <div className="absolute top-[30%] left-[-100px] w-[500px] h-[500px] rounded-full opacity-30"
            style={{ background: 'radial-gradient(circle, rgba(59,130,246,0.12) 0%, transparent 60%)' }} />
          <div className="absolute top-[40%] right-[-100px] w-[400px] h-[400px] rounded-full opacity-25"
            style={{ background: 'radial-gradient(circle, rgba(168,85,247,0.12) 0%, transparent 60%)' }} />
        </>
      )}
      {!isDark && (
        <>
          <div className="absolute top-[-100px] left-1/2 -translate-x-1/2 w-[800px] h-[500px] rounded-full"
            style={{ background: 'radial-gradient(ellipse, rgba(59,130,246,0.06) 0%, transparent 70%)' }} />
          <div className="absolute top-[40%] right-[-50px] w-[400px] h-[400px] rounded-full"
            style={{ background: 'radial-gradient(circle, rgba(139,92,246,0.04) 0%, transparent 60%)' }} />
        </>
      )}
      <div className="absolute inset-0" style={{
        backgroundImage: `radial-gradient(circle, ${dotColor} 1px, transparent 1px)`,
        backgroundSize: '32px 32px',
        maskImage: 'radial-gradient(ellipse 60% 50% at 50% 30%, black, transparent 70%)',
        WebkitMaskImage: 'radial-gradient(ellipse 60% 50% at 50% 30%, black, transparent 70%)',
      }} />

      {/* ── content ── */}
      <div className="relative max-w-5xl mx-auto px-5 sm:px-8 pt-24 pb-8 md:pt-32 md:pb-16 lg:pt-40 lg:pb-20">
        <motion.div variants={stagger} initial="hidden" animate="visible">

          {/* Announcement */}
          <motion.div variants={rise} className="flex justify-center mb-10">
            <Link to="/changelog" className="group inline-flex items-center gap-2.5 pl-1 pr-4 py-1 rounded-full transition-all backdrop-blur-sm"
              style={{
                border: `1px solid ${isDark ? 'rgba(255,255,255,0.06)' : 'rgba(0,0,0,0.06)'}`,
                background: isDark ? 'rgba(255,255,255,0.03)' : 'rgba(0,0,0,0.02)',
              }}>
              <span className="px-2.5 py-1 rounded-full bg-emerald-500/15 text-emerald-600 dark:text-emerald-400 text-[10px] font-bold uppercase tracking-wider leading-none">New</span>
              <span className="text-[13px] transition-colors" style={{ color: isDark ? 'rgba(255,255,255,0.5)' : 'rgba(0,0,0,0.4)' }}>
                v{SITE.version} — Open Source Release
              </span>
              <ArrowRight className="w-3 h-3" style={{ color: isDark ? 'rgba(255,255,255,0.2)' : 'rgba(0,0,0,0.2)' }} />
            </Link>
          </motion.div>

          {/* Headline */}
          <motion.h1 variants={rise} className="text-center max-w-4xl mx-auto">
            <span className="block text-[2.75rem] sm:text-[3.5rem] md:text-[4.25rem] lg:text-[5rem] font-extrabold tracking-[-0.025em] leading-[1.05]"
              style={{ color: headingColor }}>
              Tear a rift
            </span>
            <span className="block text-[2.75rem] sm:text-[3.5rem] md:text-[4.25rem] lg:text-[5rem] font-extrabold tracking-[-0.025em] leading-[1.05]"
              style={{ color: headingColor }}>
              through the wire.
            </span>
            <span className="block mt-1 text-[2.75rem] sm:text-[3.5rem] md:text-[4.25rem] lg:text-[5rem] font-extrabold tracking-[-0.025em] leading-[1.05] bg-clip-text [-webkit-text-fill-color:transparent]"
              style={{
                backgroundImage: isDark
                  ? 'linear-gradient(135deg, #60a5fa 0%, #a78bfa 35%, #f472b6 65%, #fb923c 100%)'
                  : 'linear-gradient(135deg, #2563eb 0%, #7c3aed 35%, #db2777 65%, #ea580c 100%)',
              }}>
              Expose localhost.
            </span>
          </motion.h1>

          {/* Subtitle */}
          <motion.p variants={rise} className="mt-6 md:mt-8 text-center text-[15px] sm:text-base md:text-lg max-w-xl mx-auto leading-relaxed"
            style={{ color: subColor }}>
            Connect any local service to the internet in one line —
            with built-in security, stream multiplexing, and traffic management.
          </motion.p>

          {/* CTA */}
          <motion.div variants={rise} className="mt-10 md:mt-12 flex flex-col sm:flex-row items-center justify-center gap-3">
            <Link to="/docs/getting-started" className="w-full sm:w-auto">
              <button className="w-full sm:w-auto px-8 py-3.5 text-[13px] font-bold uppercase tracking-[0.08em] rounded-xl shadow-lg transition-all cursor-pointer"
                style={{
                  backgroundColor: isDark ? '#e6edf3' : '#0f172a',
                  color: isDark ? '#050a15' : '#ffffff',
                }}>
                Get Started
              </button>
            </Link>
            <Link to="/docs/quick-start" className="w-full sm:w-auto">
              <button className="w-full sm:w-auto px-8 py-3.5 text-[13px] font-bold uppercase tracking-[0.08em] rounded-xl transition-all cursor-pointer"
                style={{
                  color: isDark ? 'rgba(255,255,255,0.8)' : 'rgba(15,23,42,0.7)',
                  border: `1px solid ${isDark ? 'rgba(255,255,255,0.1)' : 'rgba(15,23,42,0.15)'}`,
                }}>
                Deploy in 5 Minutes
              </button>
            </Link>
          </motion.div>

          {/* Install */}
          <motion.div variants={rise} className="mt-16 md:mt-20">
            <InstallBar isDark={isDark} />
          </motion.div>

          {/* Code */}
          <motion.div variants={scaleIn} className="mt-14 max-w-2xl mx-auto">
            <div className="relative group">
              <div className="absolute -inset-[1px] rounded-2xl" style={{
                background: isDark
                  ? 'linear-gradient(to bottom, rgba(255,255,255,0.08), rgba(255,255,255,0.02), transparent)'
                  : 'linear-gradient(to bottom, rgba(0,0,0,0.08), rgba(0,0,0,0.03), transparent)',
              }} />
              <div className="relative rounded-2xl overflow-hidden" style={{
                backgroundColor: isDark ? '#0d1117' : '#1e293b',
              }}>
                <CodeBlock code={heroCode} language="bash" filename="terminal" lineNumbers={true} showLanguageBadge={false} forceDark={true} />
              </div>
            </div>
          </motion.div>

          {/* Stats */}
          <motion.div variants={rise} className="mt-14 md:mt-16 flex flex-wrap items-center justify-center gap-x-6 gap-y-2 text-[13px]" style={{ color: statColor }}>
            {['Zero dependencies', 'Single binary', 'Auto TLS', '100% test coverage', 'MIT License'].map((s, i) => (
              <span key={s} className="flex items-center gap-6">
                {i > 0 && <span className="hidden sm:inline" style={{ color: isDark ? 'rgba(255,255,255,0.1)' : 'rgba(0,0,0,0.1)' }}>·</span>}
                {s}
              </span>
            ))}
          </motion.div>

        </motion.div>
      </div>

      {/* Bottom fade */}
      <div className="h-24 md:h-32" style={{
        background: `linear-gradient(to bottom, ${bg}, var(--color-bg))`,
      }} />
    </section>
  )
}
