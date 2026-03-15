import { Link } from 'react-router'
import { motion } from 'framer-motion'
import { ArrowRight, Copy, Check } from 'lucide-react'
import { useThemeStore } from '@/hooks/useTheme'
import { SITE } from '@/lib/constants'
import { useState, useCallback } from 'react'

export function CTA() {
  const isDark = useThemeStore((s) => s.resolved) === 'dark'
  const installCmd = SITE.installCommand
  const [copied, setCopied] = useState(false)
  const copy = useCallback(async () => {
    try {
      await navigator.clipboard.writeText(installCmd)
    } catch {
      const textarea = document.createElement('textarea')
      textarea.value = installCmd
      textarea.style.position = 'fixed'
      textarea.style.opacity = '0'
      document.body.appendChild(textarea)
      textarea.select()
      document.execCommand('copy')
      document.body.removeChild(textarea)
    }
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }, [installCmd])

  return (
    <section className="py-20 md:py-28">
      <div className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8">
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true, margin: '-100px' }}
          transition={{ duration: 0.5 }}
          className="relative overflow-hidden rounded-3xl p-10 md:p-16 text-center"
          style={{
            background: isDark
              ? 'linear-gradient(135deg, #0f172a 0%, #1e1b4b 50%, #0f172a 100%)'
              : '#ffffff',
            border: isDark ? 'none' : '1px solid #e2e8f0',
            boxShadow: isDark ? 'none' : '0 4px 24px rgba(0,0,0,0.06)',
          }}
        >
          {/* Glow - dark only */}
          {isDark && (
            <div className="absolute top-0 left-1/2 -translate-x-1/2 w-[600px] h-[300px] rounded-full opacity-20"
              style={{ background: 'radial-gradient(ellipse, rgba(99,102,241,0.4) 0%, transparent 70%)' }} />
          )}

          <div className="relative">
            <h2 className="text-3xl md:text-4xl font-bold mb-4"
              style={{ color: isDark ? '#ffffff' : '#0f172a' }}>
              Ready to tear a rift?
            </h2>
            <p className="text-base md:text-lg max-w-lg mx-auto mb-10"
              style={{ color: isDark ? 'rgba(255,255,255,0.5)' : '#64748b' }}>
              Get WireRift running in under a minute. Self-hosted, zero dependencies, production ready.
            </p>

            {/* Install command */}
            <div className="inline-flex items-center gap-3 px-5 py-3 rounded-xl font-mono text-sm mb-10"
              style={{
                background: isDark ? 'rgba(255,255,255,0.06)' : '#f1f5f9',
                border: isDark ? '1px solid rgba(255,255,255,0.08)' : '1px solid #e2e8f0',
              }}>
              <span style={{ color: isDark ? 'rgba(255,255,255,0.3)' : '#94a3b8' }} className="select-none">$</span>
              <span style={{ color: isDark ? 'rgba(255,255,255,0.7)' : '#334155' }} className="truncate max-w-[280px] sm:max-w-none">{installCmd}</span>
              <button onClick={copy} className="shrink-0 p-1 rounded transition-colors cursor-pointer"
                style={{ color: isDark ? 'rgba(255,255,255,0.3)' : '#94a3b8' }} aria-label="Copy">
                {copied ? <Check className="w-3.5 h-3.5 text-emerald-500" /> : <Copy className="w-3.5 h-3.5" />}
              </button>
            </div>

            <div className="flex flex-col sm:flex-row items-center justify-center gap-3">
              <Link to="/docs/getting-started">
                <button className="px-7 py-3 text-[13px] font-bold uppercase tracking-[0.08em] rounded-xl shadow-lg transition-all cursor-pointer inline-flex items-center gap-2"
                  style={{
                    background: isDark ? '#ffffff' : '#0f172a',
                    color: isDark ? '#0f172a' : '#ffffff',
                  }}>
                  Get Started
                  <ArrowRight className="w-4 h-4" />
                </button>
              </Link>
              <Link to="/download">
                <button className="px-7 py-3 text-[13px] font-bold uppercase tracking-[0.08em] rounded-xl transition-all cursor-pointer"
                  style={{
                    color: isDark ? 'rgba(255,255,255,0.6)' : '#64748b',
                    border: isDark ? '1px solid rgba(255,255,255,0.1)' : '1px solid #e2e8f0',
                  }}>
                  Download Binaries
                </button>
              </Link>
            </div>
          </div>
        </motion.div>
      </div>
    </section>
  )
}
