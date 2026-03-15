import { Link } from 'react-router'
import { motion } from 'framer-motion'
import { ArrowRight, Copy, Check } from 'lucide-react'
import { SITE } from '@/lib/constants'
import { useState, useCallback } from 'react'

export function CTA() {
  const installCmd = SITE.installCommand
  const [copied, setCopied] = useState(false)
  const copy = useCallback(() => {
    navigator.clipboard.writeText(installCmd)
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
            background: 'linear-gradient(135deg, #0f172a 0%, #1e1b4b 50%, #0f172a 100%)',
          }}
        >
          {/* Subtle glow */}
          <div className="absolute top-0 left-1/2 -translate-x-1/2 w-[600px] h-[300px] rounded-full opacity-20"
            style={{ background: 'radial-gradient(ellipse, rgba(99,102,241,0.4) 0%, transparent 70%)' }} />

          <div className="relative">
            <h2 className="text-3xl md:text-4xl font-bold text-white mb-4">
              Ready to tear a rift?
            </h2>
            <p className="text-base md:text-lg text-white/50 max-w-lg mx-auto mb-10">
              Get WireRift running in under a minute. Self-hosted, zero dependencies, production ready.
            </p>

            {/* Install command */}
            <div className="inline-flex items-center gap-3 px-5 py-3 rounded-xl bg-white/[0.06] border border-white/[0.08] font-mono text-sm mb-10">
              <span className="text-white/30 select-none">$</span>
              <span className="text-white/70 truncate max-w-[280px] sm:max-w-none">{installCmd}</span>
              <button onClick={copy} className="shrink-0 p-1 rounded text-white/30 hover:text-white transition-colors cursor-pointer" aria-label="Copy">
                {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
              </button>
            </div>

            <div className="flex flex-col sm:flex-row items-center justify-center gap-3">
              <Link to="/docs/getting-started">
                <button className="px-7 py-3 text-[13px] font-bold uppercase tracking-[0.08em] rounded-xl bg-white text-[#0f172a] hover:bg-white/90 shadow-lg shadow-white/5 transition-all cursor-pointer inline-flex items-center gap-2">
                  Get Started
                  <ArrowRight className="w-4 h-4" />
                </button>
              </Link>
              <Link to="/download">
                <button className="px-7 py-3 text-[13px] font-bold uppercase tracking-[0.08em] rounded-xl text-white/60 border border-white/[0.1] hover:bg-white/[0.05] hover:text-white/80 transition-all cursor-pointer">
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
