import { Link } from 'react-router'
import { motion } from 'framer-motion'
import { ArrowRight, Terminal } from 'lucide-react'
import { Button } from '@/components/ui/Button'
import { CopyButton } from '@/components/ui/CopyButton'
import { SITE } from '@/lib/constants'

export function CTA() {
  const installCmd = SITE.installCommand

  return (
    <section className="py-20 md:py-28">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true, margin: '-100px' }}
          transition={{ duration: 0.5 }}
          className="relative overflow-hidden rounded-3xl bg-gradient-to-br from-primary-600 via-accent-600 to-primary-700 p-10 md:p-16 text-center"
        >
          {/* Background decoration */}
          <div className="absolute inset-0 opacity-10">
            <div className="absolute top-0 left-0 w-72 h-72 rounded-full bg-white blur-3xl -translate-x-1/2 -translate-y-1/2" />
            <div className="absolute bottom-0 right-0 w-96 h-96 rounded-full bg-white blur-3xl translate-x-1/3 translate-y-1/3" />
          </div>

          <div className="relative">
            <h2 className="text-3xl md:text-4xl font-bold text-white mb-4">
              Ready to tear a rift?
            </h2>
            <p className="text-lg text-white/80 max-w-xl mx-auto mb-8">
              Get WireRift running in under a minute. Self-hosted, zero dependencies, production ready.
            </p>

            {/* Install command */}
            <div className="inline-flex items-center gap-2 px-4 py-3 rounded-xl bg-black/20 backdrop-blur-sm border border-white/10 font-mono text-sm text-white/90 mb-8">
              <Terminal className="w-4 h-4 shrink-0 text-white/60" />
              <span className="truncate max-w-[300px] sm:max-w-none">{installCmd}</span>
              <CopyButton text={installCmd} className="text-white/60 hover:text-white hover:bg-white/10" />
            </div>

            <div className="flex flex-col sm:flex-row items-center justify-center gap-3">
              <Link to="/docs/getting-started">
                <Button
                  size="lg"
                  className="bg-white text-primary-700 hover:bg-white/90 hover:text-primary-800 from-white to-white"
                >
                  Get Started
                  <ArrowRight className="w-4 h-4" />
                </Button>
              </Link>
              <Link to="/docs/quick-start">
                <Button
                  variant="ghost"
                  size="lg"
                  className="text-white/90 hover:text-white hover:bg-white/10"
                >
                  View Examples
                </Button>
              </Link>
            </div>
          </div>
        </motion.div>
      </div>
    </section>
  )
}
