import { motion } from 'framer-motion'
import * as LucideIcons from 'lucide-react'
import { Card } from '@/components/ui/Card'
import { FEATURES } from '@/lib/constants'

type LucideIconName = keyof typeof LucideIcons

const containerVariants = {
  hidden: { opacity: 0 },
  visible: {
    opacity: 1,
    transition: { staggerChildren: 0.06 },
  },
} as const

const itemVariants = {
  hidden: { opacity: 0, y: 20 },
  visible: { opacity: 1, y: 0, transition: { duration: 0.4, ease: 'easeOut' as const } },
}

export function Features() {
  return (
    <section className="py-20 md:py-28" style={{ backgroundColor: 'var(--color-bg-secondary)' }}>
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        {/* Section header */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true, margin: '-100px' }}
          transition={{ duration: 0.5 }}
          className="text-center mb-14"
        >
          <h2 className="text-3xl md:text-4xl font-bold text-[var(--color-text-heading)]">
            Everything you need
          </h2>
          <p className="mt-4 text-lg text-[var(--color-text-muted)] max-w-2xl mx-auto">
            WireRift ships with all the features you need for production tunnel infrastructure,
            built with zero external dependencies.
          </p>
        </motion.div>

        {/* Feature grid */}
        <motion.div
          variants={containerVariants}
          initial="hidden"
          whileInView="visible"
          viewport={{ once: true, margin: '-50px' }}
          className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-5"
        >
          {FEATURES.map((feature) => {
            const IconComponent = LucideIcons[feature.icon as LucideIconName] as LucideIcons.LucideIcon | undefined
            return (
              <motion.div key={feature.title} variants={itemVariants}>
                <Card className="h-full">
                  <div className="flex items-start gap-4">
                    <div className="shrink-0 w-10 h-10 rounded-xl bg-gradient-to-br from-primary-500/10 to-accent-500/10 flex items-center justify-center">
                      {IconComponent && <IconComponent className="w-5 h-5 text-primary-500" />}
                    </div>
                    <div>
                      <h3 className="font-semibold text-[var(--color-text-heading)] mb-1">
                        {feature.title}
                      </h3>
                      <p className="text-sm text-[var(--color-text-muted)] leading-relaxed">
                        {feature.description}
                      </p>
                    </div>
                  </div>
                </Card>
              </motion.div>
            )
          })}
        </motion.div>
      </div>
    </section>
  )
}
