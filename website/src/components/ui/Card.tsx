import { type ReactNode } from 'react'
import { motion } from 'framer-motion'
import { cn } from '@/lib/utils'

interface CardProps {
  children: ReactNode
  className?: string
  hover?: boolean
}

export function Card({ children, className, hover = true }: CardProps) {
  return (
    <motion.div
      whileHover={hover ? { y: -4, scale: 1.01 } : undefined}
      transition={{ duration: 0.2 }}
      className={cn(
        'rounded-2xl border border-[var(--color-border)] bg-[var(--color-bg-elevated)] p-6',
        'transition-all duration-300',
        hover && 'hover:shadow-lg hover:border-primary-500/30 glow-border cursor-default',
        className
      )}
    >
      {children}
    </motion.div>
  )
}
