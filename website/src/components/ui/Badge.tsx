import { type ReactNode } from 'react'
import { cn } from '@/lib/utils'

type BadgeVariant = 'default' | 'new' | 'deprecated' | 'beta' | 'version'

interface BadgeProps {
  variant?: BadgeVariant
  children: ReactNode
  className?: string
}

const variantStyles: Record<BadgeVariant, string> = {
  default:
    'bg-[var(--color-bg-tertiary)] text-[var(--color-text-muted)] border-[var(--color-border)]',
  new:
    'bg-emerald-500/10 text-emerald-600 border-emerald-500/30 dark:text-emerald-400',
  deprecated:
    'bg-amber-500/10 text-amber-600 border-amber-500/30 dark:text-amber-400',
  beta:
    'bg-blue-500/10 text-blue-600 border-blue-500/30 dark:text-blue-400',
  version:
    'bg-gradient-to-r from-primary-500/10 to-accent-500/10 text-primary-600 border-primary-500/20 dark:text-primary-400',
}

export function Badge({ variant = 'default', children, className }: BadgeProps) {
  return (
    <span
      className={cn(
        'inline-flex items-center gap-1 px-2.5 py-0.5 text-xs font-medium rounded-full border',
        variantStyles[variant],
        className
      )}
    >
      {children}
    </span>
  )
}
