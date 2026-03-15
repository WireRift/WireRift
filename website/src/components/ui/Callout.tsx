import { type ReactNode } from 'react'
import { Info, AlertTriangle, XCircle, CheckCircle } from 'lucide-react'
import { cn } from '@/lib/utils'

type CalloutVariant = 'info' | 'warning' | 'error' | 'success'

interface CalloutProps {
  variant?: CalloutVariant
  title?: string
  children: ReactNode
  className?: string
}

const variantConfig: Record<CalloutVariant, { icon: typeof Info; styles: string }> = {
  info: {
    icon: Info,
    styles: 'bg-[var(--color-callout-info-bg)] border-[var(--color-callout-info-border)] text-[var(--color-callout-info-text)]',
  },
  warning: {
    icon: AlertTriangle,
    styles: 'bg-[var(--color-callout-warning-bg)] border-[var(--color-callout-warning-border)] text-[var(--color-callout-warning-text)]',
  },
  error: {
    icon: XCircle,
    styles: 'bg-[var(--color-callout-error-bg)] border-[var(--color-callout-error-border)] text-[var(--color-callout-error-text)]',
  },
  success: {
    icon: CheckCircle,
    styles: 'bg-[var(--color-callout-success-bg)] border-[var(--color-callout-success-border)] text-[var(--color-callout-success-text)]',
  },
}

export function Callout({ variant = 'info', title, children, className }: CalloutProps) {
  const config = variantConfig[variant]
  const Icon = config.icon

  return (
    <div
      className={cn(
        'flex gap-3 p-4 rounded-xl border',
        config.styles,
        className
      )}
      role="note"
    >
      <Icon className="w-5 h-5 mt-0.5 shrink-0" />
      <div className="flex-1 min-w-0">
        {title && <p className="font-semibold mb-1">{title}</p>}
        <div className="text-sm leading-relaxed">{children}</div>
      </div>
    </div>
  )
}
