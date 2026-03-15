import { Sun, Moon } from 'lucide-react'
import { motion, AnimatePresence } from 'framer-motion'
import { useTheme } from '@/hooks/useTheme'
import { cn } from '@/lib/utils'

interface ThemeToggleProps {
  className?: string
}

export function ThemeToggle({ className }: ThemeToggleProps) {
  const { theme, toggleTheme } = useTheme()
  const isDark = theme === 'dark'

  return (
    <button
      onClick={toggleTheme}
      className={cn(
        'relative inline-flex items-center justify-center w-9 h-9 rounded-lg',
        'text-[var(--color-text-muted)] hover:text-[var(--color-text-heading)]',
        'hover:bg-[var(--color-bg-tertiary)] transition-colors duration-200',
        'focus-visible:outline-2 focus-visible:outline-primary-500 cursor-pointer',
        className
      )}
      aria-label={`Switch to ${isDark ? 'light' : 'dark'} mode`}
    >
      <AnimatePresence mode="wait">
        <motion.div
          key={theme}
          initial={{ rotate: -90, scale: 0 }}
          animate={{ rotate: 0, scale: 1 }}
          exit={{ rotate: 90, scale: 0 }}
          transition={{ duration: 0.3, ease: 'easeInOut' }}
        >
          {isDark ? <Sun className="w-[18px] h-[18px]" /> : <Moon className="w-[18px] h-[18px]" />}
        </motion.div>
      </AnimatePresence>
    </button>
  )
}
