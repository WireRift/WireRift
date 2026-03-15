import { useState } from 'react'
import { Link, useLocation } from 'react-router'
import { Github, Menu, X } from 'lucide-react'
import { motion, AnimatePresence } from 'framer-motion'
import { ThemeToggle } from '@/components/ui/ThemeToggle'
import { NAV_ITEMS, SITE } from '@/lib/constants'
import { cn } from '@/lib/utils'

export function Header() {
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false)
  const location = useLocation()

  return (
    <header
      className={cn(
        'sticky top-0 z-50 w-full',
        'bg-[var(--color-header-bg)] backdrop-blur-xl',
        'border-b border-[var(--color-border)]'
      )}
    >
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex items-center justify-between h-16">
          {/* Logo */}
          <Link
            to="/"
            className="flex items-center gap-2 shrink-0"
            aria-label="WireRift Home"
          >
            <span className="text-xl font-bold gradient-text">
              {SITE.name}
            </span>
          </Link>

          {/* Desktop Nav */}
          <nav className="hidden md:flex items-center gap-1" aria-label="Main navigation">
            {NAV_ITEMS.map((item) => {
              const isActive = location.pathname.startsWith(item.href)
              return (
                <Link
                  key={item.href}
                  to={item.href}
                  className={cn(
                    'px-3 py-2 rounded-lg text-sm font-medium transition-colors duration-200',
                    isActive
                      ? 'text-[var(--color-text-heading)] bg-[var(--color-bg-tertiary)]'
                      : 'text-[var(--color-text-muted)] hover:text-[var(--color-text-heading)] hover:bg-[var(--color-bg-tertiary)]'
                  )}
                >
                  {item.label}
                </Link>
              )
            })}
          </nav>

          {/* Right side */}
          <div className="flex items-center gap-1">
            <ThemeToggle />
            <a
              href={SITE.repo}
              target="_blank"
              rel="noopener noreferrer"
              className={cn(
                'inline-flex items-center justify-center w-9 h-9 rounded-lg',
                'text-[var(--color-text-muted)] hover:text-[var(--color-text-heading)]',
                'hover:bg-[var(--color-bg-tertiary)] transition-colors duration-200'
              )}
              aria-label="GitHub repository"
            >
              <Github className="w-[18px] h-[18px]" />
            </a>

            {/* Mobile menu button */}
            <button
              className={cn(
                'md:hidden inline-flex items-center justify-center w-9 h-9 rounded-lg',
                'text-[var(--color-text-muted)] hover:text-[var(--color-text-heading)]',
                'hover:bg-[var(--color-bg-tertiary)] transition-colors duration-200 cursor-pointer'
              )}
              onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
              aria-label={mobileMenuOpen ? 'Close menu' : 'Open menu'}
              aria-expanded={mobileMenuOpen}
            >
              {mobileMenuOpen ? <X className="w-5 h-5" /> : <Menu className="w-5 h-5" />}
            </button>
          </div>
        </div>
      </div>

      {/* Mobile menu */}
      <AnimatePresence>
        {mobileMenuOpen && (
          <motion.nav
            initial={{ opacity: 0, height: 0 }}
            animate={{ opacity: 1, height: 'auto' }}
            exit={{ opacity: 0, height: 0 }}
            transition={{ duration: 0.2 }}
            className="md:hidden border-t border-[var(--color-border)] bg-[var(--color-bg)] overflow-hidden"
            aria-label="Mobile navigation"
          >
            <div className="px-4 py-3 space-y-1">
              {NAV_ITEMS.map((item) => {
                const isActive = location.pathname.startsWith(item.href)
                return (
                  <Link
                    key={item.href}
                    to={item.href}
                    onClick={() => setMobileMenuOpen(false)}
                    className={cn(
                      'block px-3 py-2 rounded-lg text-sm font-medium transition-colors duration-200',
                      isActive
                        ? 'text-[var(--color-text-heading)] bg-[var(--color-bg-tertiary)]'
                        : 'text-[var(--color-text-muted)] hover:text-[var(--color-text-heading)]'
                    )}
                  >
                    {item.label}
                  </Link>
                )
              })}
            </div>
          </motion.nav>
        )}
      </AnimatePresence>
    </header>
  )
}
