import { useState } from 'react'
import { Outlet } from 'react-router'
import { Menu, X } from 'lucide-react'
import { AnimatePresence, motion } from 'framer-motion'
import { Sidebar } from './Sidebar'
import { cn } from '@/lib/utils'

export function DocsLayout() {
  const [sidebarOpen, setSidebarOpen] = useState(false)

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
      <div className="flex min-h-[calc(100dvh-4rem)]">
        {/* Desktop sidebar */}
        <Sidebar className="hidden lg:block border-r border-[var(--color-border)] sticky top-16 h-[calc(100dvh-4rem)]" />

        {/* Mobile sidebar toggle */}
        <button
          className={cn(
            'lg:hidden fixed bottom-6 right-6 z-40 w-12 h-12 rounded-full',
            'bg-gradient-to-r from-primary-500 to-accent-500 text-white',
            'shadow-lg flex items-center justify-center cursor-pointer',
            'hover:shadow-xl transition-shadow duration-200'
          )}
          onClick={() => setSidebarOpen(!sidebarOpen)}
          aria-label={sidebarOpen ? 'Close sidebar' : 'Open sidebar'}
        >
          {sidebarOpen ? <X className="w-5 h-5" /> : <Menu className="w-5 h-5" />}
        </button>

        {/* Mobile sidebar overlay */}
        <AnimatePresence>
          {sidebarOpen && (
            <>
              <motion.div
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                exit={{ opacity: 0 }}
                className="lg:hidden fixed inset-0 z-30 bg-black/50"
                onClick={() => setSidebarOpen(false)}
              />
              <motion.div
                initial={{ x: -280 }}
                animate={{ x: 0 }}
                exit={{ x: -280 }}
                transition={{ type: 'spring', damping: 25, stiffness: 300 }}
                className="lg:hidden fixed left-0 top-16 bottom-0 z-30 w-72 bg-[var(--color-bg)] border-r border-[var(--color-border)] overflow-y-auto"
              >
                <Sidebar onNavigate={() => setSidebarOpen(false)} />
              </motion.div>
            </>
          )}
        </AnimatePresence>

        {/* Content */}
        <div className="flex-1 min-w-0 lg:pl-8 py-8">
          <Outlet />
        </div>
      </div>
    </div>
  )
}
