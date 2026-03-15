import { Link, useParams } from 'react-router'
import { DOC_SIDEBAR_SECTIONS } from '@/lib/constants'
import { cn } from '@/lib/utils'

interface SidebarProps {
  className?: string
  onNavigate?: () => void
}

export function Sidebar({ className, onNavigate }: SidebarProps) {
  const { slug } = useParams<{ slug: string }>()

  return (
    <aside
      className={cn(
        'w-64 shrink-0 overflow-y-auto',
        className
      )}
      aria-label="Documentation sidebar"
    >
      <nav className="py-6 pr-4 space-y-6">
        {DOC_SIDEBAR_SECTIONS.map((section) => (
          <div key={section.title}>
            <h4 className="px-3 mb-1.5 text-xs font-semibold uppercase tracking-wider text-[var(--color-text-muted)]">
              {section.title}
            </h4>
            <ul className="space-y-0.5">
              {section.items.map((item) => {
                const isActive = slug === item.slug
                return (
                  <li key={item.slug}>
                    <Link
                      to={`/docs/${item.slug}`}
                      onClick={onNavigate}
                      className={cn(
                        'block px-3 py-1.5 rounded-lg text-sm transition-colors duration-150',
                        isActive
                          ? 'font-medium text-primary-600 bg-[var(--color-sidebar-active)] dark:text-primary-400'
                          : 'text-[var(--color-text-muted)] hover:text-[var(--color-text-heading)] hover:bg-[var(--color-bg-tertiary)]'
                      )}
                      aria-current={isActive ? 'page' : undefined}
                    >
                      {item.label}
                    </Link>
                  </li>
                )
              })}
            </ul>
          </div>
        ))}
      </nav>
    </aside>
  )
}
