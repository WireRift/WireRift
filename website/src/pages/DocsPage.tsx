import { useParams, Navigate, Link } from 'react-router'
import { motion } from 'framer-motion'
import { ChevronLeft, ChevronRight } from 'lucide-react'
import { docs, type DocEntry } from '@/content/docs'
import { DOC_SIDEBAR_SECTIONS } from '@/lib/constants'

function getAdjacentDocs(currentSlug: string): { prev: { slug: string; label: string } | null; next: { slug: string; label: string } | null } {
  const allItems: { slug: string; label: string }[] = []
  for (const section of DOC_SIDEBAR_SECTIONS) {
    for (const item of section.items) {
      allItems.push(item)
    }
  }

  const currentIndex = allItems.findIndex((item) => item.slug === currentSlug)
  if (currentIndex === -1) return { prev: null, next: null }

  return {
    prev: currentIndex > 0 ? allItems[currentIndex - 1] : null,
    next: currentIndex < allItems.length - 1 ? allItems[currentIndex + 1] : null,
  }
}

export default function DocsPage() {
  const { slug = 'getting-started' } = useParams<{ slug: string }>()
  const doc: DocEntry | undefined = docs[slug]

  if (!doc) {
    return <Navigate to="/docs/getting-started" replace />
  }

  const { prev, next } = getAdjacentDocs(slug)

  return (
    <motion.article
      key={slug}
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className="max-w-3xl"
    >
      {/* Header */}
      <header className="mb-8">
        <h1 className="text-3xl md:text-4xl font-bold text-[var(--color-text-heading)]">
          {doc.title}
        </h1>
        <p className="mt-3 text-lg text-[var(--color-text-muted)] leading-relaxed">
          {doc.description}
        </p>
      </header>

      {/* Content */}
      <div className="doc-content">
        {doc.content}
      </div>

      {/* Navigation */}
      <nav className="mt-16 pt-8 border-t border-[var(--color-border)] flex items-center justify-between gap-4" aria-label="Documentation pagination">
        {prev ? (
          <Link
            to={`/docs/${prev.slug}`}
            className="flex items-center gap-2 text-sm text-[var(--color-text-muted)] hover:text-[var(--color-text-heading)] transition-colors group"
          >
            <ChevronLeft className="w-4 h-4 group-hover:-translate-x-0.5 transition-transform" />
            <div className="text-right">
              <div className="text-xs text-[var(--color-text-muted)]">Previous</div>
              <div className="font-medium">{prev.label}</div>
            </div>
          </Link>
        ) : (
          <div />
        )}
        {next ? (
          <Link
            to={`/docs/${next.slug}`}
            className="flex items-center gap-2 text-sm text-[var(--color-text-muted)] hover:text-[var(--color-text-heading)] transition-colors group text-right"
          >
            <div>
              <div className="text-xs text-[var(--color-text-muted)]">Next</div>
              <div className="font-medium">{next.label}</div>
            </div>
            <ChevronRight className="w-4 h-4 group-hover:translate-x-0.5 transition-transform" />
          </Link>
        ) : (
          <div />
        )}
      </nav>
    </motion.article>
  )
}
