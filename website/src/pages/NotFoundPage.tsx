import { Link } from 'react-router'
import { motion } from 'framer-motion'
import { ArrowLeft, Unplug } from 'lucide-react'
import { Button } from '@/components/ui/Button'

export default function NotFoundPage() {
  return (
    <div className="flex items-center justify-center min-h-[60vh] px-4">
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.5 }}
        className="text-center"
      >
        <div className="inline-flex items-center justify-center w-20 h-20 rounded-2xl bg-[var(--color-bg-tertiary)] mb-6">
          <Unplug className="w-10 h-10 text-[var(--color-text-muted)]" />
        </div>
        <h1 className="text-6xl font-bold gradient-text mb-4">404</h1>
        <p className="text-xl text-[var(--color-text-heading)] mb-2">
          Tunnel not found
        </p>
        <p className="text-[var(--color-text-muted)] mb-8 max-w-md mx-auto">
          The page you are looking for does not exist or the tunnel has been closed.
        </p>
        <Link to="/">
          <Button variant="secondary" size="lg">
            <ArrowLeft className="w-4 h-4" />
            Back to Home
          </Button>
        </Link>
      </motion.div>
    </div>
  )
}
