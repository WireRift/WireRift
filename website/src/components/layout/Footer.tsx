import { Link } from 'react-router'
import { SITE } from '@/lib/constants'

export function Footer() {
  const currentYear = new Date().getFullYear()

  return (
    <footer className="border-t border-[var(--color-border)] bg-[var(--color-bg-secondary)]">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-12">
        <div className="grid grid-cols-2 md:grid-cols-4 gap-8">
          {/* Brand */}
          <div className="col-span-2 md:col-span-1">
            <span className="text-lg font-bold gradient-text">{SITE.name}</span>
            <p className="mt-2 text-sm text-[var(--color-text-muted)] leading-relaxed max-w-xs">
              {SITE.tagline}
            </p>
            <div className="mt-4 flex items-center gap-2">
              <span className="inline-flex items-center gap-1.5 px-2.5 py-1 text-xs font-medium rounded-full bg-[var(--color-bg-tertiary)] text-[var(--color-text-muted)] border border-[var(--color-border)]">
                <svg viewBox="0 0 24 24" className="w-3.5 h-3.5" fill="currentColor">
                  <path d="M1.811 10.231c-.047 0-.058-.023-.035-.059l.246-.315c.023-.035.081-.058.128-.058h4.172c.046 0 .058.035.035.07l-.199.303c-.023.036-.082.07-.117.07zM.047 11.306c-.047 0-.059-.023-.035-.058l.245-.316c.023-.035.082-.058.129-.058h5.328c.047 0 .07.035.058.07l-.093.28c-.012.047-.058.07-.105.07zm2.828 1.075c-.047 0-.059-.035-.035-.07l.163-.292c.023-.035.07-.07.117-.07h2.337c.047 0 .07.035.07.082l-.023.28c0 .047-.047.082-.082.082zm12.129-2.36c-1.588.397-2.67.69-4.258 1.088-.375.093-.397.105-.714-.257-.363-.41-.632-.679-1.14-.93-1.524-.757-3-.583-4.375.328-1.634 1.084-2.474 2.685-2.45 4.62.023 1.912 1.354 3.49 3.243 3.747 1.622.21 2.986-.351 4.094-1.52.222-.234.42-.492.655-.77H7.478c-.527 0-.656-.327-.48-.749.327-.774.935-2.07 1.294-2.72.082-.152.269-.327.527-.327h7.396c-.047.644-.047 1.287-.14 1.93-.246 1.7-.876 3.267-1.96 4.633-1.776 2.23-4.066 3.56-6.87 3.933-2.31.305-4.446-.14-6.303-1.52C.39 20.36-.33 18.484.12 16.224c.433-2.15 1.576-3.84 3.267-5.11C5.28 9.698 7.594 8.97 10.15 9.04c2.03.058 3.77.69 5.204 2.127.328.328.632.69.96 1.052l.036-.035z"/>
                </svg>
                Built with Go
              </span>
            </div>
          </div>

          {/* Docs */}
          <div>
            <h3 className="text-sm font-semibold text-[var(--color-text-heading)] mb-3">Documentation</h3>
            <ul className="space-y-2">
              <li><Link to="/docs/getting-started" className="text-sm text-[var(--color-text-muted)] hover:text-[var(--color-text-heading)] transition-colors">Getting Started</Link></li>
              <li><Link to="/docs/installation" className="text-sm text-[var(--color-text-muted)] hover:text-[var(--color-text-heading)] transition-colors">Installation</Link></li>
              <li><Link to="/docs/configuration" className="text-sm text-[var(--color-text-muted)] hover:text-[var(--color-text-heading)] transition-colors">Configuration</Link></li>
              <li><Link to="/docs/api-reference" className="text-sm text-[var(--color-text-muted)] hover:text-[var(--color-text-heading)] transition-colors">API Reference</Link></li>
            </ul>
          </div>

          {/* Features */}
          <div>
            <h3 className="text-sm font-semibold text-[var(--color-text-heading)] mb-3">Features</h3>
            <ul className="space-y-2">
              <li><Link to="/docs/http-tunnels" className="text-sm text-[var(--color-text-muted)] hover:text-[var(--color-text-heading)] transition-colors">HTTP Tunnels</Link></li>
              <li><Link to="/docs/tcp-tunnels" className="text-sm text-[var(--color-text-muted)] hover:text-[var(--color-text-heading)] transition-colors">TCP Tunnels</Link></li>
              <li><Link to="/docs/security" className="text-sm text-[var(--color-text-muted)] hover:text-[var(--color-text-heading)] transition-colors">Security</Link></li>
              <li><Link to="/docs/architecture" className="text-sm text-[var(--color-text-muted)] hover:text-[var(--color-text-heading)] transition-colors">Architecture</Link></li>
            </ul>
          </div>

          {/* Links */}
          <div>
            <h3 className="text-sm font-semibold text-[var(--color-text-heading)] mb-3">Community</h3>
            <ul className="space-y-2">
              <li><a href={SITE.repo} target="_blank" rel="noopener noreferrer" className="text-sm text-[var(--color-text-muted)] hover:text-[var(--color-text-heading)] transition-colors">GitHub</a></li>
              <li><a href={`${SITE.repo}/issues`} target="_blank" rel="noopener noreferrer" className="text-sm text-[var(--color-text-muted)] hover:text-[var(--color-text-heading)] transition-colors">Issues</a></li>
              <li><a href={`${SITE.repo}/releases`} target="_blank" rel="noopener noreferrer" className="text-sm text-[var(--color-text-muted)] hover:text-[var(--color-text-heading)] transition-colors">Releases</a></li>
              <li><Link to="/changelog" className="text-sm text-[var(--color-text-muted)] hover:text-[var(--color-text-heading)] transition-colors">Changelog</Link></li>
            </ul>
          </div>
        </div>

        {/* Bottom bar */}
        <div className="mt-10 pt-6 border-t border-[var(--color-border)] flex flex-col sm:flex-row items-center justify-between gap-4">
          <p className="text-xs text-[var(--color-text-muted)]">
            &copy; {currentYear} WireRift. Released under the {SITE.license} License.
          </p>
          <p className="text-xs text-[var(--color-text-muted)]">
            v{SITE.version}
          </p>
        </div>
      </div>
    </footer>
  )
}
