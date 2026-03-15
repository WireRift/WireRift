import { motion } from 'framer-motion'
import {
  ArrowRight,
  Globe,
  Laptop,
  Server,
  Shield,
  Layers,
  Activity,
  Network,
} from 'lucide-react'

const frameTypes = [
  { name: 'AUTH', codes: '0x01 / 0x02', desc: 'Authentication', color: '#3b82f6' },
  { name: 'TUNNEL', codes: '0x03 / 0x04 / 0x05', desc: 'Tunnel lifecycle', color: '#8b5cf6' },
  { name: 'STREAM', codes: '0x10 – 0x14', desc: 'Data transfer & flow', color: '#06b6d4' },
  { name: 'HEARTBEAT', codes: '0x20 / 0x21', desc: 'Keep-alive', color: '#10b981' },
  { name: 'CONTROL', codes: '0xFE / 0xFF', desc: 'Shutdown & errors', color: '#f59e0b' },
]

const headerBytes = [
  { label: 'Version', size: '1 byte', color: '#3b82f6' },
  { label: 'Type', size: '1 byte', color: '#8b5cf6' },
  { label: 'Stream ID', size: '3 bytes', color: '#06b6d4' },
  { label: 'Payload Len', size: '4 bytes', color: '#10b981' },
]

export function Architecture() {
  return (
    <section className="py-20 md:py-28 bg-[var(--color-bg-secondary)]">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        {/* Section header */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true, margin: '-100px' }}
          transition={{ duration: 0.5 }}
          className="text-center mb-16"
        >
          <h2 className="text-3xl md:text-4xl font-bold text-[var(--color-text-heading)]">
            Built on a solid foundation
          </h2>
          <p className="mt-4 text-lg text-[var(--color-text-muted)] max-w-2xl mx-auto">
            A custom binary protocol with stream multiplexing, flow control, and automatic reconnection.
          </p>
        </motion.div>

        {/* Data Flow Diagram */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true, margin: '-50px' }}
          transition={{ duration: 0.5 }}
          className="mb-16"
        >
          <div className="relative max-w-4xl mx-auto">
            {/* Flow boxes */}
            <div className="grid grid-cols-1 md:grid-cols-5 gap-3 md:gap-0 items-center">
              {/* Client */}
              <FlowBox
                icon={<Laptop className="w-6 h-6" />}
                title="Your Machine"
                items={['localhost:8080', 'localhost:3000']}
                gradient="from-blue-500/20 to-blue-600/20"
                borderColor="border-blue-500/30"
                iconColor="text-blue-400"
              />

              {/* Arrow */}
              <div className="hidden md:flex justify-center">
                <ArrowRight className="w-6 h-6 text-[var(--color-text-muted)]" />
              </div>

              {/* Server */}
              <FlowBox
                icon={<Server className="w-6 h-6" />}
                title="WireRift Server"
                items={['Mux Engine', 'Auth & Routing']}
                gradient="from-violet-500/20 to-purple-600/20"
                borderColor="border-violet-500/30"
                iconColor="text-violet-400"
                highlight
              />

              {/* Arrow */}
              <div className="hidden md:flex justify-center">
                <ArrowRight className="w-6 h-6 text-[var(--color-text-muted)]" />
              </div>

              {/* Internet */}
              <FlowBox
                icon={<Globe className="w-6 h-6" />}
                title="The Internet"
                items={['myapp.domain.com', 'tcp://domain:20001']}
                gradient="from-cyan-500/20 to-teal-600/20"
                borderColor="border-cyan-500/30"
                iconColor="text-cyan-400"
              />
            </div>

            {/* Connection line */}
            <div className="hidden md:block absolute top-1/2 left-[20%] right-[20%] h-px bg-gradient-to-r from-blue-500/30 via-violet-500/50 to-cyan-500/30 -z-10" />
          </div>
        </motion.div>

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-8 max-w-6xl mx-auto">
          {/* Wire Protocol Frame */}
          <motion.div
            initial={{ opacity: 0, x: -20 }}
            whileInView={{ opacity: 1, x: 0 }}
            viewport={{ once: true, margin: '-50px' }}
            transition={{ duration: 0.5 }}
            className="p-6 rounded-2xl bg-[var(--color-bg-elevated)] border border-[var(--color-border)]"
          >
            <div className="flex items-center gap-3 mb-6">
              <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-blue-500/20 to-violet-500/20 flex items-center justify-center">
                <Layers className="w-5 h-5 text-blue-400" />
              </div>
              <div>
                <h3 className="text-lg font-semibold text-[var(--color-text-heading)]">
                  Wire Protocol
                </h3>
                <p className="text-sm text-[var(--color-text-muted)]">9-byte header + payload</p>
              </div>
            </div>

            {/* Header visualization */}
            <div className="flex gap-1 mb-4">
              {headerBytes.map((byte) => (
                <div
                  key={byte.label}
                  className="flex-1 rounded-lg p-3 text-center"
                  style={{ backgroundColor: `${byte.color}15`, border: `1px solid ${byte.color}30` }}
                >
                  <div className="text-xs font-bold" style={{ color: byte.color }}>
                    {byte.label}
                  </div>
                  <div className="text-[10px] mt-1 text-[var(--color-text-muted)]">{byte.size}</div>
                </div>
              ))}
            </div>

            <div className="flex items-center gap-2 px-3 py-2 rounded-lg bg-[var(--color-bg-tertiary)] mb-4">
              <Shield className="w-4 h-4 text-[var(--color-text-muted)]" />
              <code className="text-xs font-mono text-[var(--color-text-muted)]">
                Magic: <span className="text-blue-400">0x57 0x52 0x46 0x01</span>{' '}
                <span className="text-[var(--color-text-muted)] opacity-60">("WRF\x01")</span>
              </code>
            </div>

            {/* Max payload */}
            <div className="flex items-center gap-2 px-3 py-2 rounded-lg bg-[var(--color-bg-tertiary)]">
              <Activity className="w-4 h-4 text-[var(--color-text-muted)]" />
              <span className="text-xs text-[var(--color-text-muted)]">
                Max payload: <span className="font-mono text-green-400">16 MB</span> ·
                Max streams: <span className="font-mono text-cyan-400">16M</span> ·
                Window: <span className="font-mono text-violet-400">256 KB</span>
              </span>
            </div>
          </motion.div>

          {/* Frame Types */}
          <motion.div
            initial={{ opacity: 0, x: 20 }}
            whileInView={{ opacity: 1, x: 0 }}
            viewport={{ once: true, margin: '-50px' }}
            transition={{ duration: 0.5 }}
            className="p-6 rounded-2xl bg-[var(--color-bg-elevated)] border border-[var(--color-border)]"
          >
            <div className="flex items-center gap-3 mb-6">
              <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-cyan-500/20 to-green-500/20 flex items-center justify-center">
                <Network className="w-5 h-5 text-cyan-400" />
              </div>
              <div>
                <h3 className="text-lg font-semibold text-[var(--color-text-heading)]">
                  Frame Types
                </h3>
                <p className="text-sm text-[var(--color-text-muted)]">14 frame types in 5 categories</p>
              </div>
            </div>

            <div className="space-y-2">
              {frameTypes.map((ft) => (
                <div
                  key={ft.name}
                  className="flex items-center gap-3 px-3 py-2.5 rounded-lg bg-[var(--color-bg-tertiary)] group hover:bg-[var(--color-bg-code)] transition-colors"
                >
                  <div
                    className="w-2 h-2 rounded-full shrink-0"
                    style={{ backgroundColor: ft.color }}
                  />
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2">
                      <span className="text-sm font-semibold text-[var(--color-text-heading)]">
                        {ft.name}
                      </span>
                      <code className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-[var(--color-bg-secondary)] text-[var(--color-text-muted)]">
                        {ft.codes}
                      </code>
                    </div>
                    <span className="text-xs text-[var(--color-text-muted)]">{ft.desc}</span>
                  </div>
                </div>
              ))}
            </div>
          </motion.div>
        </div>
      </div>
    </section>
  )
}

function FlowBox({
  icon,
  title,
  items,
  gradient,
  borderColor,
  iconColor,
  highlight,
}: {
  icon: React.ReactNode
  title: string
  items: string[]
  gradient: string
  borderColor: string
  iconColor: string
  highlight?: boolean
}) {
  return (
    <div
      className={`relative p-4 rounded-2xl bg-gradient-to-br ${gradient} border ${borderColor} ${
        highlight ? 'ring-1 ring-violet-500/20 shadow-lg shadow-violet-500/5' : ''
      }`}
    >
      <div className={`${iconColor} mb-2`}>{icon}</div>
      <h4 className="text-sm font-semibold text-[var(--color-text-heading)]">{title}</h4>
      <div className="mt-2 space-y-1">
        {items.map((item) => (
          <div key={item} className="text-xs font-mono text-[var(--color-text-muted)]">
            {item}
          </div>
        ))}
      </div>
    </div>
  )
}
