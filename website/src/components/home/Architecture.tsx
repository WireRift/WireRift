import { motion } from 'framer-motion'
import { CodeBlock } from '@/components/ui/CodeBlock'

const protocolDiagram = `┌─────────────────────────────────────────────────┐
│                  WireRift Architecture          │
└─────────────────────────────────────────────────┘

  Client Machine              Your Server (VPS)              Internet
 ┌──────────┐              ┌────────────────────┐         ┌──────────┐
 │          │   Control    │                    │  HTTP   │          │
 │ wirerift ├─────────────►│  wirerift-server   │◄────────┤  Users   │
 │  client  │   :4443      │                    │  :80    │          │
 │          │              │  ┌──────────────┐  │  :443   └──────────┘
 │ :8080 ◄──┼──── Mux ────┼──┤  Mux Engine  │  │
 │ :3000    │  (streams)   │  └──────┬───────┘  │
 │ :25565   │              │         │          │
 └──────────┘              │  ┌──────┴───────┐  │
                           │  │   Routing    │  │
                           │  │  HTTP→sub    │  │
                           │  │  TCP→port    │  │
                           │  └──────────────┘  │
                           │                    │
                           │  Dashboard :4040   │
                           └────────────────────┘`

const frameFormat = `Wire Protocol Frame (9-byte header):
┌─────────┬──────┬─────────────┬──────────────┐
│ Version │ Type │  Stream ID  │ Payload Len  │
│ 1 byte  │ 1 B  │   3 bytes   │   4 bytes    │
└─────────┴──────┴─────────────┴──────────────┘

Magic Bytes: 0x57 0x52 0x46 0x01 ("WRF\\x01")

Frame Types:
  AUTH_REQ / AUTH_RES      - Authentication
  TUNNEL_REQ / TUNNEL_RES  - Tunnel lifecycle
  TUNNEL_CLOSE             - Tunnel teardown
  STREAM_OPEN / STREAM_DATA / STREAM_CLOSE - Data transfer
  STREAM_RST / STREAM_WINDOW - Flow control
  HEARTBEAT / HEARTBEAT_ACK - Keep-alive
  GO_AWAY / ERROR          - Connection mgmt`

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
          className="text-center mb-14"
        >
          <h2 className="text-3xl md:text-4xl font-bold text-[var(--color-text-heading)]">
            Built on a solid foundation
          </h2>
          <p className="mt-4 text-lg text-[var(--color-text-muted)] max-w-2xl mx-auto">
            A custom binary protocol with stream multiplexing, flow control, and automatic reconnection.
          </p>
        </motion.div>

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-8 max-w-6xl mx-auto">
          {/* Architecture diagram */}
          <motion.div
            initial={{ opacity: 0, x: -20 }}
            whileInView={{ opacity: 1, x: 0 }}
            viewport={{ once: true, margin: '-50px' }}
            transition={{ duration: 0.5 }}
          >
            <h3 className="text-lg font-semibold text-[var(--color-text-heading)] mb-4">
              System Overview
            </h3>
            <div className="overflow-x-auto">
              <CodeBlock
                code={protocolDiagram}
                language="text"
                filename="architecture"
              />
            </div>
          </motion.div>

          {/* Protocol format */}
          <motion.div
            initial={{ opacity: 0, x: 20 }}
            whileInView={{ opacity: 1, x: 0 }}
            viewport={{ once: true, margin: '-50px' }}
            transition={{ duration: 0.5 }}
          >
            <h3 className="text-lg font-semibold text-[var(--color-text-heading)] mb-4">
              Wire Protocol
            </h3>
            <div className="overflow-x-auto">
              <CodeBlock
                code={frameFormat}
                language="text"
                filename="protocol.spec"
              />
            </div>
          </motion.div>
        </div>
      </div>
    </section>
  )
}
