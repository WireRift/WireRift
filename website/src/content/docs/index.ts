import type { ReactNode } from 'react'
import { gettingStarted } from './getting-started'
import { installation } from './installation'
import { quickStart } from './quick-start'
import { configuration } from './configuration'
import { architecture } from './architecture'
import { httpTunnels } from './http-tunnels'
import { tcpTunnels } from './tcp-tunnels'
import { apiReference } from './api-reference'
import { security } from './security'
import { troubleshooting } from './troubleshooting'

export interface DocEntry {
  title: string
  description: string
  content: ReactNode
}

export const docs: Record<string, DocEntry> = {
  'getting-started': gettingStarted,
  'installation': installation,
  'quick-start': quickStart,
  'configuration': configuration,
  'architecture': architecture,
  'http-tunnels': httpTunnels,
  'tcp-tunnels': tcpTunnels,
  'api-reference': apiReference,
  'security': security,
  'troubleshooting': troubleshooting,
}
