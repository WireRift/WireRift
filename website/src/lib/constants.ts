export const SITE = {
  name: 'WireRift',
  tagline: 'Tear a rift through the wire. Expose localhost to the world.',
  description: 'Self-hosted tunnel server written in Go with zero dependencies. Expose your local services to the internet securely.',
  version: '1.0.0',
  domain: 'wirerift.com',
  url: 'https://wirerift.com',
  repo: 'https://github.com/wirerift/wirerift',
  license: 'MIT',
  language: 'Go',
  installCommand: 'go install github.com/wirerift/wirerift/cmd/wirerift@latest',
  installServerCommand: 'go install github.com/wirerift/wirerift/cmd/wirerift-server@latest',
} as const

export interface NavItem {
  label: string
  href: string
  external?: boolean
}

export const NAV_ITEMS: NavItem[] = [
  { label: 'Docs', href: '/docs/getting-started' },
  { label: 'Examples', href: '/docs/quick-start' },
  { label: 'Changelog', href: '/changelog' },
]

export interface SocialLink {
  label: string
  href: string
  icon: string
}

export const SOCIAL_LINKS: SocialLink[] = [
  { label: 'GitHub', href: 'https://github.com/wirerift/wirerift', icon: 'github' },
]

export const FEATURES = [
  {
    icon: 'Package',
    title: 'Zero Dependencies',
    description: 'Built entirely with the Go standard library. No third-party packages, no supply chain risk.',
  },
  {
    icon: 'Binary',
    title: 'Single Binary',
    description: 'One binary for the client, one for the server. No runtime dependencies to install.',
  },
  {
    icon: 'Server',
    title: 'Self-Hosted',
    description: 'Run your own tunnel server on your infrastructure. Full control, no vendor lock-in.',
  },
  {
    icon: 'Globe',
    title: 'HTTP Tunnels',
    description: 'Expose local HTTP services with automatic subdomain routing and WebSocket support.',
  },
  {
    icon: 'Network',
    title: 'TCP Tunnels',
    description: 'Forward raw TCP connections for databases, game servers, SSH, and any TCP protocol.',
  },
  {
    icon: 'ShieldCheck',
    title: 'Auto TLS',
    description: 'Automatic self-signed certificate generation. Secure connections out of the box.',
  },
  {
    icon: 'Plug',
    title: 'WebSocket Support',
    description: 'Full WebSocket passthrough with automatic protocol upgrade handling.',
  },
  {
    icon: 'Globe2',
    title: 'Custom Domains',
    description: 'Bring your own domains with DNS verification and automatic routing.',
  },
  {
    icon: 'LayoutDashboard',
    title: 'Built-in Dashboard',
    description: 'Web UI on port 4040 for monitoring tunnels, sessions, and server statistics.',
  },
  {
    icon: 'Layers',
    title: 'Stream Multiplexing',
    description: 'Custom binary protocol multiplexes streams over a single TCP connection.',
  },
  {
    icon: 'Gauge',
    title: 'Flow Control',
    description: 'Per-stream backpressure with window-based flow control prevents memory exhaustion.',
  },
  {
    icon: 'Shield',
    title: 'Rate Limiting',
    description: 'Token bucket and sliding window rate limiting per-IP and per-session.',
  },
  {
    icon: 'RefreshCw',
    title: 'Auto Reconnect',
    description: 'Automatic reconnection with exponential backoff and tunnel re-creation.',
  },
  {
    icon: 'CheckCircle',
    title: '100% Test Coverage',
    description: 'Every package tested comprehensively. Production-ready from day one.',
  },
] as const

export const DOC_SIDEBAR_SECTIONS = [
  {
    title: 'Getting Started',
    items: [
      { slug: 'getting-started', label: 'Introduction' },
      { slug: 'installation', label: 'Installation' },
      { slug: 'quick-start', label: 'Quick Start' },
    ],
  },
  {
    title: 'Core Concepts',
    items: [
      { slug: 'configuration', label: 'Configuration' },
      { slug: 'http-tunnels', label: 'HTTP Tunnels' },
      { slug: 'tcp-tunnels', label: 'TCP Tunnels' },
    ],
  },
  {
    title: 'API Reference',
    items: [
      { slug: 'api-reference', label: 'Dashboard API' },
    ],
  },
  {
    title: 'Advanced',
    items: [
      { slug: 'architecture', label: 'Architecture' },
      { slug: 'security', label: 'Security' },
    ],
  },
  {
    title: 'Resources',
    items: [
      { slug: 'troubleshooting', label: 'Troubleshooting' },
    ],
  },
] as const
