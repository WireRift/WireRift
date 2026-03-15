export const SITE = {
  name: 'WireRift',
  tagline: 'Tear a rift through the wire. Expose localhost to the world.',
  description: 'Self-hosted tunnel server written in Go with zero dependencies. Expose your local services to the internet securely.',
  version: '1.3.0',
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
  { label: 'Download', href: '/download' },
  { label: 'Changelog', href: '/changelog' },
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
    title: 'Traffic Inspector',
    description: 'Real-time request/response capture in the dashboard. Replay any request with one click.',
  },
  {
    icon: 'Lock',
    title: 'Basic Auth',
    description: 'HTTP Basic Authentication per tunnel with constant-time credential comparison.',
  },
  {
    icon: 'ShieldAlert',
    title: 'IP Whitelist & PIN',
    description: 'Restrict access by IP/CIDR range or require a PIN code. Combine for layered security.',
  },
  {
    icon: 'FileText',
    title: 'Custom Headers',
    description: 'Inject response headers like X-Frame-Options, CORS, or cache controls through tunnels.',
  },
  {
    icon: 'FolderOpen',
    title: 'File Server',
    description: 'Serve a static directory through a tunnel with wirerift serve. No local web server needed.',
  },
  {
    icon: 'GitBranch',
    title: 'Webhook Relay',
    description: 'Fan-out incoming webhooks to multiple local endpoints simultaneously.',
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
    icon: 'RefreshCw',
    title: 'Auto Reconnect',
    description: 'Automatic reconnection with exponential backoff and tunnel re-creation.',
  },
  {
    icon: 'CheckCircle',
    title: '99.7% Test Coverage',
    description: 'Comprehensive test suite with fuzz, security, stress, and soak tests.',
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
