// Shared marketing content for Landing + Pricing pages.

export const FEATURES = [
  {
    tag: 'MODULE 01',
    title: 'IP Intelligence',
    body: 'Geolocation, ASN, reverse DNS, open ports, proxy/VPN flags and DNSBL reputation — plotted live on a dark tactical map.',
  },
  {
    tag: 'MODULE 02',
    title: 'Domain Recon',
    body: 'WHOIS, DNS records, SSL certificate chains, subdomain discovery and HTTP header fingerprinting in a single sweep.',
  },
  {
    tag: 'MODULE 03',
    title: 'Email Footprint',
    body: 'Format validation, MX checks, breach exposure signals, reputation scoring and search-engine dork generation.',
  },
  {
    tag: 'MODULE 04',
    title: 'Username Hunt',
    body: 'Concurrent enumeration across dozens of platforms to surface accounts tied to a single handle.',
  },
  {
    tag: 'MODULE 05',
    title: 'Phone Profiling',
    body: 'Carrier, line type, region and timezone resolution plus direct messaging-platform lookups.',
  },
  {
    tag: 'MODULE 06',
    title: 'Correlation Engine',
    body: 'Derives and cross-checks related identifiers — turning one seed target into a connected intelligence graph.',
  },
]

export const PLANS = [
  {
    plan: 'Recon',
    price: '$0',
    period: '/ forever',
    featured: false,
    cta: 'Start free',
    perks: [
      'All 6 OSINT modules',
      'Depth 1–2 scans',
      'Live terminal output',
      'JSON + CSV export',
      'Community support',
    ],
  },
  {
    plan: 'Operator',
    price: '$29',
    period: '/ month',
    featured: true,
    cta: 'Go Operator',
    perks: [
      'Everything in Recon',
      'Deep (depth 3) sweeps',
      'Correlation graph engine',
      'API keys for premium feeds',
      'Map clustering + heatmaps',
      'Priority support',
    ],
  },
  {
    plan: 'Agency',
    price: '$99',
    period: '/ month',
    featured: false,
    cta: 'Contact us',
    perks: [
      'Everything in Operator',
      'Bulk target batches',
      'Scheduled monitoring',
      'Team workspaces',
      'Audit logging',
      'SLA + onboarding',
    ],
  },
]
