<div align="center">

```
███████╗██╗  ██╗ ██████╗        ██████╗ ███████╗██╗███╗   ██╗████████╗
██╔════╝╚██╗██╔╝██╔═══██╗      ██╔═══██╗██╔════╝██║████╗  ██║╚══██╔══╝
█████╗   ╚███╔╝ ██║   ██║█████╗██║   ██║███████╗██║██╔██╗ ██║   ██║   
██╔══╝   ██╔██╗ ██║   ██║╚════╝██║   ██║╚════██║██║██║╚██╗██║   ██║   
███████╗██╔╝ ██╗╚██████╔╝      ╚██████╔╝███████║██║██║ ╚████║   ██║   
╚══════╝╚═╝  ╚═╝ ╚═════╝        ╚═════╝ ╚══════╝╚═╝╚═╝  ╚═══╝   ╚═╝
```

**[ Open Source Intelligence Framework ]**

*// Authorized intelligence gathering only*

`v1.0.0`

</div>

---

## Overview

EXO-OSINT is a professional, modular OSINT (Open Source Intelligence) framework written in Python. It performs reconnaissance against a wide range of target types — IP addresses, domains, emails, usernames, and phone numbers — and produces clean, professional reports in HTML, JSON, and CSV.

The tool is designed for authorized security research, threat intelligence, digital forensics, and red-team reconnaissance.

## Features

### IP Intelligence (`ip`)
- Geolocation (country, city, lat/long, timezone)
- ISP / ASN / organization
- Reverse DNS resolution
- VPN / Proxy / Tor / Hosting detection
- Spam blacklist (DNSBL) checks
- WHOIS data
- Common port scan (top 20 ports)
- AbuseIPDB reputation (optional API key)

### Domain Reconnaissance (`domain`)
- WHOIS (registrar, dates, nameservers, registrant)
- DNS records (A, AAAA, MX, TXT, NS, CNAME, SOA)
- Subdomain enumeration (built-in wordlist)
- SSL/TLS certificate analysis
- HTTP headers & security headers audit
- Technology detection
- Wayback Machine first-seen
- Redirect chain follower
- Parked / alive status

### Email Investigation (`email`)
- Format validation, MX verification, disposable detection, provider fingerprint
- SMTP mailbox verification with multi-MX fallback and catch-all detection
- Gravatar avatar + profile JSON (display name, location, linked accounts)
- LeakCheck public breach search (free, no key)
- Pastebin via psbdmp.ws (paste IDs + URLs, free)
- GitHub user search by email (unauthenticated)
- Web mentions via DuckDuckGo HTML scrape
- Pre-built search URL hints (Google, Bing, LinkedIn, GitHub commits, Twitter)
- Hunter.io domain intel (`HUNTER_API_KEY`)
- EmailRep.io reputation (`EMAILREP_API_KEY`)
- HaveIBeenPwned breach list (`HIBP_API_KEY`)
- Auto-runs domain recon on the email's domain

### Username Hunting (`username`)
- 50+ platforms checked **concurrently** via `ThreadPoolExecutor`
- Categorized: social, coding, gaming, creative, professional, content
- Returns profile URLs for found accounts
- Configurable threads and timeouts

### Phone Number Lookup (`phone`)
- Format parsing & validation (`phonenumbers`)
- Country / region / carrier / line type
- International, national, and E.164 formats
- Timezone(s)

### Reporting
- **HTML** — dark "ghost/phantom" theme with glowing purple accents
- **JSON** — full structured export
- **CSV** — tabular flat export
- Executive summary with risk indicators
- Per-target collapsible sections

## Installation

```bash
git clone https://github.com/exoexo0011/EXO-OSINT.git
cd EXO-OSINT
pip install -r requirements.txt
```

## Usage

```bash
# Show help
python exoosint.py --help

# IP intelligence
python exoosint.py --target 8.8.8.8 --report html --save

# Domain recon
python exoosint.py --target google.com --report html --save

# Email recon
python exoosint.py --target user@gmail.com --report html --save

# Username hunting
python exoosint.py --target elonmusk --report html --save

# Phone number lookup
python exoosint.py --target +919876543210 --report html --save

# Bulk targets from file with HTML + JSON output
python exoosint.py --targets-file targets.txt --report html,json --save
```

## CLI Reference

| Flag | Description |
|------|-------------|
| `--target` | Single target (auto-detected) |
| `--type` | Force type: `ip`, `domain`, `email`, `username`, `phone` |
| `--targets-file` | Path to file with one target per line |
| `--modules` | Comma-separated modules to run (default: all relevant) |
| `--username-platforms` | Comma-separated platforms to check |
| `--report` | `html`, `json`, `csv`, or combo (e.g. `html,json`) |
| `--save` | Save reports to a timestamped folder |
| `--output` | `table` or `json` for stdout |
| `--threads` | Concurrent threads for username/port checks (default: 20) |
| `--timeout` | Per-request timeout in seconds (default: 10) |
| `--no-banner` | Suppress ASCII banner |
| `--version` | Show version |

## Optional API Keys

EXO-OSINT works without API keys. To enable enriched data, export:

```bash
export ABUSEIPDB_API_KEY="your-key-here"   # IP abuse score
export HIBP_API_KEY="your-key-here"        # HaveIBeenPwned breach list
export HUNTER_API_KEY="your-key-here"      # Hunter.io domain intel (25 free/mo)
export EMAILREP_API_KEY="your-key-here"    # EmailRep.io reputation
```

## Design Principles

- **Graceful degradation** — never crash on missing libraries, keys, or network errors
- **Concurrency where it matters** — threaded username/port checks
- **Pipe-friendly** — logs to stderr, results to stdout
- **No mandatory dependencies on paid APIs**
- **Auto-detection** of target type from input shape

## Disclaimer

This tool is provided **for authorized security research and educational purposes only**. The user is solely responsible for ensuring all activity complies with applicable laws and the terms of service of any queried platform. Do not use EXO-OSINT to harass, stalk, or violate the privacy of individuals.

## License

MIT
