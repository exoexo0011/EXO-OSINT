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

`v2.0.0`

</div>

---

## What's New in 2.0

- **`--investigate` mega flag** — runs every relevant module + correlation engine + saves HTML/JSON reports in one command.
- **OSINT Correlation Engine** — derives related identifiers (email→username, domain→common emails, username→candidate emails, IP→reverse DNS) and confirms them with lightweight checks (Gravatar, DNS, MX, top-platform username probes).
- **85+ username platforms** organized into 11 categories (coding, social, professional, content, creative, gaming, content-creator, finance, adult, hacking, learning) with per-category risk highlights.
- **Stunning HTML dashboard** — sidebar nav, Leaflet map of IP geolocations, Chart.js severity donut + per-target footprint bar chart, dark/light toggle, in-page JSON & CSV export buttons, copy-to-clipboard on every finding, animated scan effect, profile pictures inline.
- **Digital Footprint Score (0-100)** per target, computed from finding severity, source diversity, and confirmed correlations.
- **Stealth mode** (`--stealth`) and **depth control** (`--depth 1|2|3`) for rate-limit-friendly or maximum-coverage runs.
- **New free data sources**: GreyNoise community, certificate transparency logs (crt.sh), urlscan.io public search with screenshots, GitLab user search, CDN/hosting fingerprint via ASN.
- **New optional API integrations** (graceful when missing): VirusTotal, Google Safe Browsing, SecurityTrails historical DNS, IPQualityScore.
- **Phone OSINT**: full curated dork URL set (Google + Indian directories: OLX, Justdial, Quikr, IndiaMART, Sulekha) + WhatsApp wa.me presence hint + Truecaller probe + paste leak check.

## Features by Module

### IP Intelligence (`ip`)
- Geolocation (country, city, lat/long, timezone) via ip-api.com
- ISP, ASN, organization
- **CDN / hosting fingerprint** (Cloudflare, AWS, Azure, GCP, Akamai, Fastly, DigitalOcean, Linode, Hetzner, OVH, …)
- VPN / Proxy / Tor / Hosting flags
- **GreyNoise community** noise/RIOT classification (free, no key)
- AbuseIPDB reputation (`ABUSEIPDB_API_KEY`)
- IPQualityScore fraud (`IPQUALITYSCORE_API_KEY`)
- Reverse DNS, WHOIS, common port scan, DNSBL listings
- Shodan + Censys deep-link URLs

### Domain Reconnaissance (`domain`)
- WHOIS, full DNS records (A/AAAA/MX/TXT/NS/CNAME/SOA)
- **Certificate transparency** subdomains (crt.sh)
- Brute-force subdomain enumeration (deeper wordlist at `--depth 3`)
- SSL/TLS certificate analysis with full SAN list
- HTTP headers, security headers audit, technology fingerprinting
- **urlscan.io** historical scans with screenshots
- VirusTotal v3 (`VT_API_KEY`)
- Google Safe Browsing (`SAFEBROWSING_API_KEY`)
- SecurityTrails historical DNS (`SECURITYTRAILS_API_KEY`)
- Wayback Machine first-seen, full redirect chain

### Email Investigation (`email`)
- Format, MX, disposable, provider fingerprint
- SMTP probe with multi-MX fallback + catch-all detection
- **Gravatar** profile (display name, location, linked Twitter/LinkedIn/GitHub)
- **LeakCheck** public breach search (free, no key)
- **Pastebin** via psbdmp.ws
- **GitHub + GitLab** user search by email
- Web mentions via DuckDuckGo HTML
- 11 ready-to-use Google dork URLs
- Hunter.io domain (`HUNTER_API_KEY`)
- EmailRep.io reputation (`EMAILREP_API_KEY`)
- HaveIBeenPwned breaches (`HIBP_API_KEY`)

### Username Hunting (`username`)
- **85+ platforms** checked concurrently
- Categories: coding (15), social (15), professional (7), content (13), creative (9), gaming (8), content-creator (5), finance (3), adult (2), hacking (5), learning (1)
- Risk callouts for adult / finance / hacking accounts
- Profile URLs returned for every hit

### Phone Number Lookup (`phone`)
- Parsing & validation (`phonenumbers`)
- Country / region / carrier / line type / timezone
- WhatsApp wa.me presence hint
- Truecaller public probe
- Pastebin via psbdmp.ws
- 14 platform deep-link URLs (OLX, Justdial, Quikr, IndiaMART, Sulekha, Sync.me, ShouldIAnswer, SpyDialer, Facebook/Instagram/Telegram search, Skype directory, Viber, wa.me, Truecaller)
- 14 Google dork URLs

### Correlation Engine
- **email** → username (from local part) + domain
- **domain** → candidate emails (info@, admin@, contact@, support@, …)
- **username** → candidate emails (gmail/outlook/yahoo/proton)
- **IP** → reverse DNS → candidate domain
- Lightweight confirmation: Gravatar lookup, DNS resolve, MX check, top-platform username probe

### Reporting
- **HTML dashboard** with Leaflet map, Chart.js charts, sidebar nav, dark/light toggle, footprint score bars, export buttons, copy-to-clipboard, animated scan effect, profile pictures
- **JSON** — full structured export (versioned)
- **CSV** — flat findings table

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

# Mega flag — run everything + correlation + html+json + save
python exoosint.py --target 8.8.8.8 --investigate
python exoosint.py --target github.com --investigate
python exoosint.py --target user@gmail.com --investigate
python exoosint.py --target elonmusk --investigate
python exoosint.py --target +917051930965 --investigate --country IN

# Stealth mode (random delays between requests)
python exoosint.py --target elonmusk --investigate --stealth

# Deep mode (more aggressive subdomain wordlist, etc.)
python exoosint.py --target target.com --investigate --depth 3

# Bulk
python exoosint.py --targets-file targets.txt --investigate
```

## CLI Reference

| Flag | Description |
|------|-------------|
| `--target` | Single target (auto-detected) |
| `--type` | Force type: `ip`, `domain`, `email`, `username`, `phone` |
| `--targets-file` | Path to file with one target per line |
| `--investigate` | Mega flag: run all modules + correlation + html+json + save |
| `--depth {1,2,3}` | 1=basic, 2=standard (default), 3=deep |
| `--stealth` | Random delay between external requests |
| `--country` | Default region for phone parsing (default: IN) |
| `--modules` | Comma-separated modules to run |
| `--username-platforms` | Comma-separated platforms |
| `--report` | `html`, `json`, `csv`, or combo (e.g. `html,json`) |
| `--save` | Save reports to a timestamped folder |
| `--output` | `table` or `json` for stdout |
| `--threads` | Concurrent threads (default: 20) |
| `--timeout` | Per-request timeout seconds (default: 10) |
| `--no-banner` | Suppress ASCII banner |
| `--no-correlation` | Disable the correlation engine even with `--investigate` |
| `--version` | Show version |

## Optional API Keys

EXO-OSINT works without any API keys. To enable enriched data, export:

```bash
export ABUSEIPDB_API_KEY="..."        # IP abuse score
export IPQUALITYSCORE_API_KEY="..."   # IP fraud score (free tier)
export HIBP_API_KEY="..."             # HaveIBeenPwned breach list
export HUNTER_API_KEY="..."           # Hunter.io domain intel (25 free/mo)
export EMAILREP_API_KEY="..."         # EmailRep.io reputation
export VT_API_KEY="..."               # VirusTotal v3 domain scan
export SAFEBROWSING_API_KEY="..."     # Google Safe Browsing v4
export SECURITYTRAILS_API_KEY="..."   # SecurityTrails historical DNS
```

## Realistic OSINT Note

EXO-OSINT is honest about which sources can be reliably automated and which cannot:

- **Sources that work end-to-end**: ip-api, GreyNoise community, Gravatar, LeakCheck, GitHub/GitLab search, crt.sh, urlscan.io, Wayback Machine, DuckDuckGo HTML (when not anti-bot challenged), all 85+ username platform checks, and every key-based API.
- **Sources that are anti-bot challenged**: Truecaller, Justdial, Sulekha, IndiaMART, Quikr, OLX, Facebook/Instagram phone search, raw Google searches. For these, EXO-OSINT generates one-click curated **dork URLs** so the investigator can review them manually — the same convention used by professional OSINT toolchains.

## Design Principles

- **Graceful degradation** — never crash on missing libraries, keys, or network errors
- **Concurrency where it matters** — threaded username/port checks, threaded crt.sh/urlscan
- **Pipe-friendly** — logs to stderr, results to stdout
- **No mandatory dependencies on paid APIs**
- **Auto-detection** of target type from input shape
- **Reproducible HTML** — full investigation JSON embedded inline so the report is self-contained

## Disclaimer

This tool is provided **for authorized security research and educational purposes only**. The user is solely responsible for ensuring all activity complies with applicable laws and the terms of service of any queried platform. Do not use EXO-OSINT to harass, stalk, or violate the privacy of individuals.

## License

MIT
