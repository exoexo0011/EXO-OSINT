"""Domain reconnaissance module — WHOIS, DNS, subdomains, SSL, HTTP, CT logs,
URLscan, VirusTotal/SafeBrowsing/SecurityTrails (key-based)."""

from __future__ import annotations

import os
import socket
import ssl
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from typing import Any, Dict, List, Optional
from urllib.parse import quote_plus

import requests

from . import ui
from .types import ModuleResult


SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
    "X-XSS-Protection",
]


SUBDOMAIN_WORDLIST_BASE = [
    "www", "mail", "ftp", "webmail", "smtp", "pop", "imap", "ns1", "ns2", "ns3",
    "dns", "api", "dev", "staging", "test", "demo", "beta", "admin", "portal",
    "vpn", "remote", "blog", "shop", "store", "app", "apps", "mobile", "m",
    "secure", "support", "help", "docs", "wiki", "status", "cdn", "static",
    "assets", "media", "img", "images", "video", "videos", "download", "files",
    "git", "gitlab", "jenkins", "ci", "build", "deploy", "monitor", "metrics",
    "grafana", "prometheus", "kibana", "elastic", "redis", "db", "database",
    "sql", "mysql", "postgres", "mongo", "auth", "login", "sso", "oauth",
    "id", "account", "accounts", "billing", "payments", "checkout",
]

SUBDOMAIN_WORDLIST_DEEP = SUBDOMAIN_WORDLIST_BASE + [
    "admin1", "admin2", "internal", "intranet", "extranet", "old", "new",
    "v1", "v2", "v3", "alpha", "preprod", "uat", "qa", "sandbox", "edge",
    "graphql", "grpc", "rest", "soap", "ws", "stream", "video", "voice",
    "stage", "dev1", "dev2", "test1", "test2", "demo1", "demo2",
    "office", "corp", "hr", "finance", "legal", "support1", "kb",
    "developer", "developers", "partners", "partner", "vendor", "vendors",
    "console", "control", "panel", "manage", "manager", "ops", "siem",
    "exchange", "owa", "autodiscover", "lync", "sip", "voip",
]


TECH_FINGERPRINTS = {
    "wordpress": ["wp-content", "wp-includes", "wordpress"],
    "drupal": ["drupal"],
    "joomla": ["joomla"],
    "django": ["csrfmiddlewaretoken", "django"],
    "flask": ["werkzeug"],
    "express": ["express"],
    "nginx": ["nginx"],
    "apache": ["apache"],
    "cloudflare": ["cloudflare"],
    "aws": ["amazonaws", "x-amz-"],
    "shopify": ["shopify"],
    "wix": ["wix.com"],
    "squarespace": ["squarespace"],
    "react": ["__next", "_next/static", "react"],
    "vue": ["vue.js"],
    "angular": ["ng-version"],
    "next.js": ["__next", "_next/static"],
    "nuxt": ["__nuxt"],
    "laravel": ["laravel_session", "x-laravel"],
    "ruby-on-rails": ["x-runtime", "csrf-token"],
}

DEFAULT_HEADERS = {
    "User-Agent": "EXO-OSINT/2.0 (+https://github.com/exoexo0011/EXO-OSINT)",
    "Accept": "text/html,application/xhtml+xml,application/json,*/*;q=0.8",
}


def _strip_scheme(domain: str) -> str:
    d = (domain or "").strip().lower().rstrip("/")
    if d.startswith("http://"):
        d = d[7:]
    if d.startswith("https://"):
        d = d[8:]
    return d


# ---------------------------------------------------------------------------
# WHOIS
# ---------------------------------------------------------------------------

def _whois_lookup(domain: str) -> Optional[Dict[str, Any]]:
    try:
        import whois
    except Exception:
        return None
    try:
        w = whois.whois(domain)
        if not w:
            return None
        out: Dict[str, Any] = {}
        for k, v in dict(w).items():
            if v is None:
                continue
            if isinstance(v, (list, tuple)):
                out[k] = [str(x) for x in v]
            elif isinstance(v, datetime):
                out[k] = v.isoformat()
            else:
                out[k] = str(v)
        return out or None
    except Exception as exc:
        ui.warn(f"whois failed: {exc}")
        return None


# ---------------------------------------------------------------------------
# DNS
# ---------------------------------------------------------------------------

def _dns_records(domain: str, timeout: int) -> Dict[str, List[str]]:
    records: Dict[str, List[str]] = {}
    try:
        import dns.resolver
        resolver = dns.resolver.Resolver()
        resolver.timeout = timeout
        resolver.lifetime = timeout
    except Exception:
        return records
    for rtype in ("A", "AAAA", "MX", "TXT", "NS", "CNAME", "SOA"):
        try:
            answers = resolver.resolve(domain, rtype, raise_on_no_answer=False)
            vals: List[str] = []
            for a in answers:
                vals.append(a.to_text().strip('"'))
            if vals:
                records[rtype] = vals
        except Exception:
            continue
    return records


# ---------------------------------------------------------------------------
# Subdomain enumeration via brute-force + crt.sh CT logs
# ---------------------------------------------------------------------------

def _check_subdomain(sub: str, domain: str, timeout: int) -> Optional[str]:
    fqdn = f"{sub}.{domain}"
    try:
        socket.setdefaulttimeout(timeout)
        socket.gethostbyname(fqdn)
        return fqdn
    except Exception:
        return None
    finally:
        socket.setdefaulttimeout(None)


def _enumerate_subdomains_brute(
    domain: str, threads: int, timeout: int, wordlist: List[str]
) -> List[str]:
    found: List[str] = []
    with ThreadPoolExecutor(max_workers=threads) as pool:
        futs = {pool.submit(_check_subdomain, sub, domain, timeout): sub for sub in wordlist}
        for fut in as_completed(futs):
            try:
                r = fut.result()
                if r:
                    found.append(r)
            except Exception:
                pass
    return sorted(found)


def _crtsh_subdomains(domain: str, timeout: int) -> Optional[Dict[str, Any]]:
    """crt.sh certificate transparency logs — free, no key."""
    try:
        ui.stealth_sleep()
        r = requests.get(
            "https://crt.sh/",
            params={"q": f"%.{domain}", "output": "json"},
            headers=DEFAULT_HEADERS,
            timeout=timeout * 2,  # crt.sh can be slow
        )
        if r.status_code != 200:
            return None
        try:
            data = r.json()
        except ValueError:
            return None
        names: set = set()
        for entry in (data or [])[:5000]:
            n = (entry.get("name_value") or "").strip().lower()
            for line in n.splitlines():
                line = line.strip().lstrip("*.")
                if line and (line == domain or line.endswith("." + domain)):
                    names.add(line)
        return {
            "count": len(names),
            "names": sorted(names),
        }
    except Exception as exc:
        ui.warn(f"crt.sh failed: {exc}")
        return None


# ---------------------------------------------------------------------------
# SSL/TLS
# ---------------------------------------------------------------------------

def _ssl_info(domain: str, timeout: int) -> Optional[Dict[str, Any]]:
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
        if not cert:
            return None
        issuer = dict(x[0] for x in cert.get("issuer", [])) if cert.get("issuer") else {}
        subject = dict(x[0] for x in cert.get("subject", [])) if cert.get("subject") else {}
        sans = [v for k, v in cert.get("subjectAltName", []) if k == "DNS"]
        return {
            "issuer": issuer,
            "subject": subject,
            "not_before": cert.get("notBefore"),
            "not_after": cert.get("notAfter"),
            "serial_number": cert.get("serialNumber"),
            "version": cert.get("version"),
            "subject_alt_names": sans,
        }
    except Exception as exc:
        ui.warn(f"ssl lookup failed: {exc}")
        return None


# ---------------------------------------------------------------------------
# HTTP inspection
# ---------------------------------------------------------------------------

def _http_inspect(domain: str, timeout: int) -> Optional[Dict[str, Any]]:
    out: Dict[str, Any] = {}
    for scheme in ("https", "http"):
        url = f"{scheme}://{domain}"
        try:
            ui.stealth_sleep()
            r = requests.get(
                url, timeout=timeout, allow_redirects=True,
                headers=DEFAULT_HEADERS,
            )
            redirect_chain = [{"url": h.url, "status": h.status_code} for h in r.history]
            redirect_chain.append({"url": r.url, "status": r.status_code})
            out["scheme_used"] = scheme
            out["final_url"] = r.url
            out["status_code"] = r.status_code
            out["redirect_chain"] = redirect_chain
            out["headers"] = {k: v for k, v in r.headers.items()}

            sec = {}
            lower_headers = {k.lower(): v for k, v in r.headers.items()}
            for h in SECURITY_HEADERS:
                sec[h] = lower_headers.get(h.lower())
            out["security_headers"] = sec

            body_sample = (r.text[:50000] if r.text else "").lower()
            header_blob = " ".join(f"{k}:{v}" for k, v in lower_headers.items()).lower()
            techs: List[str] = []
            for tech, markers in TECH_FINGERPRINTS.items():
                for m in markers:
                    if m in body_sample or m in header_blob:
                        techs.append(tech)
                        break
            if lower_headers.get("server"):
                techs.append(lower_headers["server"])
            out["technologies"] = sorted(set(techs))

            out["alive"] = True
            parked_markers = [
                "this domain is for sale", "parked free", "domain parking",
                "buy this domain",
            ]
            out["parked"] = any(p in body_sample for p in parked_markers)
            return out
        except Exception:
            continue
    out["alive"] = False
    return out or None


# ---------------------------------------------------------------------------
# Wayback Machine
# ---------------------------------------------------------------------------

def _wayback_first_seen(domain: str, timeout: int) -> Optional[Dict[str, Any]]:
    try:
        ui.stealth_sleep()
        url = f"https://archive.org/wayback/available?url={domain}"
        r = requests.get(url, timeout=timeout, headers=DEFAULT_HEADERS)
        if r.status_code != 200:
            return None
        data = r.json() or {}
        snap = data.get("archived_snapshots", {}).get("closest")
        if not snap:
            return None
        return {
            "available": snap.get("available", False),
            "url": snap.get("url"),
            "timestamp": snap.get("timestamp"),
            "status": snap.get("status"),
        }
    except Exception as exc:
        ui.warn(f"wayback check failed: {exc}")
        return None


# ---------------------------------------------------------------------------
# urlscan.io public search
# ---------------------------------------------------------------------------

def _urlscan_search(domain: str, timeout: int) -> Optional[Dict[str, Any]]:
    try:
        ui.stealth_sleep()
        r = requests.get(
            "https://urlscan.io/api/v1/search/",
            params={"q": f"domain:{domain}", "size": 10},
            headers=DEFAULT_HEADERS, timeout=timeout,
        )
        if r.status_code != 200:
            return None
        data = r.json() or {}
        results = []
        for hit in (data.get("results") or [])[:10]:
            results.append({
                "task_url": hit.get("result"),
                "screenshot_url": hit.get("screenshot"),
                "page": (hit.get("page") or {}).get("url"),
                "country": (hit.get("page") or {}).get("country"),
                "ip": (hit.get("page") or {}).get("ip"),
                "asn": (hit.get("page") or {}).get("asn"),
                "time": hit.get("task", {}).get("time"),
            })
        return {"total": int(data.get("total", 0)), "results": results}
    except Exception as exc:
        ui.warn(f"urlscan failed: {exc}")
        return None


# ---------------------------------------------------------------------------
# VirusTotal v3 (API key)
# ---------------------------------------------------------------------------

def _virustotal(domain: str, timeout: int) -> Optional[Dict[str, Any]]:
    api_key = os.environ.get("VT_API_KEY") or os.environ.get("VIRUSTOTAL_API_KEY")
    if not api_key:
        return None
    try:
        ui.stealth_sleep()
        r = requests.get(
            f"https://www.virustotal.com/api/v3/domains/{domain}",
            headers={"x-apikey": api_key, "Accept": "application/json"},
            timeout=timeout,
        )
        if r.status_code != 200:
            return None
        data = (r.json() or {}).get("data", {}).get("attributes", {}) or {}
        stats = data.get("last_analysis_stats", {}) or {}
        return {
            "reputation": data.get("reputation"),
            "harmless": stats.get("harmless"),
            "malicious": stats.get("malicious"),
            "suspicious": stats.get("suspicious"),
            "undetected": stats.get("undetected"),
            "categories": data.get("categories", {}),
            "last_analysis_date": data.get("last_analysis_date"),
            "creation_date": data.get("creation_date"),
            "registrar": data.get("registrar"),
        }
    except Exception as exc:
        ui.warn(f"virustotal failed: {exc}")
        return None


# ---------------------------------------------------------------------------
# Google Safe Browsing v4 (API key)
# ---------------------------------------------------------------------------

def _safe_browsing(domain: str, timeout: int) -> Optional[Dict[str, Any]]:
    api_key = os.environ.get("SAFEBROWSING_API_KEY") or os.environ.get("GSB_API_KEY")
    if not api_key:
        return None
    payload = {
        "client": {"clientId": "exo-osint", "clientVersion": "2.0"},
        "threatInfo": {
            "threatTypes": [
                "MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE",
                "POTENTIALLY_HARMFUL_APPLICATION",
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": f"http://{domain}/"}, {"url": f"https://{domain}/"}],
        },
    }
    try:
        ui.stealth_sleep()
        r = requests.post(
            f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}",
            json=payload, headers=DEFAULT_HEADERS, timeout=timeout,
        )
        if r.status_code != 200:
            return None
        data = r.json() or {}
        matches = data.get("matches", []) or []
        return {"matches": matches, "match_count": len(matches)}
    except Exception as exc:
        ui.warn(f"safebrowsing failed: {exc}")
        return None


# ---------------------------------------------------------------------------
# SecurityTrails (API key) — historical DNS
# ---------------------------------------------------------------------------

def _securitytrails_history(domain: str, timeout: int) -> Optional[Dict[str, Any]]:
    api_key = os.environ.get("SECURITYTRAILS_API_KEY")
    if not api_key:
        return None
    try:
        ui.stealth_sleep()
        r = requests.get(
            f"https://api.securitytrails.com/v1/history/{domain}/dns/a",
            headers={"APIKEY": api_key, "Accept": "application/json"},
            timeout=timeout,
        )
        if r.status_code != 200:
            return None
        data = r.json() or {}
        records = data.get("records", []) or []
        history: List[Dict[str, Any]] = []
        for rec in records[:20]:
            history.append({
                "first_seen": rec.get("first_seen"),
                "last_seen": rec.get("last_seen"),
                "values": [v.get("ip") for v in (rec.get("values") or [])],
            })
        return {"count": len(records), "history": history}
    except Exception as exc:
        ui.warn(f"securitytrails failed: {exc}")
        return None


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------

def run(domain: str, timeout: int = 10, threads: int = 20, depth: int = 2) -> ModuleResult:
    domain = _strip_scheme(domain)
    res = ModuleResult(module="domain", target=domain, target_type="domain")

    ui.info(f"WHOIS for {domain}...")
    w = _whois_lookup(domain)
    if w:
        res.data["whois"] = w
        for k in ("registrar", "creation_date", "expiration_date", "updated_date"):
            if w.get(k):
                res.add(f"whois_{k}", w[k], source="whois")
        if w.get("name_servers"):
            res.add("nameservers", w["name_servers"], source="whois")
        if w.get("registrant") or w.get("name"):
            res.add("registrant", w.get("registrant") or w.get("name"), source="whois")

    ui.info("DNS records...")
    dns_records = _dns_records(domain, timeout)
    if dns_records:
        res.data["dns"] = dns_records
        for rtype, vals in dns_records.items():
            res.add(f"dns_{rtype}", vals, source="dns")

    ui.info("HTTP inspection...")
    http_info = _http_inspect(domain, timeout)
    if http_info:
        res.data["http"] = http_info
        if http_info.get("status_code"):
            res.add("http_status", http_info["status_code"], source="http")
        if http_info.get("technologies"):
            res.add("technologies", http_info["technologies"], source="http")
        if http_info.get("parked"):
            res.add("parked", True, severity="medium", source="http",
                    note="domain appears to be parked")
        sec = http_info.get("security_headers", {})
        missing = [h for h, v in sec.items() if not v]
        if missing:
            res.add("missing_security_headers", missing, severity="medium",
                    source="http", note=f"{len(missing)} security headers missing")
        if http_info.get("redirect_chain") and len(http_info["redirect_chain"]) > 1:
            res.add("redirects", http_info["redirect_chain"], source="http")

    ui.info("SSL/TLS certificate...")
    sslinfo = _ssl_info(domain, timeout)
    if sslinfo:
        res.data["ssl"] = sslinfo
        if sslinfo.get("issuer", {}).get("organizationName"):
            res.add("ssl_issuer", sslinfo["issuer"]["organizationName"], source="ssl")
        if sslinfo.get("not_after"):
            res.add("ssl_expires", sslinfo["not_after"], source="ssl")
        if sslinfo.get("subject_alt_names"):
            res.add("ssl_sans", sslinfo["subject_alt_names"][:25], source="ssl",
                    note=f"{len(sslinfo['subject_alt_names'])} SAN entries")

    if depth >= 2:
        wl = SUBDOMAIN_WORDLIST_DEEP if depth >= 3 else SUBDOMAIN_WORDLIST_BASE
        ui.info(f"Subdomain brute-force ({len(wl)} words)...")
        subs = _enumerate_subdomains_brute(domain, threads=threads, timeout=min(timeout, 5), wordlist=wl)
        if subs:
            res.data["subdomains_brute"] = subs
            res.add("subdomains_brute_found", subs, source="dns_brute",
                    note=f"{len(subs)} live subdomains via brute-force")

    if depth >= 2:
        ui.info("crt.sh certificate transparency...")
        ct = _crtsh_subdomains(domain, timeout)
        if ct:
            res.data["crtsh"] = ct
            if ct.get("count", 0) > 0:
                res.add("crtsh_subdomains", ct["count"], source="crt.sh",
                        note=f"{ct['count']} unique names in CT logs")
                # show up to 50 names
                res.add("crtsh_sample", ct["names"][:50], source="crt.sh")

    if depth >= 2:
        ui.info("Wayback Machine...")
        wb = _wayback_first_seen(domain, timeout)
        if wb:
            res.data["wayback"] = wb
            if wb.get("timestamp"):
                res.add("wayback_first_seen", wb["timestamp"], source="archive.org",
                        profile_url=wb.get("url"))

        ui.info("urlscan.io public search...")
        us = _urlscan_search(domain, timeout)
        if us:
            res.data["urlscan"] = us
            if us.get("total", 0) > 0:
                res.add("urlscan_scans", us["total"], source="urlscan.io",
                        note=f"{us['total']} historical scans")
                for hit in (us.get("results") or [])[:5]:
                    if hit.get("task_url"):
                        res.add(f"urlscan_task", hit["task_url"], source="urlscan.io",
                                note=f"ip={hit.get('ip')} asn={hit.get('asn')}",
                                profile_url=hit["task_url"],
                                avatar_url=hit.get("screenshot_url"))

    vt = _virustotal(domain, timeout)
    if vt is not None:
        res.data["virustotal"] = vt
        mal = vt.get("malicious") or 0
        susp = vt.get("suspicious") or 0
        if mal > 0:
            res.add("vt_malicious", mal, severity="critical", source="virustotal",
                    note=f"{mal} engines flagged as malicious")
        if susp > 0:
            res.add("vt_suspicious", susp, severity="high", source="virustotal",
                    note=f"{susp} engines flagged as suspicious")
        if vt.get("reputation") is not None:
            res.add("vt_reputation", vt["reputation"], source="virustotal")
        if vt.get("categories"):
            res.add("vt_categories", vt["categories"], source="virustotal")
    else:
        if not (os.environ.get("VT_API_KEY") or os.environ.get("VIRUSTOTAL_API_KEY")):
            res.add("virustotal", "unavailable",
                    note="set VT_API_KEY for VirusTotal scan")

    sb = _safe_browsing(domain, timeout)
    if sb is not None:
        res.data["safebrowsing"] = sb
        if sb.get("match_count", 0) > 0:
            res.add("safebrowsing_matches", sb["match_count"], severity="critical",
                    source="safebrowsing.googleapis.com",
                    note="domain flagged by Google Safe Browsing")
        else:
            res.add("safebrowsing", "clean", source="safebrowsing.googleapis.com")
    else:
        if not (os.environ.get("SAFEBROWSING_API_KEY") or os.environ.get("GSB_API_KEY")):
            res.add("safebrowsing", "unavailable",
                    note="set SAFEBROWSING_API_KEY for Safe Browsing check")

    st = _securitytrails_history(domain, timeout)
    if st is not None:
        res.data["securitytrails"] = st
        if st.get("count", 0) > 0:
            res.add("st_history_count", st["count"], source="securitytrails.com",
                    note=f"{st['count']} historical A-record changes")
    else:
        if not os.environ.get("SECURITYTRAILS_API_KEY"):
            res.add("securitytrails", "unavailable",
                    note="set SECURITYTRAILS_API_KEY for historical DNS")

    # ---- Summary ----
    techs = http_info.get("technologies", []) if http_info else []
    sub_count_brute = len(res.data.get("subdomains_brute", []))
    ct_count = (res.data.get("crtsh") or {}).get("count", 0)
    vt_mal = (vt or {}).get("malicious", 0) if vt else 0
    res.summary = (
        f"alive={'yes' if (http_info and http_info.get('alive')) else 'no'} | "
        f"subs(brute)={sub_count_brute} | subs(CT)={ct_count} | "
        f"vt_malicious={vt_mal} | tech={','.join(techs[:4]) if techs else 'unknown'}"
    )

    res.finish(success=True)
    return res
