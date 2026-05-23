"""Domain reconnaissance module."""

from __future__ import annotations

import socket
import ssl
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from typing import Any, Dict, List, Optional

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


# Compact built-in subdomain wordlist
SUBDOMAIN_WORDLIST = [
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
}


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


def _enumerate_subdomains(domain: str, threads: int, timeout: int) -> List[str]:
    found: List[str] = []
    with ThreadPoolExecutor(max_workers=threads) as pool:
        futs = {pool.submit(_check_subdomain, sub, domain, timeout): sub for sub in SUBDOMAIN_WORDLIST}
        for fut in as_completed(futs):
            try:
                r = fut.result()
                if r:
                    found.append(r)
            except Exception:
                pass
    return sorted(found)


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


def _http_inspect(domain: str, timeout: int) -> Optional[Dict[str, Any]]:
    out: Dict[str, Any] = {}
    for scheme in ("https", "http"):
        url = f"{scheme}://{domain}"
        try:
            r = requests.get(
                url,
                timeout=timeout,
                allow_redirects=True,
                headers={"User-Agent": "EXO-OSINT/1.0 (+https://github.com/exoexo0011/EXO-OSINT)"},
            )
            redirect_chain = [{"url": h.url, "status": h.status_code} for h in r.history]
            redirect_chain.append({"url": r.url, "status": r.status_code})
            out["scheme_used"] = scheme
            out["final_url"] = r.url
            out["status_code"] = r.status_code
            out["redirect_chain"] = redirect_chain
            out["headers"] = {k: v for k, v in r.headers.items()}

            # security headers
            sec = {}
            lower_headers = {k.lower(): v for k, v in r.headers.items()}
            for h in SECURITY_HEADERS:
                sec[h] = lower_headers.get(h.lower())
            out["security_headers"] = sec

            # tech fingerprints
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

            # parked / alive heuristic
            out["alive"] = True
            parked_markers = ["this domain is for sale", "parked free", "domain parking", "buy this domain"]
            out["parked"] = any(p in body_sample for p in parked_markers)
            return out
        except Exception:
            continue
    out["alive"] = False
    return out or None


def _wayback_first_seen(domain: str, timeout: int) -> Optional[Dict[str, Any]]:
    try:
        url = f"https://archive.org/wayback/available?url={domain}"
        r = requests.get(url, timeout=timeout)
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


def run(domain: str, timeout: int = 10, threads: int = 20) -> ModuleResult:
    domain = domain.strip().lower().rstrip("/")
    if domain.startswith("http://"):
        domain = domain[7:]
    if domain.startswith("https://"):
        domain = domain[8:]

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
        # check missing security headers
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

    ui.info("Subdomain enumeration...")
    subs = _enumerate_subdomains(domain, threads=threads, timeout=min(timeout, 5))
    if subs:
        res.data["subdomains"] = subs
        res.add("subdomains_found", subs, source="dns_brute",
                note=f"{len(subs)} live subdomains")

    ui.info("Wayback Machine...")
    wb = _wayback_first_seen(domain, timeout)
    if wb:
        res.data["wayback"] = wb
        if wb.get("timestamp"):
            res.add("wayback_first_seen", wb["timestamp"], source="archive.org")

    res.finish(success=True)
    return res
