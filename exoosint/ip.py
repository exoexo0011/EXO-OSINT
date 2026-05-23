"""IP intelligence module — geolocation, ASN, reputation, ports, CDN detect."""

from __future__ import annotations

import ipaddress
import os
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, List, Optional

import requests

from . import ui
from .types import ModuleResult


COMMON_PORTS: Dict[int, str] = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    80: "http", 110: "pop3", 111: "rpc", 135: "msrpc", 139: "netbios",
    143: "imap", 443: "https", 445: "smb", 993: "imaps", 995: "pop3s",
    1723: "pptp", 3306: "mysql", 3389: "rdp", 5432: "postgres",
    5900: "vnc", 6379: "redis", 8080: "http-proxy", 8443: "https-alt",
    27017: "mongodb",
}


DNSBL_HOSTS: List[str] = [
    "zen.spamhaus.org",
    "bl.spamcop.net",
    "b.barracudacentral.org",
    "dnsbl.sorbs.net",
    "psbl.surriel.com",
]


# CDN / hosting fingerprint by ASN org name substring
CDN_HOSTING_PATTERNS = {
    "Cloudflare": ["cloudflare"],
    "Amazon AWS": ["amazon", "aws"],
    "Microsoft Azure": ["microsoft", "azure"],
    "Google Cloud": ["google"],
    "Akamai": ["akamai"],
    "Fastly": ["fastly"],
    "DigitalOcean": ["digitalocean"],
    "Linode/Akamai": ["linode"],
    "Hetzner": ["hetzner"],
    "OVH": ["ovh"],
    "Vultr": ["vultr"],
    "Oracle Cloud": ["oracle"],
    "IBM Cloud": ["ibm"],
    "Alibaba Cloud": ["alibaba"],
    "Tencent": ["tencent"],
    "Heroku": ["heroku"],
    "Netlify": ["netlify"],
    "Vercel": ["vercel"],
}


DEFAULT_HEADERS = {
    "User-Agent": "EXO-OSINT/2.0 (+https://github.com/exoexo0011/EXO-OSINT)",
    "Accept": "application/json",
}


def is_valid_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


# ---------------------------------------------------------------------------
# ip-api.com — geolocation, ASN, anonymizer flags
# ---------------------------------------------------------------------------

def _ipapi_lookup(ip: str, timeout: int) -> Optional[Dict[str, Any]]:
    try:
        ui.stealth_sleep()
        url = (
            "http://ip-api.com/json/" + ip
            + "?fields=status,message,continent,country,countryCode,region,regionName,"
              "city,zip,lat,lon,timezone,isp,org,as,asname,reverse,mobile,proxy,hosting,query"
        )
        r = requests.get(url, timeout=timeout)
        if r.status_code != 200:
            return None
        data = r.json()
        if data.get("status") != "success":
            return None
        return data
    except Exception as exc:
        ui.warn(f"ip-api lookup failed: {exc}")
        return None


# ---------------------------------------------------------------------------
# AbuseIPDB (key)
# ---------------------------------------------------------------------------

def _abuseipdb_lookup(ip: str, timeout: int) -> Optional[Dict[str, Any]]:
    api_key = os.environ.get("ABUSEIPDB_API_KEY")
    if not api_key:
        return None
    try:
        ui.stealth_sleep()
        r = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": ""},
            headers={"Key": api_key, "Accept": "application/json"},
            timeout=timeout,
        )
        if r.status_code != 200:
            return None
        return (r.json() or {}).get("data")
    except Exception as exc:
        ui.warn(f"abuseipdb lookup failed: {exc}")
        return None


# ---------------------------------------------------------------------------
# GreyNoise community (free, no key required)
# ---------------------------------------------------------------------------

def _greynoise_community(ip: str, timeout: int) -> Optional[Dict[str, Any]]:
    try:
        ui.stealth_sleep()
        r = requests.get(
            f"https://api.greynoise.io/v3/community/{ip}",
            headers=DEFAULT_HEADERS, timeout=timeout,
        )
        if r.status_code == 404:
            return {"noise": False, "riot": False, "classification": "unknown"}
        if r.status_code != 200:
            return None
        data = r.json() or {}
        return {
            "noise": bool(data.get("noise")),
            "riot": bool(data.get("riot")),
            "classification": data.get("classification") or "unknown",
            "name": data.get("name"),
            "link": data.get("link"),
            "last_seen": data.get("last_seen"),
            "message": data.get("message"),
        }
    except Exception as exc:
        ui.warn(f"greynoise community failed: {exc}")
        return None


# ---------------------------------------------------------------------------
# IPQualityScore (key)
# ---------------------------------------------------------------------------

def _ipqualityscore(ip: str, timeout: int) -> Optional[Dict[str, Any]]:
    api_key = os.environ.get("IPQUALITYSCORE_API_KEY")
    if not api_key:
        return None
    try:
        ui.stealth_sleep()
        r = requests.get(
            f"https://ipqualityscore.com/api/json/ip/{api_key}/{ip}",
            params={"strictness": 0, "allow_public_access_points": "true"},
            headers=DEFAULT_HEADERS, timeout=timeout,
        )
        if r.status_code != 200:
            return None
        data = r.json() or {}
        return {
            "fraud_score": data.get("fraud_score"),
            "is_proxy": data.get("proxy"),
            "is_vpn": data.get("vpn"),
            "is_tor": data.get("tor"),
            "is_active_tor": data.get("active_tor"),
            "is_active_vpn": data.get("active_vpn"),
            "is_bot": data.get("bot_status"),
            "recent_abuse": data.get("recent_abuse"),
            "country_code": data.get("country_code"),
            "host": data.get("host"),
            "isp": data.get("ISP"),
            "organization": data.get("organization"),
            "asn": data.get("ASN"),
        }
    except Exception as exc:
        ui.warn(f"ipqualityscore failed: {exc}")
        return None


# ---------------------------------------------------------------------------
# Shodan public scrape — returns curated link only (the host page is JS-rendered)
# ---------------------------------------------------------------------------

def _shodan_link(ip: str) -> str:
    return f"https://www.shodan.io/host/{ip}"


def _censys_link(ip: str) -> str:
    return f"https://search.censys.io/hosts/{ip}"


# ---------------------------------------------------------------------------
# Reverse DNS / WHOIS
# ---------------------------------------------------------------------------

def _reverse_dns(ip: str, timeout: int) -> Optional[str]:
    socket.setdefaulttimeout(timeout)
    try:
        host, _aliases, _addrs = socket.gethostbyaddr(ip)
        return host
    except Exception:
        return None
    finally:
        socket.setdefaulttimeout(None)


def _whois_lookup(ip: str) -> Optional[Dict[str, Any]]:
    try:
        import whois
    except Exception:
        return None
    try:
        w = whois.whois(ip)
        if not w:
            return None
        out: Dict[str, Any] = {}
        for k, v in dict(w).items():
            if v is None:
                continue
            if isinstance(v, (list, tuple)):
                out[k] = [str(x) for x in v]
            else:
                out[k] = str(v)
        return out or None
    except Exception as exc:
        ui.warn(f"whois lookup failed: {exc}")
        return None


# ---------------------------------------------------------------------------
# Port scan (TCP connect) and DNSBL
# ---------------------------------------------------------------------------

def _check_port(ip: str, port: int, timeout: float) -> bool:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            return s.connect_ex((ip, port)) == 0
    except Exception:
        return False


def _scan_ports(ip: str, threads: int, timeout: float) -> List[Dict[str, Any]]:
    open_ports: List[Dict[str, Any]] = []
    with ThreadPoolExecutor(max_workers=max(threads, 4)) as pool:
        futs = {pool.submit(_check_port, ip, p, timeout): p for p in COMMON_PORTS}
        for fut in as_completed(futs):
            p = futs[fut]
            try:
                if fut.result():
                    open_ports.append({"port": p, "service": COMMON_PORTS[p]})
            except Exception:
                pass
    open_ports.sort(key=lambda x: x["port"])
    return open_ports


def _dnsbl_check(ip: str, timeout: float) -> List[Dict[str, Any]]:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return []
    if isinstance(addr, ipaddress.IPv6Address):
        return []
    reversed_ip = ".".join(reversed(ip.split(".")))
    hits: List[Dict[str, Any]] = []
    socket.setdefaulttimeout(timeout)
    try:
        for host in DNSBL_HOSTS:
            query = f"{reversed_ip}.{host}"
            try:
                socket.gethostbyname(query)
                hits.append({"list": host, "listed": True})
            except socket.gaierror:
                hits.append({"list": host, "listed": False})
            except Exception:
                hits.append({"list": host, "listed": None})
    finally:
        socket.setdefaulttimeout(None)
    return hits


# ---------------------------------------------------------------------------
# CDN / hosting provider detection from ASN / org name
# ---------------------------------------------------------------------------

def _detect_cdn_or_hosting(asn_text: str, org_text: str, isp_text: str) -> Optional[str]:
    blob = " ".join([asn_text or "", org_text or "", isp_text or ""]).lower()
    if not blob.strip():
        return None
    for label, patterns in CDN_HOSTING_PATTERNS.items():
        if any(p in blob for p in patterns):
            return label
    return None


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------

def run(ip: str, timeout: int = 10, threads: int = 20, depth: int = 2) -> ModuleResult:
    res = ModuleResult(module="ip", target=ip, target_type="ip")
    if not is_valid_ip(ip):
        res.finish(success=False, error="invalid IP address")
        return res

    ui.info(f"Geolocating {ip}...")
    geo = _ipapi_lookup(ip, timeout)
    isp_str, asn_str, org_str = "", "", ""
    if geo:
        res.data["geo"] = geo
        loc = ", ".join(filter(None, [geo.get("city"), geo.get("regionName"), geo.get("country")]))
        if loc:
            res.add("location", loc, source="ip-api.com")
        if geo.get("isp"):
            isp_str = geo["isp"]
            res.add("isp", isp_str, source="ip-api.com")
        if geo.get("as"):
            asn_str = geo["as"]
            res.add("asn", asn_str, source="ip-api.com")
        if geo.get("org"):
            org_str = geo["org"]
            res.add("org", org_str, source="ip-api.com")
        if geo.get("timezone"):
            res.add("timezone", geo["timezone"], source="ip-api.com")
        if geo.get("lat") is not None and geo.get("lon") is not None:
            res.add("coordinates", f"{geo['lat']}, {geo['lon']}", source="ip-api.com")
            res.data["lat"] = geo["lat"]
            res.data["lon"] = geo["lon"]
        if geo.get("proxy"):
            res.add("proxy", True, severity="high", source="ip-api.com",
                    note="IP marked as anonymizing proxy/VPN/Tor exit")
        if geo.get("hosting"):
            res.add("hosting", True, severity="medium", source="ip-api.com",
                    note="IP belongs to a hosting/datacenter provider")
        if geo.get("mobile"):
            res.add("mobile", True, source="ip-api.com")
        if geo.get("reverse"):
            res.add("reverse_dns", geo["reverse"], source="ip-api.com")
            res.data["reverse_dns"] = geo["reverse"]
    else:
        ui.warn("ip-api lookup returned no data")

    # CDN / hosting fingerprint
    cdn = _detect_cdn_or_hosting(asn_str, org_str, isp_str)
    if cdn:
        res.add("cdn_or_hosting", cdn, severity="info", source="asn-fingerprint",
                note="provider derived from ASN/org/ISP name")
        res.data["cdn_or_hosting"] = cdn

    if "reverse_dns" not in {f.key for f in res.findings}:
        ui.info("Reverse DNS lookup...")
        rdns = _reverse_dns(ip, timeout)
        if rdns:
            res.add("reverse_dns", rdns, source="socket")
            res.data["reverse_dns"] = rdns

    ui.info("AbuseIPDB...")
    abuse = _abuseipdb_lookup(ip, timeout)
    if abuse:
        res.data["abuseipdb"] = abuse
        score = abuse.get("abuseConfidenceScore", 0)
        sev = "info"
        if score >= 75: sev = "critical"
        elif score >= 50: sev = "high"
        elif score >= 25: sev = "medium"
        elif score > 0:  sev = "low"
        res.add("abuse_score", score, severity=sev, source="abuseipdb.com",
                note=f"{abuse.get('totalReports', 0)} reports")
    elif not os.environ.get("ABUSEIPDB_API_KEY"):
        res.add("abuse_score", "unavailable", note="set ABUSEIPDB_API_KEY for abuse score")

    ui.info("GreyNoise community...")
    gn = _greynoise_community(ip, timeout)
    if gn is not None:
        res.data["greynoise"] = gn
        if gn.get("noise"):
            res.add("greynoise_noise", True, severity="high", source="greynoise.io",
                    note=f"classified as {gn.get('classification')}: {gn.get('name') or 'mass scanner'}")
        elif gn.get("riot"):
            res.add("greynoise_riot", True, severity="info", source="greynoise.io",
                    note=f"common business service: {gn.get('name')}")
        else:
            res.add("greynoise", "no_signal", source="greynoise.io",
                    note="no scan/probe activity in GreyNoise dataset")

    ipqs = _ipqualityscore(ip, timeout)
    if ipqs is not None:
        res.data["ipqualityscore"] = ipqs
        fs = ipqs.get("fraud_score") or 0
        sev = "info"
        if fs >= 90: sev = "critical"
        elif fs >= 75: sev = "high"
        elif fs >= 50: sev = "medium"
        res.add("ipqs_fraud_score", fs, severity=sev, source="ipqualityscore.com")
        for f in ("is_proxy", "is_vpn", "is_tor", "is_bot", "recent_abuse"):
            if ipqs.get(f):
                res.add(f"ipqs_{f}", True, severity="high", source="ipqualityscore.com")
    elif not os.environ.get("IPQUALITYSCORE_API_KEY"):
        res.add("ipqs", "unavailable", note="set IPQUALITYSCORE_API_KEY for fraud score")

    if depth >= 2:
        ui.info("WHOIS lookup...")
        w = _whois_lookup(ip)
        if w:
            res.data["whois"] = w
            if w.get("org"):
                res.add("whois_org", w["org"], source="whois")

    if depth >= 2:
        ui.info(f"Scanning {len(COMMON_PORTS)} common ports...")
        open_ports = _scan_ports(ip, threads=threads, timeout=min(2.0, timeout / 4))
        res.data["open_ports"] = open_ports
        if open_ports:
            for op in open_ports:
                res.add(f"port_{op['port']}", op["service"], severity="low", source="port_scan")

    if depth >= 2:
        ui.info("DNSBL reputation checks...")
        dnsbl = _dnsbl_check(ip, timeout=min(3.0, timeout / 2))
        res.data["dnsbl"] = dnsbl
        listed = [d for d in dnsbl if d.get("listed")]
        if listed:
            res.add(
                "blacklisted",
                [d["list"] for d in listed],
                severity="high",
                source="dnsbl",
                note=f"listed on {len(listed)} blacklist(s)",
            )

    # External-tool deep-dive links (always added)
    res.data["shodan_url"] = _shodan_link(ip)
    res.data["censys_url"] = _censys_link(ip)
    res.add("shodan", _shodan_link(ip), source="search-hint",
            note="Shodan host page (manual review)",
            profile_url=_shodan_link(ip))
    res.add("censys", _censys_link(ip), source="search-hint",
            note="Censys host page (manual review)",
            profile_url=_censys_link(ip))

    # ---- Summary ----
    abuse_str = "n/a"
    if abuse:
        abuse_str = f"{abuse.get('abuseConfidenceScore', 0)}%"
    ports_count = len(res.data.get("open_ports", []))
    bl_count = sum(1 for d in res.data.get("dnsbl", []) if d.get("listed"))
    gn_str = (
        "noise" if (gn and gn.get("noise")) else
        "riot" if (gn and gn.get("riot")) else
        "clean" if gn else "n/a"
    )
    res.summary = (
        f"{(geo.get('country') if geo else 'unknown')} | "
        f"{isp_str or 'unknown ISP'} | "
        f"ports={ports_count} | dnsbl={bl_count} | "
        f"abuse={abuse_str} | greynoise={gn_str}"
        + (f" | cdn={cdn}" if cdn else "")
    )

    res.finish(success=True)
    return res
