"""IP intelligence module."""

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
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    80: "http",
    110: "pop3",
    111: "rpc",
    135: "msrpc",
    139: "netbios",
    143: "imap",
    443: "https",
    445: "smb",
    993: "imaps",
    995: "pop3s",
    1723: "pptp",
    3306: "mysql",
    3389: "rdp",
    5432: "postgres",
    5900: "vnc",
    6379: "redis",
    8080: "http-proxy",
    8443: "https-alt",
    27017: "mongodb",
}


# DNSBL hosts for reputation check (PTR-style queries)
DNSBL_HOSTS: List[str] = [
    "zen.spamhaus.org",
    "bl.spamcop.net",
    "b.barracudacentral.org",
    "dnsbl.sorbs.net",
    "psbl.surriel.com",
]


def is_valid_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _ipapi_lookup(ip: str, timeout: int) -> Optional[Dict[str, Any]]:
    """Use ip-api.com free endpoint with extended fields."""
    try:
        # bitmask "fields=66846719" enables almost everything; we use named fields for clarity
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


def _abuseipdb_lookup(ip: str, timeout: int) -> Optional[Dict[str, Any]]:
    api_key = os.environ.get("ABUSEIPDB_API_KEY")
    if not api_key:
        return None
    try:
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
        import whois  # python-whois
    except Exception:
        return None
    try:
        w = whois.whois(ip)
        if not w:
            return None
        # Normalize all values to strings/lists
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
    """Reverse octets and query DNSBL hosts. Returns hits."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return []
    if isinstance(addr, ipaddress.IPv6Address):
        # Most public DNSBLs only support IPv4; skip
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


def run(ip: str, timeout: int = 10, threads: int = 20) -> ModuleResult:
    res = ModuleResult(module="ip", target=ip, target_type="ip")
    if not is_valid_ip(ip):
        res.finish(success=False, error="invalid IP address")
        return res

    ui.info(f"Geolocating {ip}...")
    geo = _ipapi_lookup(ip, timeout)
    if geo:
        res.data["geo"] = geo
        loc = ", ".join(filter(None, [geo.get("city"), geo.get("regionName"), geo.get("country")]))
        if loc:
            res.add("location", loc, source="ip-api.com")
        if geo.get("isp"):
            res.add("isp", geo["isp"], source="ip-api.com")
        if geo.get("as"):
            res.add("asn", geo["as"], source="ip-api.com")
        if geo.get("timezone"):
            res.add("timezone", geo["timezone"], source="ip-api.com")
        if geo.get("lat") is not None and geo.get("lon") is not None:
            res.add("coordinates", f"{geo['lat']}, {geo['lon']}", source="ip-api.com")
        # privacy/anonymizer flags
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
    else:
        ui.warn("ip-api lookup returned no data")

    # Independent reverse DNS as fallback
    if "reverse_dns" not in {f.key for f in res.findings}:
        ui.info("Reverse DNS lookup...")
        rdns = _reverse_dns(ip, timeout)
        if rdns:
            res.add("reverse_dns", rdns, source="socket")
            res.data["reverse_dns"] = rdns

    # AbuseIPDB
    abuse = _abuseipdb_lookup(ip, timeout)
    if abuse:
        res.data["abuseipdb"] = abuse
        score = abuse.get("abuseConfidenceScore", 0)
        sev = "info"
        if score >= 75:
            sev = "critical"
        elif score >= 50:
            sev = "high"
        elif score >= 25:
            sev = "medium"
        elif score > 0:
            sev = "low"
        res.add("abuse_score", score, severity=sev, source="abuseipdb.com",
                note=f"{abuse.get('totalReports', 0)} reports")
    else:
        if not os.environ.get("ABUSEIPDB_API_KEY"):
            res.add("abuse_score", "unavailable", note="set ABUSEIPDB_API_KEY for abuse score")

    # WHOIS
    ui.info("WHOIS lookup...")
    w = _whois_lookup(ip)
    if w:
        res.data["whois"] = w
        if w.get("org"):
            res.add("whois_org", w["org"], source="whois")

    # Port scan
    ui.info(f"Scanning {len(COMMON_PORTS)} common ports...")
    open_ports = _scan_ports(ip, threads=threads, timeout=min(2.0, timeout / 4))
    res.data["open_ports"] = open_ports
    if open_ports:
        for op in open_ports:
            res.add(f"port_{op['port']}", op["service"], severity="low", source="port_scan")

    # DNSBL
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

    res.finish(success=True)
    return res
