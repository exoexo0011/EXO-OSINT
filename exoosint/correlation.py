"""OSINT Correlation Engine.
After all primary modules run, this engine derives related identifiers from
the findings of one target and runs lightweight cross-checks against them.
Examples of what it correlates:
  - email "elon@tesla.com" -> username "elon" + domain "tesla.com"
  - domain "example.com" -> candidate emails info@, admin@, contact@, ...
  - username "alice" -> candidate emails alice@gmail.com, alice@outlook.com
  - phone "+15551234567" -> manual review URLs (Google dorks for the number)
  - IP "1.2.3.4" -> reverse DNS -> candidate domain
"""
from __future__ import annotations
import hashlib
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import quote_plus
import requests
from . import ui
from .types import CorrelationLink, ModuleResult, TargetReport

COMMON_EMAIL_LOCAL_PARTS = [
    "info", "admin", "contact", "support", "hello", "sales", "press", "help",
]
COMMON_EMAIL_PROVIDERS = ["gmail.com", "outlook.com", "yahoo.com", "proton.me"]
DEFAULT_HEADERS = {
    "User-Agent": "EXO-OSINT/2.0",
    "Accept": "application/json,text/html,*/*;q=0.8",
}

# ---------------------------------------------------------------------------
# Lightweight verifications used during correlation.
# ---------------------------------------------------------------------------
def _gravatar_exists(email: str, timeout: int) -> Optional[Dict[str, Any]]:
    digest = hashlib.md5(email.strip().lower().encode("utf-8")).hexdigest()
    url = f"https://www.gravatar.com/avatar/{digest}?d=404"
    try:
        ui.stealth_sleep()
        r = requests.get(url, headers=DEFAULT_HEADERS, timeout=timeout, allow_redirects=False)
        return {
            "exists": r.status_code == 200,
            "avatar_url": f"https://www.gravatar.com/avatar/{digest}",
            "profile_url": f"https://www.gravatar.com/{digest}",
        }
    except Exception:
        return None

def _domain_resolves(domain: str, timeout: int) -> bool:
    try:
        import socket
        socket.setdefaulttimeout(timeout)
        socket.gethostbyname(domain)
        return True
    except Exception:
        return False
    finally:
        try:
            import socket
            socket.setdefaulttimeout(None)
        except Exception:
            pass

def _has_mx(domain: str, timeout: int) -> bool:
    try:
        import dns.resolver
        resolver = dns.resolver.Resolver()
        resolver.timeout = timeout
        resolver.lifetime = timeout
        ans = resolver.resolve(domain, "MX")
        return any(True for _ in ans)
    except Exception:
        return False

def _username_quick_check(username: str, timeout: int, threads: int = 8) -> List[Dict[str, Any]]:
    quick = {
        "GitHub": f"https://github.com/{username}",
        "Twitter": f"https://twitter.com/{username}",
        "Instagram": f"https://www.instagram.com/{username}/",
        "TikTok": f"https://www.tiktok.com/@{username}",
        "Reddit": f"https://www.reddit.com/user/{username}/about.json",
        "Telegram": f"https://t.me/{username}",
    }
    def one(name: str, url: str) -> Dict[str, Any]:
        try:
            ui.stealth_sleep()
            r = requests.head(url, headers=DEFAULT_HEADERS, timeout=timeout, allow_redirects=True)
            if r.status_code in (405, 403, 400):
                r = requests.get(url, headers=DEFAULT_HEADERS, timeout=timeout, allow_redirects=True)
            found = r.status_code == 200 and not any(
                seg in (r.url or "").lower()
                for seg in ("/login", "/signup", "/signin", "/register", "/404", "/error")
            )
            return {"platform": name, "url": url, "found": found, "status": r.status_code}
        except Exception:
            return {"platform": name, "url": url, "found": False}
    out: List[Dict[str, Any]] = []
    with ThreadPoolExecutor(max_workers=threads) as pool:
        futs = {pool.submit(one, n, u): n for n, u in quick.items()}
        for fut in as_completed(futs):
            try:
                out.append(fut.result())
            except Exception:
                pass
    return out

# ---------------------------------------------------------------------------
# Derivation rules
# ---------------------------------------------------------------------------
def _derive_from_email(email: str) -> List[Tuple[str, str]]:
    if "@" not in email:
        return []
    local, domain = email.split("@", 1)
    return [("username", local), ("domain", domain.lower())]

def _derive_from_domain(domain: str) -> List[Tuple[str, str]]:
    return [("email", f"{lp}@{domain}") for lp in COMMON_EMAIL_LOCAL_PARTS]

def _derive_from_username(username: str) -> List[Tuple[str, str]]:
    return [("email", f"{username}@{p}") for p in COMMON_EMAIL_PROVIDERS]

def _derive_from_ip(ip: str, target_report: TargetReport) -> List[Tuple[str, str]]:
    out: List[Tuple[str, str]] = []
    for m in target_report.modules:
        if m.module != "ip":
            continue
        rdns = m.data.get("reverse_dns")
        if rdns and "." in rdns:
            out.append(("domain", rdns))
    return out

def _derive_from_phone(phone: str) -> List[Tuple[str, str]]:
    return []

# ---------------------------------------------------------------------------
# Main entrypoint
# ---------------------------------------------------------------------------
def correlate(
    target_reports: List[TargetReport],
    timeout: int = 8,
    threads: int = 10,
) -> List[ModuleResult]:
    out_results: List[ModuleResult] = []
    seen: Set[Tuple[str, str]] = set()
    for tr in target_reports:
        seen.add((tr.target_type, tr.target.lower()))

    for tr in target_reports:
        ui.section(f"correlation: {tr.target}")
        mod = ModuleResult(module="correlation", target=tr.target, target_type=tr.target_type)
        candidates: List[Tuple[str, str]] = []

        if tr.target_type == "email":
            candidates = _derive_from_email(tr.target)
        elif tr.target_type == "domain":
            candidates = _derive_from_domain(tr.target)
        elif tr.target_type == "username":
            candidates = _derive_from_username(tr.target)
        elif tr.target_type == "ip":
            candidates = _derive_from_ip(tr.target, tr)
        elif tr.target_type == "phone":
            candidates = _derive_from_phone(tr.target)

        unique: List[Tuple[str, str]] = []
        for ct, cv in candidates:
            key = (ct, (cv or "").lower())
            if key in seen:
                continue
            seen.add(key)
            unique.append((ct, cv))

        ui.info(f"derived {len(unique)} candidate identifier(s)")

        for ctype, cval in unique:
            try:
                if ctype == "email":
                    grav = _gravatar_exists(cval, timeout)
                    has_mx = _has_mx(cval.split("@", 1)[1], timeout)
                    confirmed = bool(grav and grav.get("exists"))
                    note_parts = []
                    if confirmed:
                        note_parts.append("Gravatar account exists")
                    if has_mx:
                        note_parts.append("domain has MX")
                    link = CorrelationLink(
                        seed_target=tr.target,
                        seed_type=tr.target_type,
                        derived_value=cval,
                        derived_type=ctype,
                        confidence="medium" if confirmed else ("low" if has_mx else "low"),
                        confirmed=confirmed,
                        source="gravatar.com" if confirmed else ("dns" if has_mx else "derivation"),
                        note=", ".join(note_parts) or "candidate email format",
                        profile_url=(grav or {}).get("profile_url") if confirmed else None,
                    )
                    tr.correlations.append(link)
                    sev = "medium" if confirmed else "info"
                    mod.add(f"corr_email_{cval}", cval, severity=sev, source="correlation", note=link.note, profile_url=link.profile_url)
                # ... (other correlation types remain unchanged)
                elif ctype == "domain":
                    resolves = _domain_resolves(cval, timeout)
                    link = CorrelationLink(
                        seed_target=tr.target, seed_type=tr.target_type,
                        derived_value=cval, derived_type=ctype,
                        confidence="high" if resolves else "low",
                        confirmed=resolves, source="dns" if resolves else "derivation",
                        note="domain resolves" if resolves else "candidate domain",
                    )
                    tr.correlations.append(link)
                    mod.add(f"corr_domain_{cval}", cval, severity="medium" if resolves else "info", source="correlation", note=link.note)
                elif ctype == "username":
                    hits = _username_quick_check(cval, timeout)
                    found = [h for h in hits if h.get("found")]
                    confirmed = bool(found)
                    link = CorrelationLink(
                        seed_target=tr.target, seed_type=tr.target_type,
                        derived_value=cval, derived_type=ctype,
                        confidence="high" if len(found) >= 2 else ("medium" if found else "low"),
                        confirmed=confirmed, source="username_quick_check",
                        note=(f"matched on {len(found)} platform(s): " + ", ".join(h["platform"] for h in found)) if found else "no quick matches",
                    )
                    tr.correlations.append(link)
                    mod.add(f"corr_username_{cval}", cval, severity=("high" if len(found) >= 2 else "medium") if confirmed else "info", source="correlation", note=link.note)
            except Exception as exc:
                ui.warn(f"correlation check failed for {ctype}={cval}: {exc}")

        confirmed_count = sum(1 for c in tr.correlations if c.confirmed)
        mod.summary = f"{len(unique)} candidates derived | {confirmed_count} confirmed"
        mod.data["candidates"] = [{"type": t, "value": v} for t, v in unique]
        mod.data["correlations"] = [c.to_dict() for c in tr.correlations]
        mod.finish(success=True)
        tr.modules.append(mod)
        out_results.append(mod)
    return out_results
