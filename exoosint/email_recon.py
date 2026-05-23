"""Email investigation module — multi-source OSINT with graceful degradation.

Sources used (all optional, gracefully degrade if unavailable):
  - DNS MX records                                          (free)
  - SMTP probe with multi-MX fallback + catch-all detect    (free, may be blocked)
  - Disposable email list                                   (free, local)
  - Provider fingerprint                                    (free, local)
  - Gravatar avatar + profile JSON                          (free, no key)
  - LeakCheck public breach search                          (free, no key)
  - Pastebin via psbdmp.ws                                  (free, no key)
  - GitHub user search by email                             (free, rate-limited)
  - GitLab user search by email                             (free, rate-limited)
  - Web mentions via DuckDuckGo HTML                        (free, no key)
  - Google dork URLs                                        (free, link-only)
  - Hunter.io domain search                                 (HUNTER_API_KEY)
  - EmailRep.io reputation                                  (EMAILREP_API_KEY)
  - HaveIBeenPwned breach list                              (HIBP_API_KEY)
"""

from __future__ import annotations

import hashlib
import os
import re
import smtplib
import socket
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import quote_plus

import requests

from . import ui
from .types import ModuleResult


EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$")

DEFAULT_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/120.0 Safari/537.36 EXO-OSINT/2.0"
    ),
    "Accept-Language": "en-US,en;q=0.9",
}


DISPOSABLE_DOMAINS = {
    "10minutemail.com", "guerrillamail.com", "mailinator.com", "tempmail.com",
    "temp-mail.org", "yopmail.com", "throwawaymail.com", "trashmail.com",
    "fakeinbox.com", "getnada.com", "dispostable.com", "maildrop.cc",
    "sharklasers.com", "mailnesia.com", "mintemail.com", "spam4.me",
    "tempr.email", "trbvm.com", "tempmailaddress.com", "moakt.com",
    "mailcatch.com", "33mail.com", "anonbox.net", "burnermail.io",
}


# Known dating / adult / matrimonial breaches.
# Matched (case-insensitive substring) against breach names returned by HIBP
# and LeakCheck so the analyst sees a *real* OSINT signal — sourced from
# public breach data, not from any account-enumeration attempt.
DATING_BREACH_PATTERNS: List[str] = [
    "ashleymadison", "ashley madison", "alm",  # Avid Life Media (parent)
    "adultfriendfinder", "adult friend finder", "friend finder networks", "ffn",
    "meetmindful", "beautifulpeople", "beautiful people",
    "brazzers", "cams.com", "fling", "mate1", "naughtyamerica",
    "okcupid", "plenty of fish", "pof.com", "zoosk",
    "stripshow", "stripchat", "snapcheat",
    "youporn", "penthouse", "wearehairy",
    "muslimmatch", "shaadi", "jeevansathi", "bharatmatrimony",
    "tinder", "bumble", "hinge", "grindr", "feeld",
    "xhamster", "pornhub", "redtube",
]


def _match_dating_breaches(names: List[str]) -> List[str]:
    """Return the subset of `names` that match known dating/adult breach
    patterns. Case-insensitive substring match."""
    matches: List[str] = []
    for n in names:
        if not n:
            continue
        n_lower = str(n).lower()
        for pat in DATING_BREACH_PATTERNS:
            if pat in n_lower:
                matches.append(str(n))
                break
    # de-dupe while preserving order
    seen: set = set()
    out: List[str] = []
    for m in matches:
        if m not in seen:
            seen.add(m)
            out.append(m)
    return out


PROVIDERS = {
    "gmail.com": "Google Gmail",
    "googlemail.com": "Google Gmail",
    "yahoo.com": "Yahoo Mail",
    "ymail.com": "Yahoo Mail",
    "outlook.com": "Microsoft Outlook",
    "hotmail.com": "Microsoft Hotmail",
    "live.com": "Microsoft Live",
    "msn.com": "Microsoft MSN",
    "icloud.com": "Apple iCloud",
    "me.com": "Apple iCloud",
    "mac.com": "Apple iCloud",
    "protonmail.com": "ProtonMail",
    "proton.me": "ProtonMail",
    "tutanota.com": "Tutanota",
    "zoho.com": "Zoho Mail",
    "yandex.com": "Yandex Mail",
    "yandex.ru": "Yandex Mail",
    "aol.com": "AOL Mail",
    "fastmail.com": "FastMail",
    "gmx.com": "GMX Mail",
    "mail.com": "Mail.com",
    "qq.com": "Tencent QQ Mail",
    "163.com": "NetEase 163",
    "126.com": "NetEase 126",
}


# ---------------------------------------------------------------------------
# Validation & local checks
# ---------------------------------------------------------------------------

def is_valid_email(value: str) -> bool:
    return bool(EMAIL_RE.match(value or ""))


def _md5(value: str) -> str:
    return hashlib.md5(value.strip().lower().encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# DNS / MX
# ---------------------------------------------------------------------------

def _mx_records(domain: str, timeout: int) -> List[Tuple[int, str]]:
    """Return list of (priority, host) sorted by priority ascending."""
    try:
        import dns.resolver
        resolver = dns.resolver.Resolver()
        resolver.timeout = timeout
        resolver.lifetime = timeout
        answers = resolver.resolve(domain, "MX")
        out = [(int(r.preference), str(r.exchange).rstrip(".")) for r in answers]
        out.sort(key=lambda x: x[0])
        return out
    except Exception as exc:
        ui.warn(f"mx lookup failed for {domain}: {exc}")
        return []


# ---------------------------------------------------------------------------
# SMTP — multi-MX fallback + catch-all detection
# ---------------------------------------------------------------------------

def _smtp_probe_one(mx: str, port: int, sender: str, recipients: List[str], timeout: int) -> Dict[str, Any]:
    result: Dict[str, Any] = {
        "mx": mx, "port": port, "connected": False, "banner": None,
        "responses": {}, "error": None,
    }
    srv: Optional[smtplib.SMTP] = None
    try:
        socket.setdefaulttimeout(timeout)
        srv = smtplib.SMTP(timeout=timeout)
        code, banner = srv.connect(mx, port)
        result["connected"] = True
        result["banner"] = (banner.decode("utf-8", "ignore") if isinstance(banner, bytes) else str(banner))[:200]
        try:
            srv.ehlo("exo-osint.local")
        except Exception:
            srv.helo("exo-osint.local")
        try:
            srv.mail(sender)
        except Exception as exc:
            result["error"] = f"MAIL FROM rejected: {exc}"
            return result
        for r in recipients:
            try:
                code, msg = srv.rcpt(r)
                msg_text = msg.decode("utf-8", "ignore") if isinstance(msg, bytes) else str(msg)
                result["responses"][r] = {
                    "code": int(code),
                    "message": msg_text[:200],
                    "deliverable": int(code) in (250, 251),
                }
            except Exception as exc:
                result["responses"][r] = {"code": None, "message": str(exc)[:200], "deliverable": None}
    except (socket.timeout, TimeoutError):
        result["error"] = "timeout"
    except ConnectionRefusedError:
        result["error"] = "connection_refused"
    except OSError as exc:
        result["error"] = f"network_error: {exc}"
    except smtplib.SMTPException as exc:
        result["error"] = f"smtp_error: {exc}"
    except Exception as exc:
        result["error"] = f"unexpected: {exc}"
    finally:
        if srv is not None:
            try:
                srv.quit()
            except Exception:
                try:
                    srv.close()
                except Exception:
                    pass
        socket.setdefaulttimeout(None)
    return result


def _smtp_verify(email: str, mx_records: List[Tuple[int, str]], timeout: int) -> Dict[str, Any]:
    if not mx_records:
        return {"deliverable": None, "error": "no MX records"}
    domain = email.split("@", 1)[1]
    fake_local = "exo-osint-noreply-" + hashlib.md5(email.encode()).hexdigest()[:10]
    fake_email = f"{fake_local}@{domain}"
    sender = "noreply@exo-osint.local"
    last_error: Optional[str] = None
    attempts: List[Dict[str, Any]] = []
    for prio, mx in mx_records[:3]:
        probe = _smtp_probe_one(mx, 25, sender, [email, fake_email], timeout=timeout)
        attempts.append(probe)
        if probe.get("error"):
            last_error = probe["error"]
            continue
        responses = probe.get("responses", {})
        real_resp = responses.get(email, {})
        fake_resp = responses.get(fake_email, {})
        real_d = real_resp.get("deliverable")
        fake_d = fake_resp.get("deliverable")
        if real_d is True and fake_d is True:
            return {
                "deliverable": None, "catch_all": True,
                "real_response": real_resp, "fake_response": fake_resp,
                "mx_used": mx, "mx_priority": prio, "attempts": attempts,
                "note": "server accepts every recipient (catch-all) — verification inconclusive",
            }
        if real_d is True:
            return {
                "deliverable": True, "catch_all": False,
                "real_response": real_resp, "fake_response": fake_resp,
                "mx_used": mx, "mx_priority": prio, "attempts": attempts,
            }
        if real_d is False:
            return {
                "deliverable": False, "catch_all": False,
                "real_response": real_resp, "fake_response": fake_resp,
                "mx_used": mx, "mx_priority": prio, "attempts": attempts,
            }
    return {
        "deliverable": None,
        "error": last_error or "all MX servers gave ambiguous responses",
        "attempts": attempts,
        "note": "outbound port 25 may be blocked from this network",
    }


# ---------------------------------------------------------------------------
# Gravatar
# ---------------------------------------------------------------------------

def _gravatar(email: str, timeout: int) -> Optional[Dict[str, Any]]:
    digest = _md5(email)
    avatar_url = f"https://www.gravatar.com/avatar/{digest}"
    profile_json = f"https://www.gravatar.com/{digest}.json"
    out: Dict[str, Any] = {"avatar_hash": digest, "exists": False}
    try:
        ui.stealth_sleep()
        r = requests.get(f"{avatar_url}?d=404", headers=DEFAULT_HEADERS,
                         timeout=timeout, allow_redirects=False)
        out["exists"] = r.status_code == 200
        out["avatar_url"] = avatar_url if out["exists"] else None
    except Exception as exc:
        ui.warn(f"gravatar avatar check failed: {exc}")
        return None
    if out["exists"]:
        try:
            ui.stealth_sleep()
            r = requests.get(profile_json, headers=DEFAULT_HEADERS, timeout=timeout)
            if r.status_code == 200 and r.text.strip().startswith("{"):
                data = r.json() or {}
                entries = data.get("entry", [])
                if entries:
                    e = entries[0]
                    out["profile"] = {
                        "display_name": e.get("displayName"),
                        "preferred_username": e.get("preferredUsername"),
                        "name": e.get("name"),
                        "about_me": e.get("aboutMe"),
                        "current_location": e.get("currentLocation"),
                        "profile_url": e.get("profileUrl"),
                        "accounts": e.get("accounts", []),
                        "urls": e.get("urls", []),
                    }
        except Exception:
            pass
    return out


# ---------------------------------------------------------------------------
# LeakCheck public — free, no key
# ---------------------------------------------------------------------------

def _leakcheck_public(email: str, timeout: int) -> Optional[Dict[str, Any]]:
    try:
        ui.stealth_sleep()
        r = requests.get(
            "https://leakcheck.io/api/public",
            params={"check": email}, headers=DEFAULT_HEADERS, timeout=timeout,
        )
        if r.status_code != 200:
            return None
        data = r.json() or {}
        if not data.get("success"):
            return {"found": 0, "sources": [], "fields": []}
        return {
            "found": int(data.get("found", 0)),
            "fields": data.get("fields", []) or [],
            "sources": data.get("sources", []) or [],
        }
    except Exception as exc:
        ui.warn(f"leakcheck failed: {exc}")
        return None


# ---------------------------------------------------------------------------
# Pastebin via psbdmp.ws
# ---------------------------------------------------------------------------

def _psbdmp_pastebin(email: str, timeout: int) -> Optional[Dict[str, Any]]:
    try:
        ui.stealth_sleep()
        r = requests.get(
            f"https://psbdmp.ws/api/search/{quote_plus(email)}",
            headers=DEFAULT_HEADERS, timeout=timeout,
        )
        if r.status_code != 200:
            return None
        text = r.text.strip()
        if not text:
            return {"count": 0, "pastes": []}
        try:
            data = r.json()
        except ValueError:
            return {"count": 0, "pastes": []}
        if isinstance(data, dict):
            count = int(data.get("count", 0))
            pastes = data.get("data", []) or []
        elif isinstance(data, list):
            count = len(data); pastes = data
        else:
            return {"count": 0, "pastes": []}
        out: List[Dict[str, Any]] = []
        for p in pastes[:25]:
            if isinstance(p, dict) and p.get("id"):
                out.append({
                    "id": p.get("id"),
                    "url": f"https://pastebin.com/{p.get('id')}",
                    "date": p.get("date"),
                })
        return {"count": count, "pastes": out}
    except Exception as exc:
        ui.warn(f"psbdmp pastebin failed: {exc}")
        return None


# ---------------------------------------------------------------------------
# GitHub & GitLab email search
# ---------------------------------------------------------------------------

def _github_email_search(email: str, timeout: int) -> Optional[Dict[str, Any]]:
    try:
        ui.stealth_sleep()
        r = requests.get(
            "https://api.github.com/search/users",
            params={"q": f"{email} in:email"},
            headers={**DEFAULT_HEADERS, "Accept": "application/vnd.github+json"},
            timeout=timeout,
        )
        if r.status_code == 403:
            return {"rate_limited": True, "users": []}
        if r.status_code != 200:
            return None
        data = r.json() or {}
        users: List[Dict[str, Any]] = []
        for u in (data.get("items") or [])[:10]:
            users.append({
                "login": u.get("login"),
                "url": u.get("html_url"),
                "avatar": u.get("avatar_url"),
            })
        return {"total": int(data.get("total_count", 0)), "users": users}
    except Exception as exc:
        ui.warn(f"github email search failed: {exc}")
        return None


def _gitlab_email_search(email: str, timeout: int) -> Optional[Dict[str, Any]]:
    """GitLab.com supports public username search by exact email (limited)."""
    try:
        ui.stealth_sleep()
        r = requests.get(
            "https://gitlab.com/api/v4/users",
            params={"search": email},
            headers=DEFAULT_HEADERS, timeout=timeout,
        )
        if r.status_code != 200:
            return None
        data = r.json() or []
        users: List[Dict[str, Any]] = []
        for u in (data or [])[:10]:
            if isinstance(u, dict) and u.get("username"):
                users.append({
                    "username": u.get("username"),
                    "name": u.get("name"),
                    "url": u.get("web_url"),
                    "avatar": u.get("avatar_url"),
                })
        return {"total": len(users), "users": users}
    except Exception as exc:
        ui.warn(f"gitlab email search failed: {exc}")
        return None


# ---------------------------------------------------------------------------
# Web mentions via DuckDuckGo HTML scrape
# ---------------------------------------------------------------------------

def _web_mentions(email: str, timeout: int, max_results: int = 10) -> Optional[Dict[str, Any]]:
    try:
        from bs4 import BeautifulSoup  # type: ignore
    except Exception:
        return None
    query = f'"{email}"'
    endpoints = [
        ("POST", "https://html.duckduckgo.com/html/", {"q": query, "kl": "us-en"}),
        ("GET", "https://html.duckduckgo.com/html/", {"q": query, "kl": "us-en"}),
        ("GET", "https://lite.duckduckgo.com/lite/", {"q": query}),
    ]
    headers = {
        **DEFAULT_HEADERS,
        "Referer": "https://html.duckduckgo.com/",
        "Origin": "https://html.duckduckgo.com",
    }
    last_status: Optional[int] = None
    for method, url, params in endpoints:
        try:
            ui.stealth_sleep()
            if method == "POST":
                r = requests.post(url, data=params, headers=headers, timeout=timeout)
            else:
                r = requests.get(url, params=params, headers=headers, timeout=timeout)
            last_status = r.status_code
        except Exception:
            continue
        if r.status_code != 200:
            continue
        soup = BeautifulSoup(r.text, "html.parser")
        results: List[Dict[str, str]] = []
        seen = set()
        for a in soup.select("a.result__a"):
            href = a.get("href", "")
            title = a.get_text(strip=True)
            if not href or not title:
                continue
            real = _ddg_unwrap(href)
            if not real or real in seen:
                continue
            seen.add(real)
            results.append({"title": title[:200], "url": real})
            if len(results) >= max_results:
                break
        if not results:
            for a in soup.select("a.result-link, td.result-snippet a, a[rel='noopener']"):
                href = a.get("href", "")
                title = a.get_text(strip=True)
                if not href or not title or href.startswith("/"):
                    continue
                real = _ddg_unwrap(href) or href
                if not real.startswith("http") or real in seen:
                    continue
                seen.add(real)
                results.append({"title": title[:200], "url": real})
                if len(results) >= max_results:
                    break
        if results:
            return {
                "query": query, "engine": "duckduckgo", "endpoint": url,
                "count": len(results), "results": results,
            }
    return {
        "query": query, "engine": "duckduckgo", "count": 0, "results": [],
        "blocked": last_status == 202, "last_status": last_status,
    }


def _ddg_unwrap(href: str) -> Optional[str]:
    if href.startswith("//duckduckgo.com/l/"):
        href = "https:" + href
    if "duckduckgo.com/l/" in href:
        from urllib.parse import urlparse, parse_qs, unquote
        q = parse_qs(urlparse(href).query)
        if "uddg" in q:
            return unquote(q["uddg"][0])
        return None
    if href.startswith("http"):
        return href
    return None


# ---------------------------------------------------------------------------
# Hunter.io / EmailRep / HIBP
# ---------------------------------------------------------------------------

def _hunter_domain(domain: str, timeout: int) -> Optional[Dict[str, Any]]:
    api_key = os.environ.get("HUNTER_API_KEY")
    if not api_key:
        return None
    try:
        ui.stealth_sleep()
        r = requests.get(
            "https://api.hunter.io/v2/domain-search",
            params={"domain": domain, "api_key": api_key, "limit": 10},
            headers=DEFAULT_HEADERS, timeout=timeout,
        )
        if r.status_code != 200:
            return None
        data = (r.json() or {}).get("data") or {}
        emails = data.get("emails", []) or []
        return {
            "organization": data.get("organization"),
            "country": data.get("country"),
            "pattern": data.get("pattern"),
            "technologies": data.get("technologies", []),
            "linkedin": data.get("linkedin"),
            "twitter": data.get("twitter"),
            "facebook": data.get("facebook"),
            "email_count": len(emails),
            "emails": [
                {
                    "value": e.get("value"),
                    "first_name": e.get("first_name"),
                    "last_name": e.get("last_name"),
                    "position": e.get("position"),
                    "department": e.get("department"),
                    "confidence": e.get("confidence"),
                    "sources_count": len(e.get("sources", [])),
                }
                for e in emails[:10]
            ],
        }
    except Exception as exc:
        ui.warn(f"hunter.io failed: {exc}")
        return None


def _emailrep(email: str, timeout: int) -> Optional[Dict[str, Any]]:
    headers = {**DEFAULT_HEADERS, "Accept": "application/json"}
    api_key = os.environ.get("EMAILREP_API_KEY")
    if api_key:
        headers["Key"] = api_key
    try:
        ui.stealth_sleep()
        r = requests.get(f"https://emailrep.io/{quote_plus(email)}",
                         headers=headers, timeout=timeout)
        if r.status_code in (401, 403):
            return {"unavailable": True, "reason": "API key required"}
        if r.status_code == 429:
            return {"unavailable": True, "reason": "rate limited"}
        if r.status_code != 200:
            return None
        data = r.json() or {}
        if data.get("status") == "fail":
            return {"unavailable": True, "reason": data.get("reason")}
        details = data.get("details") or {}
        return {
            "email": data.get("email"),
            "reputation": data.get("reputation"),
            "suspicious": data.get("suspicious"),
            "references": data.get("references"),
            "blacklisted": details.get("blacklisted"),
            "malicious_activity": details.get("malicious_activity"),
            "credentials_leaked": details.get("credentials_leaked"),
            "data_breach": details.get("data_breach"),
            "first_seen": details.get("first_seen"),
            "last_seen": details.get("last_seen"),
            "domain_age_days": details.get("domain_age"),
            "deliverable": details.get("deliverable"),
            "valid_mx": details.get("valid_mx"),
            "spam": details.get("spam"),
            "free_provider": details.get("free_provider"),
            "disposable": details.get("disposable"),
            "profiles": details.get("profiles", []) or [],
        }
    except Exception as exc:
        ui.warn(f"emailrep failed: {exc}")
        return None


def _hibp_breaches(email: str, timeout: int) -> Optional[List[Dict[str, Any]]]:
    api_key = os.environ.get("HIBP_API_KEY")
    if not api_key:
        return None
    try:
        ui.stealth_sleep()
        r = requests.get(
            f"https://haveibeenpwned.com/api/v3/breachedaccount/{quote_plus(email)}",
            params={"truncateResponse": "false"},
            headers={"hibp-api-key": api_key, "User-Agent": "EXO-OSINT/2.0"},
            timeout=timeout,
        )
        if r.status_code == 404:
            return []
        if r.status_code == 200:
            return r.json()
    except Exception as exc:
        ui.warn(f"hibp lookup failed: {exc}")
    return None


# ---------------------------------------------------------------------------
# Search URL hints (always free)
# ---------------------------------------------------------------------------

def _search_hints(email: str) -> Dict[str, str]:
    q = quote_plus(f'"{email}"')
    qbare = quote_plus(email)
    return {
        "google": f"https://www.google.com/search?q={q}",
        "google_linkedin": f"https://www.google.com/search?q={q}+site%3Alinkedin.com",
        "google_github": f"https://www.google.com/search?q={q}+site%3Agithub.com",
        "google_filetype_pdf": f"https://www.google.com/search?q={q}+filetype%3Apdf",
        "google_pastebin": f"https://www.google.com/search?q={q}+site%3Apastebin.com",
        "google_facebook": f"https://www.google.com/search?q={q}+site%3Afacebook.com",
        "google_twitter": f"https://www.google.com/search?q={q}+(site%3Atwitter.com+OR+site%3Ax.com)",
        "bing": f"https://www.bing.com/search?q={q}",
        "duckduckgo": f"https://duckduckgo.com/?q={q}",
        "github_search": f"https://github.com/search?q={qbare}&type=commits",
        "gitlab_search": f"https://gitlab.com/search?search={qbare}",
    }


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------

def run(
    email: str,
    timeout: int = 10,
    run_domain_recon: bool = True,
    threads: int = 20,
    depth: int = 2,
) -> ModuleResult:
    res = ModuleResult(module="email", target=email, target_type="email")

    if not is_valid_email(email):
        res.add("valid_format", False, severity="medium", source="regex")
        res.finish(success=False, error="invalid email format")
        return res

    res.add("valid_format", True, source="regex")
    local, domain = email.split("@", 1)
    domain = domain.lower()
    res.data["local_part"] = local
    res.data["domain"] = domain

    provider = PROVIDERS.get(domain)
    res.add("provider", provider or "Custom / Self-hosted", source="signature")

    disposable = domain in DISPOSABLE_DOMAINS
    if disposable:
        res.add("disposable", True, severity="high", source="static_list",
                note="known disposable email provider")
    else:
        res.add("disposable", False, source="static_list")

    ui.info(f"Checking MX records for {domain}...")
    mx = _mx_records(domain, timeout)
    if mx:
        mx_strings = [f"{prio} {host}" for prio, host in mx if host]
        mx_active = [(p, h) for p, h in mx if h and h != "."]
        res.data["mx_records"] = mx_strings
        if mx_strings:
            res.add("mx_records", mx_strings, source="dns")
        if mx_active:
            res.add("can_receive_mail", True, source="dns")
        else:
            res.add("can_receive_mail", False, severity="medium", source="dns",
                    note="domain has null MX (RFC 7505) — does not accept mail")
            mx = []
    else:
        res.add("can_receive_mail", False, severity="medium", source="dns",
                note="domain has no MX records")

    if mx and depth >= 2:
        ui.info("SMTP probe (multi-MX fallback)...")
        smtp_result = _smtp_verify(email, mx, timeout=min(timeout, 8))
        res.data["smtp"] = smtp_result
        if smtp_result.get("deliverable") is True:
            res.add("smtp_deliverable", True, source="smtp",
                    note=f"server {smtp_result.get('mx_used')} accepted RCPT")
        elif smtp_result.get("deliverable") is False:
            res.add("smtp_deliverable", False, severity="low", source="smtp",
                    note=f"server {smtp_result.get('mx_used')} rejected RCPT")
        elif smtp_result.get("catch_all"):
            res.add("smtp_deliverable", "catch_all", severity="info", source="smtp",
                    note="server is a catch-all — verification inconclusive")
        else:
            res.add("smtp_deliverable", "unavailable", source="smtp",
                    note=smtp_result.get("error") or smtp_result.get("note") or "ambiguous")

    ui.info("Gravatar lookup...")
    grav = _gravatar(email, timeout)
    if grav:
        res.data["gravatar"] = grav
        if grav.get("exists"):
            res.add("gravatar", True, severity="info", source="gravatar.com",
                    note=grav.get("avatar_url") or "",
                    profile_url=grav.get("profile", {}).get("profile_url") if grav.get("profile") else None,
                    avatar_url=grav.get("avatar_url"))
            prof = grav.get("profile") or {}
            for k in ("display_name", "preferred_username", "current_location"):
                if prof.get(k):
                    res.add(f"gravatar_{k}", prof[k], source="gravatar.com")
            if prof.get("accounts"):
                accts = [
                    {"shortname": a.get("shortname"), "url": a.get("url")}
                    for a in prof["accounts"] if isinstance(a, dict)
                ]
                if accts:
                    res.add("gravatar_linked_accounts", accts, severity="medium",
                            source="gravatar.com",
                            note=f"{len(accts)} linked social profile(s)")

    ui.info("LeakCheck breach search...")
    lc = _leakcheck_public(email, timeout)
    dating_breach_hits: List[str] = []
    if lc is not None:
        res.data["leakcheck"] = lc
        if lc.get("found", 0) > 0:
            count = lc["found"]
            sev = "critical" if count >= 50 else ("high" if count >= 5 else "medium")
            sources = [s.get("name", "?") for s in (lc.get("sources") or [])[:10] if isinstance(s, dict)]
            res.add("leakcheck_breaches", count, severity=sev, source="leakcheck.io",
                    note=", ".join(sources) if sources else "")
            if lc.get("fields"):
                res.add("leaked_fields", lc["fields"], severity="high", source="leakcheck.io")
            # Dating-specific breach match (real OSINT signal — public breach data)
            all_source_names = [s.get("name", "") for s in (lc.get("sources") or []) if isinstance(s, dict)]
            dating_hits = _match_dating_breaches(all_source_names)
            if dating_hits:
                dating_breach_hits.extend(dating_hits)
                res.add("dating_breach_match_leakcheck", dating_hits,
                        severity="high", source="leakcheck.io",
                        note=f"email appears in {len(dating_hits)} known dating/adult breach corpus(es)")
        else:
            res.add("leakcheck_breaches", 0, source="leakcheck.io")

    ui.info("Pastebin search...")
    psb = _psbdmp_pastebin(email, timeout)
    if psb is not None:
        res.data["pastebin"] = psb
        if psb.get("count", 0) > 0:
            sev = "high" if psb["count"] >= 5 else "medium"
            res.add("pastebin_appearances", psb["count"], severity=sev,
                    source="psbdmp.ws", note=f"appears in {psb['count']} paste(s)")
            for p in (psb.get("pastes") or [])[:5]:
                res.add(f"paste_{p.get('id')}", p.get("url"), severity="medium",
                        source="psbdmp.ws", note=p.get("date") or "",
                        profile_url=p.get("url"))
        else:
            res.add("pastebin_appearances", 0, source="psbdmp.ws")

    ui.info("GitHub email search...")
    gh = _github_email_search(email, timeout)
    if gh is not None:
        res.data["github"] = gh
        if gh.get("rate_limited"):
            res.add("github_search", "rate_limited", source="api.github.com",
                    note="unauthenticated rate limit hit")
        elif gh.get("total", 0) > 0:
            res.add("github_users_found", gh["total"], severity="medium",
                    source="api.github.com",
                    note=f"{gh['total']} user(s) match this email")
            for u in (gh.get("users") or [])[:5]:
                res.add(f"github_user_{u.get('login')}", u.get("url"),
                        severity="medium", source="api.github.com",
                        profile_url=u.get("url"), avatar_url=u.get("avatar"))
        else:
            res.add("github_users_found", 0, source="api.github.com")

    ui.info("GitLab email search...")
    gl = _gitlab_email_search(email, timeout)
    if gl is not None:
        res.data["gitlab"] = gl
        if gl.get("total", 0) > 0:
            res.add("gitlab_users_found", gl["total"], severity="medium",
                    source="gitlab.com",
                    note=f"{gl['total']} user(s) match this email")
            for u in (gl.get("users") or [])[:5]:
                res.add(f"gitlab_user_{u.get('username')}", u.get("url"),
                        severity="medium", source="gitlab.com",
                        profile_url=u.get("url"), avatar_url=u.get("avatar"))

    if depth >= 2:
        ui.info("Web mentions (DuckDuckGo)...")
        web = _web_mentions(email, timeout)
        if web is not None:
            res.data["web_mentions"] = web
            if web.get("count", 0) > 0:
                sev = "medium" if web["count"] >= 3 else "low"
                res.add("web_mentions_count", web["count"], severity=sev,
                        source="duckduckgo.com",
                        note=f"{web['count']} public web mention(s) found")
                for m in (web.get("results") or [])[:5]:
                    res.add(f"web_mention", m.get("url"), severity="info",
                            source="duckduckgo.com", note=m.get("title", "")[:120],
                            profile_url=m.get("url"))
            elif web.get("blocked"):
                res.add("web_mentions_count", "blocked", source="duckduckgo.com",
                        note="search engine challenged the request — use search_urls below")
            else:
                res.add("web_mentions_count", 0, source="duckduckgo.com")

    ui.info("Hunter.io domain search...")
    hunter = _hunter_domain(domain, timeout)
    if hunter is None:
        if not os.environ.get("HUNTER_API_KEY"):
            res.add("hunter_io", "unavailable", note="set HUNTER_API_KEY for domain intel")
    else:
        res.data["hunter_io"] = hunter
        if hunter.get("organization"):
            res.add("hunter_organization", hunter["organization"], source="hunter.io")
        if hunter.get("pattern"):
            res.add("hunter_email_pattern", hunter["pattern"], source="hunter.io",
                    note="common email format used by this organization")
        if hunter.get("email_count", 0) > 0:
            res.add("hunter_emails_known", hunter["email_count"], severity="low",
                    source="hunter.io", note=f"{hunter['email_count']} email(s) on hunter.io")
        for net in ("linkedin", "twitter", "facebook"):
            if hunter.get(net):
                res.add(f"hunter_{net}", hunter[net], source="hunter.io",
                        profile_url=hunter[net])

    ui.info("EmailRep reputation...")
    rep = _emailrep(email, timeout)
    if rep is None:
        if not os.environ.get("EMAILREP_API_KEY"):
            res.add("emailrep", "unavailable", note="set EMAILREP_API_KEY for reputation data")
    elif rep.get("unavailable"):
        res.add("emailrep", "unavailable", note=rep.get("reason", ""))
    else:
        res.data["emailrep"] = rep
        if rep.get("suspicious"):
            res.add("emailrep_suspicious", True, severity="high", source="emailrep.io")
        if rep.get("blacklisted"):
            res.add("emailrep_blacklisted", True, severity="high", source="emailrep.io")
        if rep.get("malicious_activity"):
            res.add("emailrep_malicious", True, severity="critical", source="emailrep.io")
        if rep.get("credentials_leaked"):
            res.add("emailrep_credentials_leaked", True, severity="high", source="emailrep.io")
        if rep.get("data_breach"):
            res.add("emailrep_data_breach", True, severity="high", source="emailrep.io")
        if rep.get("reputation"):
            res.add("emailrep_reputation", rep["reputation"], source="emailrep.io")
        if rep.get("references") is not None:
            res.add("emailrep_references", rep["references"], source="emailrep.io",
                    note="number of public references seen")
        profiles = rep.get("profiles") or []
        if profiles:
            res.add("emailrep_profiles", profiles, severity="medium", source="emailrep.io",
                    note=f"{len(profiles)} linked profile(s)")

    breaches = _hibp_breaches(email, timeout)
    if breaches is None:
        if not os.environ.get("HIBP_API_KEY"):
            res.add("hibp_breaches", "unavailable", note="set HIBP_API_KEY for breach data")
    else:
        res.data["hibp_breaches"] = breaches
        if breaches:
            sev = "critical" if len(breaches) >= 5 else "high"
            res.add("hibp_breaches_found", len(breaches), severity=sev,
                    source="haveibeenpwned",
                    note=", ".join(b.get("Name", "?") for b in breaches[:5]))
            # Dating-specific breach match
            hibp_names = [b.get("Name", "") for b in breaches if isinstance(b, dict)]
            hibp_dating = _match_dating_breaches(hibp_names)
            if hibp_dating:
                dating_breach_hits.extend(hibp_dating)
                res.add("dating_breach_match_hibp", hibp_dating,
                        severity="high", source="haveibeenpwned",
                        note=f"email appears in {len(hibp_dating)} known dating/adult breach(es)")
        else:
            res.add("hibp_breaches_found", 0, source="haveibeenpwned")

    # Aggregate dating-breach signal
    if dating_breach_hits:
        # de-dupe
        unique_hits = list(dict.fromkeys(dating_breach_hits))
        res.data["dating_breach_hits"] = unique_hits
        res.add("dating_breach_total", len(unique_hits),
                severity="high", source="breach-correlation",
                note="; ".join(unique_hits[:8]))

    # Search URL hints (always)
    hints = _search_hints(email)
    res.data["search_urls"] = hints
    for label, url in hints.items():
        res.add(f"dork_{label}", url, severity="info", source="search-hint",
                note="manual review URL", profile_url=url)

    # Optional follow-up domain recon
    if run_domain_recon and depth >= 2:
        try:
            from . import domain as domain_mod
            ui.info(f"Running domain recon on {domain}...")
            dom_res = domain_mod.run(domain, timeout=timeout, threads=threads, depth=depth)
            res.data["domain_recon"] = dom_res.to_dict()
            for f in dom_res.findings:
                if f.severity in ("high", "critical"):
                    res.add(f"domain.{f.key}", f.value, severity=f.severity,
                            source=f.source, note=f.note)
        except Exception as exc:
            ui.warn(f"domain recon failed: {exc}")

    # ---- Summary ----
    fraud = "n/a"
    if rep and not rep.get("unavailable") and rep is not None:
        fraud = f"rep={rep.get('reputation', '?')}, suspicious={rep.get('suspicious')}"
    breach_count = (lc or {}).get("found", 0) if lc else 0
    pb_count = (psb or {}).get("count", 0) if psb else 0
    gh_count = (gh or {}).get("total", 0) if gh else 0
    res.summary = (
        f"provider={provider or 'custom'} | mx={'yes' if mx else 'no'} | "
        f"breaches={breach_count} | pastes={pb_count} | "
        f"gh={gh_count} | reputation={fraud}"
    )

    res.finish(success=True)
    return res
