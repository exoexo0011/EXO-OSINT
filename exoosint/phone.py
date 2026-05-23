"""Phone number module — parsing, dork URLs, paste check, social hints, summary.

Realistic OSINT note:
  Several requested sources (Truecaller, Justdial, Sulekha, IndiaMART, Google
  dorks, Facebook/Instagram phone search) are heavily protected against
  automation. Where reliable scraping is impossible, EXO-OSINT generates
  ready-to-use search URLs ("dork links") so an investigator can review them
  manually with one click. This is the same convention used by professional
  OSINT toolchains.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional
from urllib.parse import quote_plus

import requests

from . import ui
from .types import ModuleResult


DEFAULT_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/120.0 Safari/537.36 EXO-OSINT/2.0"
    ),
    "Accept-Language": "en-US,en;q=0.9",
}


def is_phone_like(value: str) -> bool:
    s = (value or "").strip()
    if not s:
        return False
    if s.startswith("+"):
        return any(c.isdigit() for c in s[1:])
    digits = sum(1 for c in s if c.isdigit())
    return digits >= 7


def _digits_only(phone: str) -> str:
    return re.sub(r"\D", "", phone or "")


# ---------------------------------------------------------------------------
# Dork URL generators — manual review URLs for sources that block scraping
# ---------------------------------------------------------------------------

def _google_dorks(phone_variants: List[str]) -> Dict[str, str]:
    """Build Google search URLs for a phone number."""
    primary = phone_variants[0]
    p = quote_plus(primary)
    p_alts = " OR ".join(f'"{v}"' for v in phone_variants[:5])
    p_alts_q = quote_plus(p_alts)
    return {
        "google_general": f"https://www.google.com/search?q={p}",
        "google_quoted_alts": f"https://www.google.com/search?q={p_alts_q}",
        "google_olx_in": f"https://www.google.com/search?q={p}+site%3Aolx.in",
        "google_justdial": f"https://www.google.com/search?q={p}+site%3Ajustdial.com",
        "google_quikr": f"https://www.google.com/search?q={p}+site%3Aquikr.com",
        "google_indiamart": f"https://www.google.com/search?q={p}+site%3Aindiamart.com",
        "google_sulekha": f"https://www.google.com/search?q={p}+site%3Asulekha.com",
        "google_filetype_pdf": f"https://www.google.com/search?q={p}+filetype%3Apdf",
        "google_inurl_contact": f"https://www.google.com/search?q={p}+inurl%3Acontact",
        "google_facebook": f"https://www.google.com/search?q={p}+site%3Afacebook.com",
        "google_instagram": f"https://www.google.com/search?q={p}+site%3Ainstagram.com",
        "google_linkedin": f"https://www.google.com/search?q={p}+site%3Alinkedin.com",
        "google_twitter": f"https://www.google.com/search?q={p}+(site%3Atwitter.com+OR+site%3Ax.com)",
        "google_telegram": f"https://www.google.com/search?q={p}+site%3At.me",
    }


def _platform_links(e164: str, national: str, digits: str) -> Dict[str, str]:
    """Direct platform/lookup pages. The investigator opens these manually."""
    e164_no_plus = e164.lstrip("+")
    return {
        "wa.me": f"https://wa.me/{e164_no_plus}",
        "truecaller": f"https://www.truecaller.com/search/{(e164_no_plus[:2] or 'in').lower()}/{e164_no_plus}",
        "shouldianswer": f"https://www.shouldianswer.com/phone-number/{digits}",
        "sync.me": f"https://sync.me/search/?number={quote_plus(e164)}",
        "spy_dialer": f"https://www.spydialer.com/default.aspx?searchphone={quote_plus(digits)}",
        "olx_in": f"https://www.olx.in/items/q-{quote_plus(digits)}",
        "quikr": f"https://www.quikr.com/search?query={quote_plus(digits)}",
        "indiamart": f"https://dir.indiamart.com/search.mp?ss={quote_plus(digits)}",
        "justdial": f"https://www.justdial.com/{quote_plus(digits)}",
        "facebook_search": f"https://www.facebook.com/search/top/?q={quote_plus(e164)}",
        "instagram_search": f"https://www.google.com/search?q=site%3Ainstagram.com+{quote_plus(e164)}",
        "telegram_search": f"https://www.google.com/search?q=site%3At.me+{quote_plus(e164)}",
        "skype_directory": f"https://www.skype.com/en/search-skype/?q={quote_plus(e164)}",
        "viber_lookup": f"viber://contact?number={e164_no_plus}",
    }


# ---------------------------------------------------------------------------
# WhatsApp wa.me — passive presence hint
# ---------------------------------------------------------------------------

def _whatsapp_check(e164_no_plus: str, timeout: int) -> Optional[Dict[str, Any]]:
    """Probe wa.me. Note: wa.me always returns 200 for syntactically-valid
    international numbers regardless of registration. We capture the redirect
    final URL — if it ends up on `/send` with the same number it's at least a
    plausibly-formatted WhatsApp identifier. This is intentionally a hint,
    not a confirmation."""
    url = f"https://wa.me/{e164_no_plus}"
    try:
        ui.stealth_sleep()
        r = requests.get(
            url, headers=DEFAULT_HEADERS, timeout=timeout, allow_redirects=True
        )
        return {
            "url": url,
            "status_code": r.status_code,
            "final_url": r.url,
            "reachable": r.status_code == 200,
        }
    except Exception as exc:
        return {"url": url, "error": str(exc)[:120]}


# ---------------------------------------------------------------------------
# Truecaller public page — usually challenged, capture status only
# ---------------------------------------------------------------------------

def _truecaller_probe(e164_no_plus: str, timeout: int) -> Optional[Dict[str, Any]]:
    cc = e164_no_plus[:2] if len(e164_no_plus) >= 2 else "in"
    url = f"https://www.truecaller.com/search/{cc.lower()}/{e164_no_plus}"
    try:
        ui.stealth_sleep()
        r = requests.get(url, headers=DEFAULT_HEADERS, timeout=timeout, allow_redirects=True)
        # Truecaller heavily challenges bots — just record status + a suggestive
        # title heuristic if the body somehow makes it through.
        body = (r.text or "")[:50000].lower()
        name = None
        m = re.search(r"<title>([^<]+)</title>", body, re.IGNORECASE)
        if m:
            t = m.group(1).strip()
            # Skip generic "Truecaller - ..." page titles.
            if t and "truecaller" not in t.lower() and "challenge" not in t.lower():
                name = t[:80]
        return {
            "url": url,
            "status_code": r.status_code,
            "name_hint": name,
            "blocked": r.status_code in (202, 403, 429) or (
                r.status_code == 200 and "challenge" in body
            ),
        }
    except Exception as exc:
        return {"url": url, "error": str(exc)[:120]}


# ---------------------------------------------------------------------------
# psbdmp.ws paste search by phone number
# ---------------------------------------------------------------------------

def _psbdmp_paste(query: str, timeout: int) -> Optional[Dict[str, Any]]:
    try:
        ui.stealth_sleep()
        r = requests.get(
            f"https://psbdmp.ws/api/search/{quote_plus(query)}",
            headers=DEFAULT_HEADERS,
            timeout=timeout,
        )
        if r.status_code != 200 or not (r.text or "").strip():
            return {"count": 0, "pastes": []}
        try:
            data = r.json()
        except ValueError:
            return {"count": 0, "pastes": []}
        if isinstance(data, dict):
            count = int(data.get("count", 0))
            pastes = data.get("data", []) or []
        elif isinstance(data, list):
            count = len(data)
            pastes = data
        else:
            return {"count": 0, "pastes": []}
        out: List[Dict[str, Any]] = []
        for p in pastes[:20]:
            if isinstance(p, dict) and p.get("id"):
                out.append({
                    "id": p.get("id"),
                    "url": f"https://pastebin.com/{p.get('id')}",
                    "date": p.get("date"),
                })
        return {"count": count, "pastes": out}
    except Exception as exc:
        ui.warn(f"psbdmp paste search failed: {exc}")
        return None


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------

def run(
    phone: str,
    default_region: str = "IN",
    timeout: int = 10,
    depth: int = 2,
) -> ModuleResult:
    res = ModuleResult(module="phone", target=phone, target_type="phone")

    try:
        import phonenumbers
        from phonenumbers import carrier, geocoder, timezone, number_type, NumberParseException
        from phonenumbers.phonenumberutil import PhoneNumberType
    except Exception as exc:
        res.finish(success=False, error=f"phonenumbers library missing: {exc}")
        return res

    region = None if (phone or "").strip().startswith("+") else default_region
    try:
        parsed = phonenumbers.parse(phone, region)
    except NumberParseException as exc:
        res.add("valid", False, severity="medium", source="phonenumbers", note=str(exc))
        res.finish(success=False, error=str(exc))
        return res

    valid = phonenumbers.is_valid_number(parsed)
    possible = phonenumbers.is_possible_number(parsed)
    res.add("valid", valid, source="phonenumbers")
    res.add("possible", possible, source="phonenumbers")

    if not valid:
        res.finish(success=False, error="invalid phone number")
        return res

    country_name = geocoder.country_name_for_number(parsed, "en") or ""
    region_desc = geocoder.description_for_number(parsed, "en") or ""
    car = carrier.name_for_number(parsed, "en") or ""
    tzs = list(timezone.time_zones_for_number(parsed)) or []

    type_map: Dict[int, str] = {
        PhoneNumberType.MOBILE: "mobile",
        PhoneNumberType.FIXED_LINE: "fixed_line",
        PhoneNumberType.FIXED_LINE_OR_MOBILE: "fixed_line_or_mobile",
        PhoneNumberType.TOLL_FREE: "toll_free",
        PhoneNumberType.PREMIUM_RATE: "premium_rate",
        PhoneNumberType.SHARED_COST: "shared_cost",
        PhoneNumberType.VOIP: "voip",
        PhoneNumberType.PERSONAL_NUMBER: "personal",
        PhoneNumberType.PAGER: "pager",
        PhoneNumberType.UAN: "uan",
        PhoneNumberType.VOICEMAIL: "voicemail",
        PhoneNumberType.UNKNOWN: "unknown",
    }
    line_type = type_map.get(number_type(parsed), "unknown")

    fmt: Dict[str, str] = {
        "international": phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.INTERNATIONAL),
        "national": phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.NATIONAL),
        "e164": phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164),
        "rfc3966": phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.RFC3966),
    }

    digits = _digits_only(fmt["e164"])
    e164_no_plus = fmt["e164"].lstrip("+")
    variants = list(dict.fromkeys([
        fmt["e164"], fmt["international"], fmt["national"],
        e164_no_plus, digits, _digits_only(fmt["national"]),
    ]))
    variants = [v for v in variants if v]

    res.data["country_code"] = parsed.country_code
    res.data["national_number"] = parsed.national_number
    res.data["country"] = country_name
    res.data["region"] = region_desc
    res.data["carrier"] = car
    res.data["line_type"] = line_type
    res.data["timezones"] = tzs
    res.data["formats"] = fmt
    res.data["variants"] = variants

    # ---- Findings: identity ----
    res.add("country", country_name or "unknown", source="phonenumbers")
    if region_desc and region_desc != country_name:
        res.add("region", region_desc, source="phonenumbers")
    res.add("carrier", car or "unknown", source="phonenumbers")
    res.add("line_type", line_type, source="phonenumbers")
    if tzs:
        res.add("timezones", tzs, source="phonenumbers")
    res.add("e164", fmt["e164"], source="phonenumbers")
    res.add("international", fmt["international"], source="phonenumbers")
    res.add("national", fmt["national"], source="phonenumbers")

    if line_type == "voip":
        res.add("voip", True, severity="medium", source="phonenumbers",
                note="VoIP numbers are often less attributable")

    # ---- WhatsApp wa.me presence ----
    ui.info("WhatsApp wa.me presence hint...")
    wa = _whatsapp_check(e164_no_plus, timeout)
    if wa:
        res.data["whatsapp"] = wa
        if wa.get("reachable"):
            res.add("whatsapp_reachable", True, severity="low", source="wa.me",
                    note="wa.me responds for this number (does not confirm registration)",
                    profile_url=wa.get("url"))
        elif wa.get("status_code"):
            res.add("whatsapp_reachable", False, source="wa.me",
                    note=f"status {wa['status_code']}")

    # ---- Truecaller public probe ----
    ui.info("Truecaller public probe...")
    tc = _truecaller_probe(e164_no_plus, timeout)
    if tc:
        res.data["truecaller"] = tc
        if tc.get("name_hint"):
            res.add("truecaller_name_hint", tc["name_hint"], severity="medium",
                    source="truecaller.com",
                    note="extracted from page title — verify manually",
                    profile_url=tc.get("url"))
        elif tc.get("blocked"):
            res.add("truecaller", "blocked", source="truecaller.com",
                    note="bot challenge — open URL manually",
                    profile_url=tc.get("url"))

    # ---- Pastebin via psbdmp.ws ----
    ui.info("Pastebin search by phone...")
    psb = _psbdmp_paste(digits, timeout)
    if psb is not None:
        res.data["pastebin"] = psb
        if psb.get("count", 0) > 0:
            sev = "high" if psb["count"] >= 5 else "medium"
            res.add("pastebin_appearances", psb["count"], severity=sev,
                    source="psbdmp.ws",
                    note=f"appears in {psb['count']} paste(s)")
            for p in (psb.get("pastes") or [])[:5]:
                res.add(f"paste_{p.get('id')}", p.get("url"),
                        severity="medium", source="psbdmp.ws",
                        note=p.get("date") or "",
                        profile_url=p.get("url"))
        else:
            res.add("pastebin_appearances", 0, source="psbdmp.ws")

    # ---- Curated dork + platform search URLs ----
    dorks = _google_dorks(variants)
    plats = _platform_links(fmt["e164"], fmt["national"], digits)
    res.data["google_dorks"] = dorks
    res.data["platform_links"] = plats

    # Surface the most useful ones as findings (clickable in HTML report)
    for label, url in plats.items():
        res.add(f"platform_{label}", url, severity="info", source="search-hint",
                note="manual review URL", profile_url=url)
    for label, url in dorks.items():
        res.add(f"dork_{label}", url, severity="info", source="search-hint",
                note="Google dork URL", profile_url=url)

    # ---- Summary ----
    pb_count = (psb or {}).get("count", 0) if psb else 0
    plat_total = len(plats)
    dork_total = len(dorks)
    spam_hint = "blocked" if (tc and tc.get("blocked")) else (
        "name found" if (tc and tc.get("name_hint")) else "not available"
    )
    res.summary = (
        f"{country_name or 'unknown'} | {car or 'no carrier'} | "
        f"{line_type} | pastebin: {pb_count} | "
        f"platform links: {plat_total} | dorks: {dork_total} | "
        f"truecaller: {spam_hint}"
    )
    ui.found(f"{phone} -> {res.summary}")

    res.finish(success=True)
    return res
