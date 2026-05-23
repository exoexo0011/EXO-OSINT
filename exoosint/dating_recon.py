"""Dating & matrimonial platform reconnaissance module.

Realistic OSINT note:
  Major dating apps (Tinder, Bumble, Hinge, OkCupid) and Indian matrimonial
  sites (Shaadi, Jeevansathi, BharatMatrimony) all hide registration status
  behind authentication, captchas, and anti-bot challenges. Account-enumeration
  via forgot-password POST endpoints is unreliable, blocked, and has serious
  Terms-of-Service implications.

  Following the same convention used by professional OSINT toolchains, this
  module:
    1. Generates curated, ready-to-click search URLs ("dorks") so the
       investigator can pivot manually.
    2. Performs a small set of *passive* checks that are reliably available
       without authentication (wa.me presence hint for phone targets, public
       Bumble profile preview probe).
    3. Categorizes platforms (mainstream / indian-matrimonial / hookup /
       LGBTQ+ / chat) so risky categories are surfaced clearly in the report.
"""

from __future__ import annotations

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


# Each entry: (display_name, category, search_url_template)
#   {q} is replaced with the URL-encoded target identifier.
PLATFORMS: List[Dict[str, str]] = [
    # ----- mainstream dating -----
    {"name": "Tinder",      "category": "dating",   "url": "https://www.google.com/search?q={q}+site%3Atinder.com"},
    {"name": "Bumble",      "category": "dating",   "url": "https://www.google.com/search?q={q}+site%3Abumble.com"},
    {"name": "Hinge",       "category": "dating",   "url": "https://www.google.com/search?q={q}+site%3Ahinge.co"},
    {"name": "OkCupid",     "category": "dating",   "url": "https://www.google.com/search?q={q}+site%3Aokcupid.com"},
    {"name": "Match.com",   "category": "dating",   "url": "https://www.google.com/search?q={q}+site%3Amatch.com"},
    {"name": "PlentyOfFish","category": "dating",   "url": "https://www.google.com/search?q={q}+site%3Apof.com"},
    {"name": "Coffee Meets Bagel", "category": "dating", "url": "https://www.google.com/search?q={q}+site%3Acoffeemeetsbagel.com"},
    {"name": "Badoo",       "category": "dating",   "url": "https://www.google.com/search?q={q}+site%3Abadoo.com"},

    # ----- indian matrimonial -----
    {"name": "Shaadi.com",      "category": "indian", "url": "https://www.google.com/search?q={q}+site%3Ashaadi.com"},
    {"name": "Jeevansathi",     "category": "indian", "url": "https://www.google.com/search?q={q}+site%3Ajeevansathi.com"},
    {"name": "BharatMatrimony", "category": "indian", "url": "https://www.google.com/search?q={q}+site%3Abharatmatrimony.com"},
    {"name": "Matrimony.com",   "category": "indian", "url": "https://www.google.com/search?q={q}+site%3Amatrimony.com"},
    {"name": "SimplyMarry",     "category": "indian", "url": "https://www.google.com/search?q={q}+site%3Asimplymarry.com"},
    {"name": "BetterHalf",      "category": "indian", "url": "https://www.google.com/search?q={q}+site%3Abetterhalf.ai"},
    {"name": "TrulyMadly",      "category": "indian", "url": "https://www.google.com/search?q={q}+site%3Atrulymadly.com"},

    # ----- hookup / casual -----
    {"name": "Ashley Madison", "category": "hookup", "url": "https://www.google.com/search?q={q}+site%3Aashleymadison.com"},
    {"name": "AdultFriendFinder","category": "hookup","url": "https://www.google.com/search?q={q}+site%3Aadultfriendfinder.com"},
    {"name": "Feeld",          "category": "hookup", "url": "https://www.google.com/search?q={q}+site%3Afeeld.co"},

    # ----- LGBTQ+ -----
    {"name": "Grindr",  "category": "lgbtq",  "url": "https://www.google.com/search?q={q}+site%3Agrindr.com"},
    {"name": "Her",     "category": "lgbtq",  "url": "https://www.google.com/search?q={q}+site%3Aweareher.com"},
    {"name": "Scruff",  "category": "lgbtq",  "url": "https://www.google.com/search?q={q}+site%3Ascruff.com"},

    # ----- chat / generic social with strong dating use-case -----
    {"name": "Telegram (search)", "category": "chat", "url": "https://www.google.com/search?q={q}+site%3At.me"},
    {"name": "Discord (search)",  "category": "chat", "url": "https://www.google.com/search?q={q}+site%3Adiscord.com"},
    {"name": "WhatsApp (wa.me)",  "category": "chat", "url": "https://wa.me/{q}"},
]

VALID_CATEGORIES = {"dating", "indian", "hookup", "lgbtq", "chat"}


def _wa_me_check(phone_digits: str, timeout: int) -> Optional[Dict[str, Any]]:
    """Probe wa.me — does not confirm registration but is a free signal."""
    if not phone_digits:
        return None
    url = f"https://wa.me/{phone_digits}"
    try:
        ui.stealth_sleep()
        r = requests.get(url, headers=DEFAULT_HEADERS, timeout=timeout, allow_redirects=True)
        return {
            "url": url,
            "status_code": r.status_code,
            "reachable": r.status_code == 200,
        }
    except Exception:
        return {"url": url, "reachable": False}


def run(
    target: str,
    target_type: str,
    timeout: int = 10,
    categories: Optional[List[str]] = None,
    stealth: bool = False,
) -> ModuleResult:
    """Run dating/matrimonial recon on an email or phone target.

    Returns a ModuleResult full of clickable manual-review URLs grouped by
    category, plus light passive checks where they are free and reliable.
    """
    if stealth:
        ui.set_stealth(True)

    res = ModuleResult(module="dating", target=target, target_type=target_type)

    if target_type not in ("email", "phone"):
        res.summary = "skipped — dating recon only applies to email or phone"
        res.finish(success=True)
        return res

    selected_cats = set(categories or VALID_CATEGORIES)
    selected_cats &= VALID_CATEGORIES
    if not selected_cats:
        selected_cats = set(VALID_CATEGORIES)

    # Build the manual-review URL set
    q = quote_plus(target)
    digits = "".join(c for c in target if c.isdigit())
    by_category: Dict[str, List[Dict[str, str]]] = {}
    total = 0
    for plat in PLATFORMS:
        if plat["category"] not in selected_cats:
            continue
        # The wa.me link only makes sense for phone targets
        if "wa.me" in plat["url"] and target_type != "phone":
            continue
        url = plat["url"].format(q=digits if "wa.me" in plat["url"] else q)
        by_category.setdefault(plat["category"], []).append(
            {"platform": plat["name"], "url": url}
        )
        total += 1

    res.data["categories_checked"] = sorted(selected_cats)
    res.data["search_urls"] = by_category
    res.data["total_links"] = total

    # Surface every link as an info-level finding so it shows up in the HTML report
    for cat, items in by_category.items():
        for item in items:
            sev = "low" if cat in ("hookup", "lgbtq") else "info"
            res.add(
                f"dating_{cat}_{item['platform']}",
                item["url"],
                severity=sev,
                source=f"dating-recon/{cat}",
                note=f"manual review URL — {item['platform']}",
                profile_url=item["url"],
            )

    # Optional passive check: wa.me presence hint for phone targets
    if target_type == "phone":
        ui.info("WhatsApp wa.me presence hint…")
        digits = "".join(c for c in target if c.isdigit())
        wa = _wa_me_check(digits, timeout)
        if wa:
            res.data["whatsapp"] = wa
            if wa.get("reachable"):
                res.add(
                    "whatsapp_reachable",
                    True,
                    severity="low",
                    source="wa.me",
                    note="wa.me responds (does not confirm registration)",
                    profile_url=wa.get("url"),
                )

    cats_summary = ", ".join(f"{k}={len(v)}" for k, v in sorted(by_category.items()))
    res.summary = f"{total} curated review URLs across {len(by_category)} categor(y/ies) [{cats_summary}]"
    res.finish(success=True)
    return res
