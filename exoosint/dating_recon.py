"""Dating & matrimonial platform reconnaissance module.

Realistic OSINT note:
  Major dating apps (Tinder, Bumble, Hinge, OkCupid) and Indian matrimonial
  sites (Shaadi, Jeevansathi, BharatMatrimony) all hide registration status
  behind authentication, captchas, and anti-bot challenges. Account-enumeration
  via forgot-password POST endpoints is unreliable, blocked, and has serious
  Terms-of-Service implications.

  This module follows the convention used by professional OSINT toolchains:
    1. Generates curated, ready-to-click search URLs ("dorks") so the
       investigator can pivot manually — 38+ platforms across 5 categories.
    2. Performs *passive* checks against truly public profile pages where the
       target's email-local-part or phone is treated as a possible username
       (Reddit, Telegram t.me, wa.me — all return public data without auth).
    3. Categorizes platforms (mainstream / matrimonial / hookup /
       LGBTQ+ / chat) so risky categories surface clearly in the HTML report.
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
    {"name": "Lovoo",       "category": "dating",   "url": "https://www.google.com/search?q={q}+site%3Alovoo.com"},
    {"name": "Once",        "category": "dating",   "url": "https://www.google.com/search?q={q}+site%3Aonce.com"},
    {"name": "Inner Circle","category": "dating",   "url": "https://www.google.com/search?q={q}+site%3Atheinnercircle.com"},
    {"name": "Hily",        "category": "dating",   "url": "https://www.google.com/search?q={q}+site%3Ahily.com"},
    {"name": "Clover",      "category": "dating",   "url": "https://www.google.com/search?q={q}+site%3Aclover.co"},
    {"name": "Pairs (JP)",  "category": "dating",   "url": "https://www.google.com/search?q={q}+site%3Apairs.lv"},
    {"name": "Tantan (CN)", "category": "dating",   "url": "https://www.google.com/search?q={q}+site%3Atantanapp.com"},

    # ----- matrimonial -----
    {"name": "Shaadi.com",      "category": "matrimonial", "url": "https://www.google.com/search?q={q}+site%3Ashaadi.com"},
    {"name": "Jeevansathi",     "category": "matrimonial", "url": "https://www.google.com/search?q={q}+site%3Ajeevansathi.com"},
    {"name": "BharatMatrimony", "category": "matrimonial", "url": "https://www.google.com/search?q={q}+site%3Abharatmatrimony.com"},
    {"name": "Matrimony.com",   "category": "matrimonial", "url": "https://www.google.com/search?q={q}+site%3Amatrimony.com"},
    {"name": "SimplyMarry",     "category": "matrimonial", "url": "https://www.google.com/search?q={q}+site%3Asimplymarry.com"},
    {"name": "BetterHalf",      "category": "matrimonial", "url": "https://www.google.com/search?q={q}+site%3Abetterhalf.ai"},
    {"name": "TrulyMadly",      "category": "matrimonial", "url": "https://www.google.com/search?q={q}+site%3Atrulymadly.com"},
    {"name": "JapanCupid",      "category": "matrimonial", "url": "https://www.google.com/search?q={q}+site%3Ajapancupid.com"},
    {"name": "KoreanCupid",     "category": "matrimonial", "url": "https://www.google.com/search?q={q}+site%3Akoreancupid.com"},
    {"name": "ChristianMingle", "category": "matrimonial", "url": "https://www.google.com/search?q={q}+site%3Achristianmingle.com"},
    {"name": "Muslima",         "category": "matrimonial", "url": "https://www.google.com/search?q={q}+site%3Amuslima.com"},
    {"name": "JDate",           "category": "matrimonial", "url": "https://www.google.com/search?q={q}+site%3Ajdate.com"},
    {"name": "LatinAmericanCupid", "category": "matrimonial", "url": "https://www.google.com/search?q={q}+site%3Alatinamericancupid.com"},

    # ----- hookup / casual -----
    {"name": "Ashley Madison", "category": "hookup", "url": "https://www.google.com/search?q={q}+site%3Aashleymadison.com"},
    {"name": "AdultFriendFinder","category": "hookup","url": "https://www.google.com/search?q={q}+site%3Aadultfriendfinder.com"},
    {"name": "Feeld",          "category": "hookup", "url": "https://www.google.com/search?q={q}+site%3Afeeld.co"},
    {"name": "Pure",           "category": "hookup", "url": "https://www.google.com/search?q={q}+site%3Apure.app"},

    # ----- LGBTQ+ -----
    {"name": "Grindr",  "category": "lgbtq",  "url": "https://www.google.com/search?q={q}+site%3Agrindr.com"},
    {"name": "Her",     "category": "lgbtq",  "url": "https://www.google.com/search?q={q}+site%3Aweareher.com"},
    {"name": "Scruff",  "category": "lgbtq",  "url": "https://www.google.com/search?q={q}+site%3Ascruff.com"},
    {"name": "Taimi",   "category": "lgbtq",  "url": "https://www.google.com/search?q={q}+site%3Ataimi.com"},
    {"name": "Hornet",  "category": "lgbtq",  "url": "https://www.google.com/search?q={q}+site%3Ahornet.com"},
    {"name": "Romeo (PR)", "category": "lgbtq", "url": "https://www.google.com/search?q={q}+site%3Aromeo.com"},
    {"name": "Lex",     "category": "lgbtq",  "url": "https://www.google.com/search?q={q}+site%3Athisislex.app"},

    # ----- chat / social with strong dating use-case -----
    {"name": "Telegram (search)", "category": "chat", "url": "https://www.google.com/search?q={q}+site%3At.me"},
    {"name": "Discord (search)",  "category": "chat", "url": "https://www.google.com/search?q={q}+site%3Adiscord.com"},
    {"name": "Reddit (r4r)",      "category": "chat", "url": "https://www.google.com/search?q={q}+site%3Areddit.com+r4r"},
    {"name": "WhatsApp (wa.me)",  "category": "chat", "url": "https://wa.me/{q}"},
]

# Categories with their ordering and styling weight
VALID_CATEGORIES = {"dating", "matrimonial", "hookup", "lgbtq", "chat"}

# UI severity tier per category — used by report.py for color coding.
CATEGORY_TIER: Dict[str, str] = {
    "hookup": "high",       # red — high-stigma
    "lgbtq": "high",        # red — sensitivity in many jurisdictions
    "dating": "medium",     # yellow — mainstream
    "matrimonial": "medium",# yellow
    "chat": "low",          # green — low stigma, chat-adjacent
}


# ---------------------------------------------------------------------------
# Public-profile HEAD/GET checks — pages that are intentionally public.
# ---------------------------------------------------------------------------

def _wa_me_check(phone_digits: str, timeout: int) -> Optional[Dict[str, Any]]:
    """wa.me always returns 200 for syntactically-valid international numbers.
    Capture whether the redirect lands on /send (plausible) and the final URL.
    This is intentionally a hint, not a registration confirmation."""
    if not phone_digits:
        return None
    url = f"https://wa.me/{phone_digits}"
    try:
        ui.stealth_sleep()
        r = requests.get(url, headers=DEFAULT_HEADERS, timeout=timeout, allow_redirects=True)
        return {
            "url": url,
            "status_code": r.status_code,
            "final_url": r.url,
            "reachable": r.status_code == 200,
        }
    except Exception:
        return {"url": url, "reachable": False}


def _telegram_username_check(username: str, timeout: int) -> Optional[Dict[str, Any]]:
    """t.me/{username} is intentionally public. Returns 200 always; the page
    title differs based on whether the handle exists. We parse the title."""
    if not username or not re.match(r"^[A-Za-z0-9_]{4,32}$", username):
        return None
    url = f"https://t.me/{username}"
    try:
        ui.stealth_sleep()
        r = requests.get(url, headers=DEFAULT_HEADERS, timeout=timeout, allow_redirects=True)
        if r.status_code != 200:
            return {"url": url, "exists": False, "status": r.status_code}
        body = (r.text or "")[:50000]
        title_m = re.search(r"<title>([^<]+)</title>", body, re.IGNORECASE)
        og_title_m = re.search(r'property="og:title"\s+content="([^"]+)"', body)
        title = (title_m.group(1).strip() if title_m else "")
        og_title = (og_title_m.group(1).strip() if og_title_m else "")
        # Existing Telegram usernames render og:title as the channel/user name.
        # Non-existent ones render the generic "Telegram: Contact @..." title.
        exists = bool(og_title and og_title.lower() != f"telegram: contact @{username}".lower())
        display = og_title or title
        return {
            "url": url,
            "exists": exists,
            "display_name": display,
            "title": title,
        }
    except Exception:
        return {"url": url, "exists": False}


def _reddit_user_check(username: str, timeout: int) -> Optional[Dict[str, Any]]:
    """Reddit user-about endpoint is fully public. 200 = exists, 404 = not."""
    if not username or not re.match(r"^[A-Za-z0-9_\-]{3,20}$", username):
        return None
    url = f"https://www.reddit.com/user/{username}/about.json"
    try:
        ui.stealth_sleep()
        r = requests.get(url, headers=DEFAULT_HEADERS, timeout=timeout, allow_redirects=True)
        if r.status_code == 404:
            return {"url": f"https://www.reddit.com/user/{username}/", "exists": False}
        if r.status_code != 200:
            return {"url": f"https://www.reddit.com/user/{username}/", "exists": None,
                    "status": r.status_code}
        try:
            data = r.json() or {}
        except ValueError:
            return None
        if data.get("kind") != "t2":
            return {"url": f"https://www.reddit.com/user/{username}/", "exists": False}
        d = data.get("data") or {}
        return {
            "url": f"https://www.reddit.com/user/{username}/",
            "exists": True,
            "name": d.get("name"),
            "created_utc": d.get("created_utc"),
            "comment_karma": d.get("comment_karma"),
            "link_karma": d.get("link_karma"),
            "verified": d.get("verified"),
            "is_employee": d.get("is_employee"),
            "icon_img": (d.get("icon_img") or "").split("?")[0] or None,
        }
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------

def run(
    target: str,
    target_type: str,
    timeout: int = 10,
    categories: Optional[List[str]] = None,
    stealth: bool = False,
) -> ModuleResult:
    """Run dating/matrimonial recon on an email or phone target.

    Returns a ModuleResult with curated review URLs grouped by category, plus
    light passive checks against truly public profile pages.
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
    q_url = quote_plus(target)
    digits = "".join(c for c in target if c.isdigit())
    by_category: Dict[str, List[Dict[str, str]]] = {}
    total = 0
    for plat in PLATFORMS:
        if plat["category"] not in selected_cats:
            continue
        # The wa.me link only makes sense for phone targets
        if "wa.me" in plat["url"] and target_type != "phone":
            continue
        url = plat["url"].format(q=digits if "wa.me" in plat["url"] else q_url)
        by_category.setdefault(plat["category"], []).append(
            {"platform": plat["name"], "url": url, "tier": CATEGORY_TIER[plat["category"]]}
        )
        total += 1

    res.data["categories_checked"] = sorted(selected_cats)
    res.data["search_urls"] = by_category
    res.data["total_links"] = total

    # Surface curated review URLs as findings
    for cat, items in by_category.items():
        for item in items:
            sev = "low" if cat == "chat" else ("medium" if cat in ("dating", "matrimonial") else "high")
            res.add(
                f"dating_{cat}_{item['platform']}",
                item["url"],
                severity=sev,
                source=f"dating-recon/{cat}",
                note=f"manual review URL — {item['platform']}",
                profile_url=item["url"],
            )

    # ---------- Public-profile passive checks ----------
    public_profiles: Dict[str, Any] = {}

    if target_type == "phone":
        ui.info("WhatsApp wa.me presence hint…")
        wa = _wa_me_check(digits, timeout)
        if wa:
            public_profiles["whatsapp"] = wa
            if wa.get("reachable"):
                res.add(
                    "whatsapp_reachable",
                    True,
                    severity="low",
                    source="wa.me",
                    note="wa.me responds (does not confirm registration)",
                    profile_url=wa.get("url"),
                )

    if target_type == "email":
        local_part = target.split("@", 1)[0] if "@" in target else target
        # Telegram and Reddit treat anything in their URL space as a public
        # username. Probing them with the email's local-part is legitimate
        # — these pages are intentionally public.
        ui.info(f"Telegram public profile probe for @{local_part}…")
        tg = _telegram_username_check(local_part, timeout)
        if tg:
            public_profiles["telegram"] = tg
            if tg.get("exists"):
                res.add(
                    "telegram_username_active",
                    f"@{local_part}",
                    severity="medium",
                    source="t.me",
                    note=tg.get("display_name") or "public Telegram handle exists",
                    profile_url=tg.get("url"),
                )

        ui.info(f"Reddit public profile probe for u/{local_part}…")
        rd = _reddit_user_check(local_part, timeout)
        if rd:
            public_profiles["reddit"] = rd
            if rd.get("exists"):
                karma = (rd.get("comment_karma") or 0) + (rd.get("link_karma") or 0)
                res.add(
                    "reddit_user_active",
                    f"u/{local_part}",
                    severity="medium",
                    source="reddit.com",
                    note=f"karma={karma}, verified={rd.get('verified')}",
                    profile_url=rd.get("url"),
                    avatar_url=rd.get("icon_img"),
                )

    res.data["public_profiles"] = public_profiles

    cats_summary = ", ".join(f"{k}={len(v)}" for k, v in sorted(by_category.items()))
    pp_count = sum(1 for v in public_profiles.values() if isinstance(v, dict) and v.get("exists") or v.get("reachable"))
    res.summary = (
        f"{total} curated URLs across {len(by_category)} categor(y/ies) "
        f"[{cats_summary}] | public profile hits: {pp_count}"
    )
    res.finish(success=True)
    return res
