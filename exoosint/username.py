"""Username hunter — checks 85+ platforms concurrently."""

from __future__ import annotations

import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, List, Optional

import requests

from . import ui
from .types import ModuleResult


# Each platform is a dict of:
#   url     : URL template with {} for the username
#   method  : 'status' (200=found), 'absent' (substring missing => found),
#             'present' (substring present => found)
#   marker  : substring used by 'absent' / 'present' methods
#   invert_marker: bool — flip the meaning of 'absent' (present means found)
#   category: social | coding | gaming | creative | professional | content |
#             content-creator | finance | adult | misc | hacking | learning
PLATFORMS: Dict[str, Dict[str, Any]] = {
    # ---------------- Coding / Dev ----------------
    "GitHub": {"url": "https://github.com/{}", "method": "status", "category": "coding"},
    "GitLab": {"url": "https://gitlab.com/{}", "method": "status", "category": "coding"},
    "Bitbucket": {"url": "https://bitbucket.org/{}/", "method": "status", "category": "coding"},
    "Codeberg": {"url": "https://codeberg.org/{}", "method": "status", "category": "coding"},
    "Dev.to": {"url": "https://dev.to/{}", "method": "status", "category": "coding"},
    "CodePen": {"url": "https://codepen.io/{}", "method": "status", "category": "coding"},
    "Replit": {"url": "https://replit.com/@{}", "method": "status", "category": "coding"},
    "Kaggle": {"url": "https://www.kaggle.com/{}", "method": "status", "category": "coding"},
    "HackerNews": {
        "url": "https://hacker-news.firebaseio.com/v0/user/{}.json",
        "method": "absent",
        "marker": "null",
        "category": "coding",
    },
    "Pastebin": {"url": "https://pastebin.com/u/{}", "method": "status", "category": "coding"},
    "Keybase": {"url": "https://keybase.io/{}", "method": "status", "category": "coding"},
    "StackOverflow": {
        "url": "https://stackoverflow.com/users/{}",
        "method": "status",
        "category": "coding",
    },
    "NPM": {
        "url": "https://www.npmjs.com/~{}",
        "method": "status",
        "category": "coding",
    },
    "PyPI": {
        "url": "https://pypi.org/user/{}/",
        "method": "status",
        "category": "coding",
    },
    "DockerHub": {
        "url": "https://hub.docker.com/u/{}",
        "method": "status",
        "category": "coding",
    },

    # ---------------- Social ----------------
    "Twitter": {"url": "https://twitter.com/{}", "method": "status", "category": "social"},
    "X": {"url": "https://x.com/{}", "method": "status", "category": "social"},
    "Instagram": {"url": "https://www.instagram.com/{}/", "method": "status", "category": "social"},
    "Reddit": {
        "url": "https://www.reddit.com/user/{}/about.json",
        "method": "absent",
        "marker": '"error": 404',
        "category": "social",
    },
    "TikTok": {"url": "https://www.tiktok.com/@{}", "method": "status", "category": "social"},
    "Facebook": {"url": "https://www.facebook.com/{}", "method": "status", "category": "social"},
    "Tumblr": {"url": "https://{}.tumblr.com", "method": "status", "category": "social"},
    "Telegram": {
        "url": "https://t.me/{}",
        "method": "absent",
        "marker": "tgme_page_title",
        "invert_marker": True,
        "category": "social",
    },
    "Snapchat": {"url": "https://www.snapchat.com/add/{}", "method": "status", "category": "social"},
    "Mastodon-social": {"url": "https://mastodon.social/@{}", "method": "status", "category": "social"},
    "Threads": {"url": "https://www.threads.net/@{}", "method": "status", "category": "social"},
    "Bluesky": {"url": "https://bsky.app/profile/{}.bsky.social", "method": "status", "category": "social"},
    "Quora": {"url": "https://www.quora.com/profile/{}", "method": "status", "category": "social"},
    "VK": {"url": "https://vk.com/{}", "method": "status", "category": "social"},
    "Disqus": {"url": "https://disqus.com/by/{}/", "method": "status", "category": "social"},

    # ---------------- Professional ----------------
    "LinkedIn": {"url": "https://www.linkedin.com/in/{}", "method": "status", "category": "professional"},
    "ProductHunt": {"url": "https://www.producthunt.com/@{}", "method": "status", "category": "professional"},
    "AboutMe": {"url": "https://about.me/{}", "method": "status", "category": "professional"},
    "Linktree": {
        "url": "https://linktr.ee/{}",
        "method": "absent",
        "marker": "Sorry, this content isn",
        "category": "professional",
    },
    "Slideshare": {"url": "https://www.slideshare.net/{}", "method": "status", "category": "professional"},
    "Fiverr": {"url": "https://www.fiverr.com/{}", "method": "status", "category": "professional"},
    "Upwork": {"url": "https://www.upwork.com/freelancers/{}", "method": "status", "category": "professional"},

    # ---------------- Content ----------------
    "YouTube": {"url": "https://www.youtube.com/@{}", "method": "status", "category": "content"},
    "Medium": {"url": "https://medium.com/@{}", "method": "status", "category": "content"},
    "Substack": {
        "url": "https://{}.substack.com",
        "method": "absent",
        "marker": "We can",
        "category": "content",
    },
    "WordPress": {
        "url": "https://{}.wordpress.com",
        "method": "absent",
        "marker": "doesn",
        "category": "content",
    },
    "Blogspot": {"url": "https://{}.blogspot.com", "method": "status", "category": "content"},
    "Ghost": {"url": "https://{}.ghost.io", "method": "status", "category": "content"},
    "Wattpad": {"url": "https://www.wattpad.com/user/{}", "method": "status", "category": "content"},
    "Goodreads": {"url": "https://www.goodreads.com/{}", "method": "status", "category": "content"},
    "Letterboxd": {"url": "https://letterboxd.com/{}/", "method": "status", "category": "content"},
    "Trakt": {"url": "https://trakt.tv/users/{}", "method": "status", "category": "content"},
    "Last.fm": {"url": "https://www.last.fm/user/{}", "method": "status", "category": "content"},
    "Mixcloud": {"url": "https://www.mixcloud.com/{}/", "method": "status", "category": "content"},
    "Spotify": {"url": "https://open.spotify.com/user/{}", "method": "status", "category": "content"},
    "SoundCloud": {"url": "https://soundcloud.com/{}", "method": "status", "category": "content"},
    "Vimeo": {"url": "https://vimeo.com/{}", "method": "status", "category": "content"},

    # ---------------- Creative ----------------
    "Behance": {"url": "https://www.behance.net/{}", "method": "status", "category": "creative"},
    "Dribbble": {"url": "https://dribbble.com/{}", "method": "status", "category": "creative"},
    "Pinterest": {"url": "https://www.pinterest.com/{}/", "method": "status", "category": "creative"},
    "Flickr": {"url": "https://www.flickr.com/people/{}", "method": "status", "category": "creative"},
    "DeviantArt": {"url": "https://www.deviantart.com/{}", "method": "status", "category": "creative"},
    "VSCO": {"url": "https://vsco.co/{}", "method": "status", "category": "creative"},
    "WeHeartIt": {"url": "https://weheartit.com/{}", "method": "status", "category": "creative"},
    "Bandcamp": {"url": "https://{}.bandcamp.com", "method": "status", "category": "creative"},
    "Itch.io": {"url": "https://{}.itch.io", "method": "status", "category": "creative"},

    # ---------------- Gaming ----------------
    "Twitch": {"url": "https://www.twitch.tv/{}", "method": "status", "category": "gaming"},
    "Steam": {
        "url": "https://steamcommunity.com/id/{}",
        "method": "absent",
        "marker": "The specified profile could not be found",
        "category": "gaming",
    },
    "Roblox": {
        "url": "https://www.roblox.com/user.aspx?username={}",
        "method": "status",
        "category": "gaming",
    },
    "Chess.com": {"url": "https://www.chess.com/member/{}", "method": "status", "category": "gaming"},
    "Lichess": {
        "url": "https://lichess.org/api/user/{}",
        "method": "present",
        "marker": '"id":',
        "category": "gaming",
    },
    "Minecraft": {
        # Mojang public name -> uuid endpoint; 200 with body if exists, 204 / 404 if not.
        "url": "https://api.mojang.com/users/profiles/minecraft/{}",
        "method": "present",
        "marker": '"id"',
        "category": "gaming",
    },
    "Epic-Games": {
        # Epic Games public profile via fortnite-api community endpoint
        "url": "https://fortnite-api.com/v2/stats/br/v2?name={}",
        "method": "present",
        "marker": '"account"',
        "category": "gaming",
    },
    "GOG": {
        "url": "https://www.gog.com/u/{}",
        "method": "absent",
        "marker": "404",
        "category": "gaming",
    },

    # ---------------- Content creator / monetization ----------------
    "Patreon": {"url": "https://www.patreon.com/{}", "method": "status", "category": "content-creator"},
    "Buymeacoffee": {"url": "https://www.buymeacoffee.com/{}", "method": "status", "category": "content-creator"},
    "Ko-fi": {"url": "https://ko-fi.com/{}", "method": "status", "category": "content-creator"},
    "OnlyFans": {
        "url": "https://onlyfans.com/{}",
        "method": "status",
        "category": "content-creator",
    },
    "Pornhub": {
        "url": "https://www.pornhub.com/users/{}",
        "method": "status",
        "category": "adult",
    },

    # ---------------- Finance / payment handles ----------------
    "Cash-App": {
        "url": "https://cash.app/${}",
        "method": "absent",
        "marker": "We couldn",
        "category": "finance",
    },
    "Venmo": {
        "url": "https://account.venmo.com/u/{}",
        "method": "status",
        "category": "finance",
    },
    "PayPal.me": {
        "url": "https://www.paypal.com/paypalme/{}",
        "method": "status",
        "category": "finance",
    },

    # ---------------- Hacking / security / learning ----------------
    "HackerOne": {
        "url": "https://hackerone.com/{}",
        "method": "absent",
        "marker": "Page not found",
        "category": "hacking",
    },
    "Bugcrowd": {
        "url": "https://bugcrowd.com/{}",
        "method": "status",
        "category": "hacking",
    },
    "CTFtime": {
        # CTFtime uses numeric IDs but supports team/user search; team page returns 200 if exists
        "url": "https://ctftime.org/user/{}",
        "method": "status",
        "category": "hacking",
    },
    "TryHackMe": {
        "url": "https://tryhackme.com/p/{}",
        "method": "status",
        "category": "hacking",
    },
    "Duolingo": {
        "url": "https://www.duolingo.com/profile/{}",
        "method": "status",
        "category": "learning",
    },
}


# Categories used to derive icons / colors in the HTML report
CATEGORY_ICONS: Dict[str, str] = {
    "coding": "</>",
    "social": "@",
    "professional": "★",
    "content": "▶",
    "creative": "✦",
    "gaming": "♛",
    "content-creator": "$",
    "finance": "$",
    "adult": "!",
    "hacking": "#",
    "learning": "✎",
    "misc": "•",
}


USERNAME_RE = re.compile(r"^[A-Za-z0-9_\-.]{1,40}$")
DEFAULT_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/120.0 Safari/537.36 EXO-OSINT/2.0"
    ),
    "Accept-Language": "en-US,en;q=0.9",
    "Accept": "text/html,application/xhtml+xml,application/json,*/*;q=0.8",
}


def is_valid_username(value: str) -> bool:
    return bool(USERNAME_RE.match(value or ""))


def _check_one(name: str, conf: Dict[str, Any], username: str, timeout: int) -> Dict[str, Any]:
    url = conf["url"].format(username)
    method = conf.get("method", "status")
    out: Dict[str, Any] = {
        "platform": name,
        "category": conf.get("category", "misc"),
        "url": url,
        "found": False,
        "status_code": None,
        "error": None,
    }
    try:
        ui.stealth_sleep()
        if method == "status":
            r = requests.head(url, headers=DEFAULT_HEADERS, timeout=timeout, allow_redirects=True)
            if r.status_code in (405, 403, 400):
                r = requests.get(url, headers=DEFAULT_HEADERS, timeout=timeout, allow_redirects=True)
            out["status_code"] = r.status_code
            out["found"] = r.status_code == 200 and not _looks_like_404(r)
        else:
            r = requests.get(url, headers=DEFAULT_HEADERS, timeout=timeout, allow_redirects=True)
            out["status_code"] = r.status_code
            marker = conf.get("marker", "")
            invert = conf.get("invert_marker", False)
            text = r.text or ""
            present = marker in text
            if method == "absent":
                out["found"] = (r.status_code == 200) and (present if invert else not present)
            elif method == "present":
                out["found"] = (r.status_code == 200) and present
    except requests.Timeout:
        out["error"] = "timeout"
    except Exception as exc:
        out["error"] = str(exc)[:80]
    return out


def _looks_like_404(r: requests.Response) -> bool:
    """Heuristic: detect soft-404 redirects to home page or login."""
    final = (r.url or "").lower()
    bad_segments = ("/login", "/signup", "/signin", "/register", "/404", "/error")
    return any(seg in final for seg in bad_segments)


def run(
    username: str,
    timeout: int = 10,
    threads: int = 20,
    platforms: Optional[List[str]] = None,
    depth: int = 2,
) -> ModuleResult:
    res = ModuleResult(module="username", target=username, target_type="username")

    if not is_valid_username(username):
        res.finish(success=False, error="invalid username format")
        return res

    selected: Dict[str, Dict[str, Any]] = {}
    if platforms:
        wanted = {p.strip().lower() for p in platforms if p.strip()}
        for name, conf in PLATFORMS.items():
            if name.lower() in wanted:
                selected[name] = conf
        if not selected:
            ui.warn("No matching platforms; falling back to all.")
            selected = PLATFORMS
    else:
        selected = PLATFORMS

    # Depth filter — at depth 1 we only check the top-tier platforms
    if depth <= 1 and not platforms:
        depth1_keep = {
            "GitHub", "GitLab", "Twitter", "X", "Instagram", "Reddit",
            "TikTok", "YouTube", "LinkedIn", "Facebook", "Medium",
            "Telegram", "Twitch", "Steam", "Pinterest", "Spotify",
            "SoundCloud", "Mastodon-social", "Threads", "Bluesky",
        }
        selected = {n: c for n, c in selected.items() if n in depth1_keep}

    ui.info(f"Checking {len(selected)} platforms with {threads} threads (depth={depth})...")
    progress = ui.ProgressBar(total=len(selected), label="username")
    results: List[Dict[str, Any]] = []
    with ThreadPoolExecutor(max_workers=threads) as pool:
        futs = {
            pool.submit(_check_one, name, conf, username, timeout): name
            for name, conf in selected.items()
        }
        for fut in as_completed(futs):
            name = futs[fut]
            try:
                r = fut.result()
            except Exception as exc:
                r = {"platform": name, "url": "", "found": False, "error": str(exc)}
            results.append(r)
            progress.tick(1, note=name)
    progress.close()

    results.sort(key=lambda x: (not x["found"], x["platform"].lower()))
    found_list = [r for r in results if r["found"]]

    res.data["platforms_checked"] = len(selected)
    res.data["results"] = results
    res.data["found_count"] = len(found_list)

    by_category: Dict[str, List[Dict[str, Any]]] = {}
    for r in found_list:
        by_category.setdefault(r.get("category", "misc"), []).append(
            {"platform": r["platform"], "url": r["url"]}
        )
    res.data["found_by_category"] = by_category

    if found_list:
        sev = "high" if len(found_list) >= 15 else ("medium" if len(found_list) >= 7 else "low")
        res.add(
            "accounts_found",
            len(found_list),
            severity=sev,
            source="username_hunter",
            note=f"on {len(found_list)} of {len(selected)} platform(s)",
        )
        # Highlight risky categories
        for risky in ("adult", "finance", "hacking", "content-creator"):
            n = len(by_category.get(risky, []))
            if n:
                cat_sev = "high" if risky in ("adult", "finance") else "medium"
                res.add(f"{risky}_accounts", n, severity=cat_sev,
                        source="username_hunter",
                        note=", ".join(p["platform"] for p in by_category[risky]))
        for r in found_list:
            res.add(
                f"profile_{r['platform']}",
                r["url"],
                severity="info",
                source="username_hunter",
                note=r.get("category", ""),
                profile_url=r["url"],
            )
    else:
        res.add("accounts_found", 0, source="username_hunter")

    # Build a one-line executive summary
    cat_summary = ", ".join(
        f"{c}={len(by_category[c])}" for c in sorted(by_category) if by_category[c]
    )
    res.summary = (
        f"{len(found_list)} of {len(selected)} platforms hit"
        + (f"  [{cat_summary}]" if cat_summary else "")
    )

    res.finish(success=True)
    return res
