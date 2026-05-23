"""Username hunter — checks 50+ platforms concurrently."""

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
#   category: social | coding | gaming | creative | professional | content | misc
PLATFORMS: Dict[str, Dict[str, Any]] = {
    # Social
    "GitHub": {"url": "https://github.com/{}", "method": "status", "category": "coding"},
    "GitLab": {"url": "https://gitlab.com/{}", "method": "status", "category": "coding"},
    "Bitbucket": {"url": "https://bitbucket.org/{}/", "method": "status", "category": "coding"},
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
    "YouTube": {"url": "https://www.youtube.com/@{}", "method": "status", "category": "content"},
    "LinkedIn": {"url": "https://www.linkedin.com/in/{}", "method": "status", "category": "professional"},
    "Facebook": {"url": "https://www.facebook.com/{}", "method": "status", "category": "social"},
    "Pinterest": {"url": "https://www.pinterest.com/{}/", "method": "status", "category": "creative"},
    "Tumblr": {"url": "https://{}.tumblr.com", "method": "status", "category": "social"},
    "Twitch": {"url": "https://www.twitch.tv/{}", "method": "status", "category": "gaming"},
    "Steam": {"url": "https://steamcommunity.com/id/{}", "method": "absent",
              "marker": "The specified profile could not be found", "category": "gaming"},
    "Telegram": {"url": "https://t.me/{}", "method": "absent",
                 "marker": "tgme_page_title", "category": "social", "invert_marker": True},
    "Snapchat": {"url": "https://www.snapchat.com/add/{}", "method": "status", "category": "social"},
    "Medium": {"url": "https://medium.com/@{}", "method": "status", "category": "content"},
    "Dev.to": {"url": "https://dev.to/{}", "method": "status", "category": "coding"},
    "HackerNews": {
        "url": "https://hacker-news.firebaseio.com/v0/user/{}.json",
        "method": "absent",
        "marker": "null",
        "category": "coding",
    },
    "ProductHunt": {"url": "https://www.producthunt.com/@{}", "method": "status", "category": "professional"},
    "Pastebin": {"url": "https://pastebin.com/u/{}", "method": "status", "category": "coding"},
    "CodePen": {"url": "https://codepen.io/{}", "method": "status", "category": "coding"},
    "Replit": {"url": "https://replit.com/@{}", "method": "status", "category": "coding"},
    "Kaggle": {"url": "https://www.kaggle.com/{}", "method": "status", "category": "coding"},
    "Spotify": {"url": "https://open.spotify.com/user/{}", "method": "status", "category": "content"},
    "SoundCloud": {"url": "https://soundcloud.com/{}", "method": "status", "category": "content"},
    "Behance": {"url": "https://www.behance.net/{}", "method": "status", "category": "creative"},
    "Dribbble": {"url": "https://dribbble.com/{}", "method": "status", "category": "creative"},
    "Fiverr": {"url": "https://www.fiverr.com/{}", "method": "status", "category": "professional"},
    "Upwork": {"url": "https://www.upwork.com/freelancers/{}", "method": "status", "category": "professional"},
    "Vimeo": {"url": "https://vimeo.com/{}", "method": "status", "category": "content"},
    "Flickr": {"url": "https://www.flickr.com/people/{}", "method": "status", "category": "creative"},
    "DeviantArt": {"url": "https://www.deviantart.com/{}", "method": "status", "category": "creative"},
    "Mastodon-social": {"url": "https://mastodon.social/@{}", "method": "status", "category": "social"},
    "Threads": {"url": "https://www.threads.net/@{}", "method": "status", "category": "social"},
    "Bluesky": {"url": "https://bsky.app/profile/{}.bsky.social", "method": "status", "category": "social"},
    "Keybase": {"url": "https://keybase.io/{}", "method": "status", "category": "coding"},
    "Quora": {"url": "https://www.quora.com/profile/{}", "method": "status", "category": "social"},
    "Slideshare": {"url": "https://www.slideshare.net/{}", "method": "status", "category": "professional"},
    "AboutMe": {"url": "https://about.me/{}", "method": "status", "category": "professional"},
    "Patreon": {"url": "https://www.patreon.com/{}", "method": "status", "category": "creative"},
    "Buymeacoffee": {"url": "https://www.buymeacoffee.com/{}", "method": "status", "category": "creative"},
    "Ko-fi": {"url": "https://ko-fi.com/{}", "method": "status", "category": "creative"},
    "Roblox": {"url": "https://www.roblox.com/user.aspx?username={}", "method": "status", "category": "gaming"},
    "Chess.com": {"url": "https://www.chess.com/member/{}", "method": "status", "category": "gaming"},
    "Lichess": {
        "url": "https://lichess.org/api/user/{}",
        "method": "present",
        "marker": '"id":',
        "category": "gaming",
    },
    "Disqus": {"url": "https://disqus.com/by/{}/", "method": "status", "category": "social"},
    "VSCO": {"url": "https://vsco.co/{}", "method": "status", "category": "creative"},
    "Wattpad": {"url": "https://www.wattpad.com/user/{}", "method": "status", "category": "content"},
    "Goodreads": {"url": "https://www.goodreads.com/{}", "method": "status", "category": "content"},
    "Trakt": {"url": "https://trakt.tv/users/{}", "method": "status", "category": "content"},
    "Last.fm": {"url": "https://www.last.fm/user/{}", "method": "status", "category": "content"},
    "Bandcamp": {"url": "https://{}.bandcamp.com", "method": "status", "category": "creative"},
    "Mixcloud": {"url": "https://www.mixcloud.com/{}/", "method": "status", "category": "content"},
}


USERNAME_RE = re.compile(r"^[A-Za-z0-9_\-.]{1,40}$")
DEFAULT_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/120.0 Safari/537.36 EXO-OSINT/1.0"
    ),
    "Accept-Language": "en-US,en;q=0.9",
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
        # Use HEAD when possible for speed; some platforms reject HEAD so fall back
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
                # found = marker NOT in text (unless invert_marker)
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

    ui.info(f"Checking {len(selected)} platforms with {threads} threads...")
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

    # Group by category
    by_category: Dict[str, List[Dict[str, Any]]] = {}
    for r in found_list:
        by_category.setdefault(r.get("category", "misc"), []).append(
            {"platform": r["platform"], "url": r["url"]}
        )
    res.data["found_by_category"] = by_category

    if found_list:
        sev = "high" if len(found_list) >= 10 else ("medium" if len(found_list) >= 5 else "low")
        res.add(
            "accounts_found",
            len(found_list),
            severity=sev,
            source="username_hunter",
            note=f"on {len(found_list)} platform(s)",
        )
        for r in found_list:
            res.add(f"profile_{r['platform']}", r["url"], severity="info",
                    source="username_hunter", note=r.get("category", ""))
    else:
        res.add("accounts_found", 0, source="username_hunter")

    res.finish(success=True)
    return res
