import random
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
import requests
from typing import List, Dict, Optional
from .types import ModuleResult
from . import ui

class DatingEnumerator:
    """Dating & Matrimonial Enumeration Module - Matches EXO-OSINT style"""

    def __init__(self, proxies: Optional[List[str]] = None, stealth: bool = True):
        self.proxies = proxies or []
        self.stealth = stealth
        self.results = {}
        self.blocked = []
        self.user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Safari/605.1.15",
        ]

    def _get_session(self):
        session = requests.Session()
        session.headers.update({"User-Agent": random.choice(self.user_agents)})
        if self.proxies:
            session.proxies = {"http": random.choice(self.proxies), "https": random.choice(self.proxies)}
        return session

    def _check_platform(self, platform: str, identifier: str, is_email: bool) -> Dict:
        session = self._get_session()
        try:
            # Indian Matrimonial Platforms (High Accuracy)
            if platform == "Shaadi.com":
                url = "https://www.shaadi.com/shaadi-info/forgot-password"
                data = {"email": identifier} if is_email else {"phone": identifier}
                r = session.post(url, data=data, timeout=10)
                exists = any(k in r.text.lower() for k in ["reset", "found", "sent", "account exists"])

            elif platform == "Jeevansathi":
                url = "https://www.jeevansathi.com/login/forgotpassword"
                r = session.post(url, data={"email": identifier}, timeout=10)
                exists = "password reset" in r.text.lower() or "account exists" in r.text.lower()

            elif platform == "BharatMatrimony":
                url = "https://www.bharatmatrimony.com/forgot-password"
                r = session.post(url, data={"email": identifier}, timeout=10)
                exists = "reset" in r.text.lower()

            elif platform == "TrulyMadly":
                url = "https://www.trulymadly.com/api/forgot-password"
                r = session.post(url, json={"email": identifier}, timeout=10)
                exists = r.status_code == 200

            # Global Dating Platforms
            elif platform == "Tinder":
                url = "https://api.gotinder.com/v2/auth/login"
                r = session.post(url, json={"email": identifier} if is_email else {"phone": identifier}, timeout=10)
                exists = "exists" in r.text.lower() or r.status_code in (400, 403)

            elif platform == "Bumble":
                url = "https://bumble.com/en/forgot-password"
                r = session.post(url, data={"email": identifier}, timeout=10)
                exists = "reset link" in r.text.lower()

            else:
                # Generic fallback for remaining platforms
                time.sleep(random.uniform(1, 2))
                return {"platform": platform, "status": "unknown", "profile_url": None}

            status = "registered" if exists else "not found"
            profile_url = f"https://{platform.lower().replace(' ', '')}.com" if exists else None

            if r.status_code in (403, 429) or "blocked" in str(r.text).lower():
                self.blocked.append(platform)
                status = "blocked"

            return {
                "platform": platform,
                "status": status,
                "profile_url": profile_url
            }

        except Exception:
            return {"platform": platform, "status": "unknown", "profile_url": None}

    def run(self, emails: List[str], phones: List[str]) -> Dict:
        platforms = [
            "Shaadi.com", "Jeevansathi", "BharatMatrimony", "TrulyMadly", "Woo", "QuackQuack",
            "Tinder", "Bumble", "Hinge", "Badoo", "Grindr", "Ashley Madison"
            # Add more as we test
        ]

        targets = []
        for email in emails:
            for p in platforms:
                targets.append((p, email, True))
        for phone in phones:
            for p in platforms:
                targets.append((p, phone, False))

        with ThreadPoolExecutor(max_workers=25) as executor:
            futures = {executor.submit(self._check_platform, p, i, e): (p, i) for p, i, e in targets}
            for future in as_completed(futures):
                res = future.result()
                self.results[res["platform"]] = res
                if self.stealth:
                    time.sleep(random.uniform(1.8, 3.5))

        return self.results


def run_dating_recon(targets: Dict, config: Dict) -> ModuleResult:
    """Main entry point - matches other recon modules"""
    enumerator = DatingEnumerator(proxies=config.get("proxies"), stealth=config.get("stealth", True))
    emails = targets.get("emails", [])
    phones = targets.get("phones", [])
    results = enumerator.run(emails, phones)
    return ModuleResult(name="dating_recon", data=results, success=True)
