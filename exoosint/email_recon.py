"""Email investigation module."""

from __future__ import annotations

import os
import re
import smtplib
import socket
from typing import Any, Dict, List, Optional

import requests

from . import ui
from .types import ModuleResult


EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$")


# Compact list of common disposable email domains (extend as needed)
DISPOSABLE_DOMAINS = {
    "10minutemail.com", "guerrillamail.com", "mailinator.com", "tempmail.com",
    "temp-mail.org", "yopmail.com", "throwawaymail.com", "trashmail.com",
    "fakeinbox.com", "getnada.com", "dispostable.com", "maildrop.cc",
    "sharklasers.com", "mailnesia.com", "mintemail.com", "spam4.me",
    "tempr.email", "trbvm.com", "tempmailaddress.com", "moakt.com",
    "mailcatch.com", "33mail.com", "anonbox.net", "burnermail.io",
}


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


def is_valid_email(value: str) -> bool:
    return bool(EMAIL_RE.match(value or ""))


def _mx_records(domain: str, timeout: int) -> List[str]:
    try:
        import dns.resolver
        resolver = dns.resolver.Resolver()
        resolver.timeout = timeout
        resolver.lifetime = timeout
        answers = resolver.resolve(domain, "MX")
        return sorted([str(r.exchange).rstrip(".") for r in answers])
    except Exception as exc:
        ui.warn(f"mx lookup failed for {domain}: {exc}")
        return []


def _smtp_verify(email: str, mx: str, timeout: int) -> Optional[Dict[str, Any]]:
    """Best-effort SMTP probe. Many servers mask responses, so result is informational."""
    try:
        socket.setdefaulttimeout(timeout)
        srv = smtplib.SMTP(timeout=timeout)
        srv.connect(mx, 25)
        srv.helo("exo-osint.local")
        srv.mail("noreply@exo-osint.local")
        code, msg = srv.rcpt(email)
        srv.quit()
        msg_text = msg.decode("utf-8", "ignore") if isinstance(msg, bytes) else str(msg)
        return {"code": code, "message": msg_text, "deliverable": code in (250, 251)}
    except Exception as exc:
        return {"error": str(exc), "deliverable": None}
    finally:
        socket.setdefaulttimeout(None)


def _hibp_breaches(email: str, timeout: int) -> Optional[List[Dict[str, Any]]]:
    api_key = os.environ.get("HIBP_API_KEY")
    if not api_key:
        return None
    try:
        r = requests.get(
            f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}",
            params={"truncateResponse": "false"},
            headers={
                "hibp-api-key": api_key,
                "User-Agent": "EXO-OSINT/1.0",
            },
            timeout=timeout,
        )
        if r.status_code == 404:
            return []
        if r.status_code == 200:
            return r.json()
    except Exception as exc:
        ui.warn(f"hibp lookup failed: {exc}")
    return None


def run(email: str, timeout: int = 10, run_domain_recon: bool = True, threads: int = 20) -> ModuleResult:
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

    # Provider
    provider = PROVIDERS.get(domain)
    if provider:
        res.add("provider", provider, source="signature")
    else:
        res.add("provider", "Custom / Self-hosted", source="signature")

    # Disposable
    disposable = domain in DISPOSABLE_DOMAINS
    if disposable:
        res.add("disposable", True, severity="high", source="static_list",
                note="known disposable email provider")
    else:
        res.add("disposable", False, source="static_list")

    # MX
    ui.info(f"Checking MX records for {domain}...")
    mx = _mx_records(domain, timeout)
    if mx:
        res.data["mx_records"] = mx
        res.add("mx_records", mx, source="dns")
        res.add("can_receive_mail", True, source="dns")
    else:
        res.add("can_receive_mail", False, severity="medium", source="dns",
                note="domain has no MX records")

    # SMTP probe (only if we have MX, optional)
    if mx:
        ui.info("SMTP probe (best-effort)...")
        smtp_result = _smtp_verify(email, mx[0], timeout=min(timeout, 8))
        res.data["smtp"] = smtp_result
        if smtp_result.get("deliverable") is True:
            res.add("smtp_deliverable", True, source="smtp",
                    note=f"server accepted RCPT (code {smtp_result.get('code')})")
        elif smtp_result.get("deliverable") is False:
            res.add("smtp_deliverable", False, severity="low", source="smtp",
                    note=f"server rejected RCPT (code {smtp_result.get('code')})")

    # HIBP breach check
    breaches = _hibp_breaches(email, timeout)
    if breaches is None:
        if not os.environ.get("HIBP_API_KEY"):
            res.add("breaches", "unavailable", note="set HIBP_API_KEY for breach data")
    else:
        res.data["breaches"] = breaches
        if breaches:
            sev = "critical" if len(breaches) >= 5 else "high"
            res.add("breaches_found", len(breaches), severity=sev, source="haveibeenpwned",
                    note=", ".join(b.get("Name", "?") for b in breaches[:5]))
        else:
            res.add("breaches_found", 0, source="haveibeenpwned")

    # Domain recon
    if run_domain_recon:
        try:
            from . import domain as domain_mod
            ui.info(f"Running domain recon on {domain}...")
            dom_res = domain_mod.run(domain, timeout=timeout, threads=threads)
            res.data["domain_recon"] = dom_res.to_dict()
            # surface high-value findings up
            for f in dom_res.findings:
                if f.severity in ("high", "critical"):
                    res.add(f"domain.{f.key}", f.value, severity=f.severity,
                            source=f.source, note=f.note)
        except Exception as exc:
            ui.warn(f"domain recon failed: {exc}")

    res.finish(success=True)
    return res
