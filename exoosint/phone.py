"""Phone number lookup."""

from __future__ import annotations

from typing import Any, Dict

from . import ui
from .types import ModuleResult


def is_phone_like(value: str) -> bool:
    s = (value or "").strip()
    if not s:
        return False
    if s.startswith("+"):
        return any(c.isdigit() for c in s[1:])
    digits = sum(1 for c in s if c.isdigit())
    return digits >= 7


def run(phone: str, default_region: str = "US", timeout: int = 10) -> ModuleResult:
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

    res.data["country_code"] = parsed.country_code
    res.data["national_number"] = parsed.national_number
    res.data["country"] = country_name
    res.data["region"] = region_desc
    res.data["carrier"] = car
    res.data["line_type"] = line_type
    res.data["timezones"] = tzs
    res.data["formats"] = fmt

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

    ui.found(f"{phone} -> {country_name} | {car or 'no carrier'} | {line_type}")

    res.finish(success=True)
    return res
