"""Command-line interface for EXO-OSINT v2.0."""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from datetime import datetime
from typing import List, Optional

from . import __version__, ui
from . import correlation as corr_mod
from . import domain as domain_mod
from . import email_recon as email_mod
from . import ip as ip_mod
from . import phone as phone_mod
from . import report as report_mod
from . import username as username_mod
from .types import Investigation, ModuleResult, TargetReport


VALID_TYPES = ("ip", "domain", "email", "username", "phone")
EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$")
DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)([A-Za-z0-9-]{1,63}(?<!-)\.)+[A-Za-z]{2,63}$"
)


def detect_type(target: str) -> str:
    """Auto-detect target type from input shape."""
    t = (target or "").strip()
    if not t:
        return "username"
    if ip_mod.is_valid_ip(t):
        return "ip"
    if EMAIL_RE.match(t):
        return "email"
    digits_only = re.sub(r"\D", "", t)
    if t.startswith("+") or (
        len(digits_only) >= 7
        and t.replace(" ", "").replace("-", "").replace("(", "").replace(")", "").lstrip("+").isdigit()
    ):
        return "phone"
    cleaned = t.replace("http://", "").replace("https://", "").rstrip("/")
    if DOMAIN_RE.match(cleaned):
        return "domain"
    return "username"


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="exoosint",
        description="EXO-OSINT v2.0 — Open Source Intelligence Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "examples:\n"
            "  exoosint --target 8.8.8.8 --investigate --report html --save\n"
            "  exoosint --target user@gmail.com --investigate --depth 3 --save\n"
            "  exoosint --target +917051930965 --investigate --country IN --save\n"
            "  exoosint --target elonmusk --investigate --stealth\n"
            "  exoosint --targets-file targets.txt --investigate\n"
        ),
    )
    p.add_argument("--target", help="Single target (IP, domain, email, username, phone)")
    p.add_argument("--type", choices=VALID_TYPES, help="Force target type (auto-detect if omitted)")
    p.add_argument("--targets-file", help="File with list of targets (one per line, # for comments)")
    p.add_argument("--modules", default="all",
                   help="Comma-separated modules: ip,domain,email,username,phone,correlation,all")
    p.add_argument("--username-platforms", default="",
                   help="Comma-separated platform names to limit username hunt")
    p.add_argument("--report", default="",
                   help="Report formats — comma-separated subset of: html,json,csv")
    p.add_argument("--save", action="store_true", help="Save reports to a timestamped folder")
    p.add_argument("--output", choices=("table", "json"), default="table",
                   help="Stdout format (table is human readable; json is machine readable)")
    p.add_argument("--threads", type=int, default=20, help="Concurrent threads (default: 20)")
    p.add_argument("--timeout", type=int, default=10, help="Per-request timeout seconds (default: 10)")
    p.add_argument("--no-banner", action="store_true", help="Suppress the ASCII banner")
    p.add_argument("--version", action="version", version=f"EXO-OSINT v{__version__}")
    p.add_argument("--out-dir", default="exo_reports", help="Base directory for saved reports")
    p.add_argument("--country", default="IN", help="Default country/region for phone parsing")
    p.add_argument("--region", default=None, help="Alias for --country")
    p.add_argument("--depth", type=int, choices=[1, 2, 3], default=2,
                   help="Investigation depth — 1 fast, 2 standard, 3 deep")
    p.add_argument("--stealth", action="store_true",
                   help="Insert random delays between external requests")
    p.add_argument("--investigate", action="store_true",
                   help="Mega flag: run every relevant module + correlation + html+json + save")
    p.add_argument("--no-correlation", action="store_true",
                   help="Disable the correlation engine even with --investigate")
    return p


# ---------------------------------------------------------------------------
# Target loading
# ---------------------------------------------------------------------------

def _load_targets(args: argparse.Namespace) -> List[str]:
    """Collect targets from --target and/or --targets-file."""
    targets: List[str] = []
    if args.target:
        targets.append(args.target.strip())
    if args.targets_file:
        try:
            with open(args.targets_file, "r", encoding="utf-8") as f:
                for raw in f:
                    line = raw.strip()
                    if not line or line.startswith("#"):
                        continue
                    targets.append(line)
        except OSError as exc:
            ui.error(f"could not read targets file: {exc}")
    # de-duplicate while preserving order
    seen: set = set()
    deduped: List[str] = []
    for t in targets:
        if t and t not in seen:
            seen.add(t)
            deduped.append(t)
    return deduped


# ---------------------------------------------------------------------------
# Per-target dispatcher
# ---------------------------------------------------------------------------

def _wanted(modules: List[str], name: str) -> bool:
    return ("all" in modules) or (not modules) or (name in modules)


def _run_target(target: str, args: argparse.Namespace) -> TargetReport:
    forced = args.type
    ttype = forced or detect_type(target)
    ui.section(f"{target} [{ttype}] depth={args.depth}")
    tr = TargetReport(target=target, target_type=ttype)

    modules = [m.strip().lower() for m in args.modules.split(",") if m.strip()]
    region = args.region or args.country or "IN"

    try:
        if ttype == "ip" and _wanted(modules, "ip"):
            tr.modules.append(ip_mod.run(
                target, timeout=args.timeout, threads=args.threads, depth=args.depth,
            ))
        elif ttype == "domain" and _wanted(modules, "domain"):
            tr.modules.append(domain_mod.run(
                target, timeout=args.timeout, threads=args.threads, depth=args.depth,
            ))
        elif ttype == "email" and _wanted(modules, "email"):
            tr.modules.append(email_mod.run(
                target,
                timeout=args.timeout,
                threads=args.threads,
                run_domain_recon=_wanted(modules, "domain"),
                depth=args.depth,
            ))
        elif ttype == "username" and _wanted(modules, "username"):
            platforms = [p.strip() for p in (args.username_platforms or "").split(",") if p.strip()]
            tr.modules.append(username_mod.run(
                target,
                timeout=args.timeout,
                threads=args.threads,
                platforms=platforms or None,
                depth=args.depth,
            ))
        elif ttype == "phone" and _wanted(modules, "phone"):
            tr.modules.append(phone_mod.run(
                target, default_region=region, timeout=args.timeout, depth=args.depth,
            ))
    except Exception as exc:
        ui.error(f"primary module crashed: {exc}")
        m = ModuleResult(module=ttype, target=target, target_type=ttype)
        m.finish(success=False, error=str(exc))
        tr.modules.append(m)

    # ---------- Verdict line ----------
    risk = tr.risk_level()
    score = tr.footprint_score()
    line = f"{target} [{ttype}] -> risk={risk} score={score}/100"
    if risk in ("high", "critical"):
        ui.result_found("HIT", line)
    elif risk == "medium":
        ui.result_unknown("PARTIAL", line)
    else:
        ui.result_missing("CLEAN", line)

    tr.finish()
    return tr


# ---------------------------------------------------------------------------
# Reports
# ---------------------------------------------------------------------------

def _save_reports(inv: Investigation, args: argparse.Namespace) -> List[str]:
    formats = [r.strip().lower() for r in (args.report or "").split(",") if r.strip()]
    if not formats:
        return []
    timestamp = datetime.utcnow().strftime("%Y%m%d-%H%M%S")
    base_dir = os.path.join(args.out_dir, f"exo_{timestamp}") if args.save else "."
    os.makedirs(base_dir, exist_ok=True)
    written: List[str] = []
    if "html" in formats:
        path = os.path.join(base_dir, "report.html")
        report_mod.write_html(inv, path)
        ui.found(f"HTML report -> {path}")
        written.append(path)
    if "json" in formats:
        path = os.path.join(base_dir, "report.json")
        report_mod.write_json(inv, path)
        ui.found(f"JSON report -> {path}")
        written.append(path)
    if "csv" in formats:
        path = os.path.join(base_dir, "report.csv")
        report_mod.write_csv(inv, path)
        ui.found(f"CSV report -> {path}")
        written.append(path)
    return written


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------

def main(argv: Optional[List[str]] = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.stealth:
        ui.set_stealth(True)
        ui.info("stealth mode ON")

    if args.investigate:
        if args.modules == "all" or not args.modules:
            args.modules = "all"
        if not args.report:
            args.report = "html,json"
        args.save = True

    if not args.no_banner:
        ui.print_banner(version=__version__)

    targets = _load_targets(args)
    if not targets:
        ui.error("no target specified — use --target or --targets-file")
        parser.print_help(sys.stderr)
        return 2

    ui.info(f"loaded {len(targets)} target(s) | depth={args.depth} | threads={args.threads}")

    investigation = Investigation(version=__version__)
    try:
        for tgt in targets:
            tr = _run_target(tgt, args)
            investigation.targets.append(tr)
    except KeyboardInterrupt:
        ui.warn("interrupted by user")

    # Correlation engine
    modules_lower = [m.strip().lower() for m in args.modules.split(",")]
    want_correlation = (
        (args.investigate and not args.no_correlation)
        or "correlation" in modules_lower
    )
    if want_correlation and investigation.targets and not args.no_correlation:
        ui.section("CORRELATION ENGINE")
        try:
            corr_mod.correlate(
                investigation.targets,
                timeout=min(args.timeout, 8),
                threads=max(args.threads // 2, 6),
            )
        except Exception as exc:
            ui.error(f"correlation engine failed: {exc}")

    investigation.finish()
    _save_reports(investigation, args)

    if args.output == "json":
        sys.stdout.write(json.dumps(investigation.to_dict(), indent=2, default=str) + "\n")
    else:
        sys.stdout.write(report_mod.render_text(investigation) + "\n")
    sys.stdout.flush()

    # Final tagline
    s = investigation.summary or {}
    ui.info(
        f"done — {s.get('total_targets', 0)} target(s), "
        f"{s.get('total_findings', 0)} finding(s), "
        f"{s.get('total_correlations', 0)} correlation(s), "
        f"avg footprint {s.get('avg_footprint_score', 0)}/100"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
