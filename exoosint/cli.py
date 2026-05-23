"""Command-line interface for EXO-OSINT."""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from datetime import datetime
from typing import List, Optional

from . import __version__, ui
from . import ip as ip_mod
from . import domain as domain_mod
from . import email_recon as email_mod
from . import phone as phone_mod
from . import report as report_mod
from . import username as username_mod
from .types import Investigation, ModuleResult, TargetReport


VALID_TYPES = ("ip", "domain", "email", "username", "phone")
EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$")
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?!-)([A-Za-z0-9-]{1,63}(?<!-)\.)+[A-Za-z]{2,63}$")


def detect_type(target: str) -> str:
    """Auto-detect target type from input shape."""
    t = (target or "").strip()
    if not t:
        return "username"
    if ip_mod.is_valid_ip(t):
        return "ip"
    if EMAIL_RE.match(t):
        return "email"
    if t.startswith("+") or (t.replace(" ", "").replace("-", "").replace("(", "").replace(")", "").lstrip("+").isdigit() and len(re.sub(r"\D", "", t)) >= 7):
        return "phone"
    if DOMAIN_RE.match(t.replace("http://", "").replace("https://", "").rstrip("/")):
        return "domain"
    return "username"


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="exoosint",
        description="EXO-OSINT — Open Source Intelligence Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "examples:\n"
            "  exoosint --target 8.8.8.8\n"
            "  exoosint --target google.com --report html --save\n"
            "  exoosint --target user@gmail.com --report html --save\n"
            "  exoosint --target elonmusk --report html --save\n"
            "  exoosint --target +14155552671 --report html --save\n"
            "  exoosint --targets-file targets.txt --report html,json --save\n"
        ),
    )
    p.add_argument("--target", help="Single target (IP, domain, email, username, phone)")
    p.add_argument("--type", choices=VALID_TYPES, help="Force target type (auto-detect if omitted)")
    p.add_argument("--targets-file", help="File with list of targets (one per line)")
    p.add_argument("--modules", default="all", help="Comma-separated modules to run (default: all)")
    p.add_argument(
        "--username-platforms", default="",
        help="Comma-separated platforms to check for username (default: all)",
    )
    p.add_argument(
        "--report", default="",
        help="Report formats: html, json, csv, or combo like 'html,json'",
    )
    p.add_argument("--save", action="store_true", help="Save reports to a timestamped folder")
    p.add_argument("--output", choices=("table", "json"), default="table", help="Stdout format")
    p.add_argument("--threads", type=int, default=20, help="Concurrent threads (default: 20)")
    p.add_argument("--timeout", type=int, default=10, help="Per-request timeout seconds (default: 10)")
    p.add_argument("--no-banner", action="store_true", help="Suppress ASCII banner")
    p.add_argument("--version", action="version", version=f"EXO-OSINT v{__version__}")
    p.add_argument("--out-dir", default="exo_reports", help="Base directory for saved reports")
    p.add_argument("--region", default="US", help="Default region for phone parsing (default: US)")
    return p


def _load_targets(args: argparse.Namespace) -> List[str]:
    targets: List[str] = []
    if args.target:
        targets.append(args.target.strip())
    if args.targets_file:
        try:
            with open(args.targets_file, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        targets.append(line)
        except OSError as exc:
            ui.error(f"Could not read targets file: {exc}")
            sys.exit(2)
    return targets


def _run_target(target: str, args: argparse.Namespace) -> TargetReport:
    forced = args.type
    ttype = forced or detect_type(target)
    ui.section(f"{target}  [{ttype}]")

    tr = TargetReport(target=target, target_type=ttype)
    modules = [m.strip().lower() for m in args.modules.split(",") if m.strip()]
    run_all = "all" in modules or not modules

    try:
        if ttype == "ip":
            if run_all or "ip" in modules:
                tr.modules.append(ip_mod.run(target, timeout=args.timeout, threads=args.threads))
        elif ttype == "domain":
            if run_all or "domain" in modules:
                tr.modules.append(domain_mod.run(target, timeout=args.timeout, threads=args.threads))
        elif ttype == "email":
            if run_all or "email" in modules:
                tr.modules.append(email_mod.run(
                    target, timeout=args.timeout, threads=args.threads,
                    run_domain_recon=(run_all or "domain" in modules),
                ))
        elif ttype == "username":
            if run_all or "username" in modules:
                platforms = [p.strip() for p in (args.username_platforms or "").split(",") if p.strip()]
                tr.modules.append(username_mod.run(
                    target, timeout=args.timeout, threads=args.threads,
                    platforms=platforms or None,
                ))
        elif ttype == "phone":
            if run_all or "phone" in modules:
                tr.modules.append(phone_mod.run(target, default_region=args.region, timeout=args.timeout))
        else:
            ui.error(f"Unknown target type: {ttype}")
    except KeyboardInterrupt:
        raise
    except Exception as exc:
        ui.error(f"Module crashed: {exc}")
        m = ModuleResult(module=ttype, target=target, target_type=ttype)
        m.finish(success=False, error=str(exc))
        tr.modules.append(m)

    tr.finish()
    return tr


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
        ui.found(f"HTML report  -> {path}")
        written.append(path)
    if "json" in formats:
        path = os.path.join(base_dir, "report.json")
        report_mod.write_json(inv, path)
        ui.found(f"JSON report  -> {path}")
        written.append(path)
    if "csv" in formats:
        path = os.path.join(base_dir, "report.csv")
        report_mod.write_csv(inv, path)
        ui.found(f"CSV report   -> {path}")
        written.append(path)
    return written


def main(argv: Optional[List[str]] = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    if not args.no_banner:
        ui.print_banner(version=__version__)

    targets = _load_targets(args)
    if not targets:
        ui.error("No target specified. Use --target or --targets-file.")
        parser.print_help(sys.stderr)
        return 2

    investigation = Investigation(version=__version__)
    try:
        for tgt in targets:
            tr = _run_target(tgt, args)
            investigation.targets.append(tr)
    except KeyboardInterrupt:
        ui.warn("Interrupted by user.")
    investigation.finish()

    # Save reports if requested
    _save_reports(investigation, args)

    # stdout output
    if args.output == "json":
        sys.stdout.write(json.dumps(investigation.to_dict(), indent=2, default=str) + "\n")
    else:
        sys.stdout.write(report_mod.render_text(investigation) + "\n")
    sys.stdout.flush()
    return 0


if __name__ == "__main__":
    sys.exit(main())
