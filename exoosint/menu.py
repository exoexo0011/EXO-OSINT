"""Interactive TUI menu for EXO-OSINT — built with the `rich` library.

Launched automatically when `python exoosint.py` is invoked with no
arguments. Preserves the legacy CLI behaviour for any explicit flag run.

Theme palette (matches the cyberpunk EXO-OSINT brand):
    neon green  #00ff41   primary / borders / banner
    cyan        #00cfff   info / accents
    red         #ff003c   high risk / errors
    yellow      #ffe600   warnings / medium risk
"""

from __future__ import annotations

import argparse
import os
import re
import sys
import threading
import time
import webbrowser
from collections import deque
from typing import Any, Deque, Dict, List, Optional

from rich.align import Align
from rich.box import DOUBLE, HEAVY, ROUNDED, SIMPLE_HEAVY
from rich.console import Console, Group
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeElapsedColumn,
)
from rich.prompt import Confirm, Prompt
from rich.spinner import Spinner
from rich.table import Table
from rich.text import Text

from . import __version__
from . import correlation as corr_mod
from . import ui as exo_ui
from .types import Investigation, ModuleResult, TargetReport


# ---------------------------------------------------------------------------
# Theme
# ---------------------------------------------------------------------------

GREEN = "#00ff41"
CYAN = "#00cfff"
RED = "#ff003c"
YELLOW = "#ffe600"
DIM = "grey50"

SEV_STYLE = {
    "info": CYAN,
    "low": GREEN,
    "medium": YELLOW,
    "high": RED,
    "critical": f"bold {RED}",
}

RISK_STYLE = {
    "info": GREEN,
    "low": GREEN,
    "medium": YELLOW,
    "high": RED,
    "critical": f"bold {RED}",
}

ANSI_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")


# ---------------------------------------------------------------------------
# Live findings tap: monkey-patches ModuleResult.add while a dashboard is
# active so individual findings stream into the dashboard in real time
# (instead of only appearing in one batch when the module returns).
# ---------------------------------------------------------------------------

_ACTIVE_DASHBOARD: Optional["LiveDashboard"] = None
_ORIGINAL_MODULE_ADD = ModuleResult.add


def _tapped_module_add(
    self: ModuleResult,
    key: str,
    value: Any,
    severity: str = "info",
    source: str = "",
    note: str = "",
    profile_url: Optional[str] = None,
    avatar_url: Optional[str] = None,
) -> None:
    _ORIGINAL_MODULE_ADD(
        self, key, value,
        severity=severity, source=source, note=note,
        profile_url=profile_url, avatar_url=avatar_url,
    )
    dash = _ACTIVE_DASHBOARD
    if dash is not None and self.findings:
        dash._on_finding(self.target, self.module, self.findings[-1])


def _install_finding_tap(dashboard: "LiveDashboard") -> None:
    global _ACTIVE_DASHBOARD
    _ACTIVE_DASHBOARD = dashboard
    ModuleResult.add = _tapped_module_add  # type: ignore[assignment]


def _uninstall_finding_tap() -> None:
    global _ACTIVE_DASHBOARD
    _ACTIVE_DASHBOARD = None
    ModuleResult.add = _ORIGINAL_MODULE_ADD  # type: ignore[assignment]


# ---------------------------------------------------------------------------
# Stderr capture so existing module logs flow into our live log panel
# ---------------------------------------------------------------------------

class _LogCapture:
    """A thread-safe stderr replacement that fans writes into a deque AND
    optionally a passthrough stream so the user still sees output in
    non-TTY runs (the rich Live panel handles TTY output)."""

    def __init__(self, lines: Deque[str], passthrough: bool = False) -> None:
        self._lines = lines
        self._buf = ""
        self._lock = threading.Lock()
        self._real_stderr = sys.__stderr__
        self._passthrough = passthrough

    def write(self, data: str) -> int:
        if not data:
            return 0
        with self._lock:
            self._buf += data
            while "\n" in self._buf:
                line, self._buf = self._buf.split("\n", 1)
                clean = ANSI_RE.sub("", line).rstrip("\r ").strip()
                if clean:
                    self._lines.append(clean)
            if self._passthrough:
                try:
                    self._real_stderr.write(data)
                except Exception:
                    pass
        return len(data)

    def flush(self) -> None:
        if self._passthrough:
            try:
                self._real_stderr.flush()
            except Exception:
                pass

    def isatty(self) -> bool:
        # Keeping False prevents existing ProgressBar from fighting our Live.
        return False


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _modules_for_type(ttype: str) -> str:
    return {
        "ip": "geo + asn + abuse + ports + dnsbl",
        "domain": "whois + dns + ssl + subdomains + headers",
        "email": "format + mx + breach + reputation + dorks",
        "username": "85+ platforms (concurrent)",
        "phone": "carrier + format + dorks + wa.me",
    }.get(ttype, "auto")


def _depth_label(d: int) -> str:
    return {1: "basic (1)", 2: "standard (2)", 3: "deep (3)"}.get(d, f"custom ({d})")


def _default_args() -> argparse.Namespace:
    """Mirror the argparse defaults from cli.py without re-parsing argv."""
    return argparse.Namespace(
        target=None,
        type=None,
        targets_file=None,
        modules="all",
        username_platforms="",
        report="html,json",
        save=True,
        output="table",
        threads=20,
        timeout=10,
        no_banner=True,
        out_dir="exo_reports",
        country="IN",
        region=None,
        depth=2,
        stealth=False,
        investigate=True,
        no_correlation=False,
    )


# ---------------------------------------------------------------------------
# Banner / Main menu
# ---------------------------------------------------------------------------

def _render_banner(console: Console) -> None:
    art = (
        "███████╗██╗  ██╗ ██████╗        ██████╗ ███████╗██╗███╗   ██╗████████╗\n"
        "██╔════╝╚██╗██╔╝██╔═══██╗      ██╔═══██╗██╔════╝██║████╗  ██║╚══██╔══╝\n"
        "█████╗   ╚███╔╝ ██║   ██║█████╗██║   ██║███████╗██║██╔██╗ ██║   ██║   \n"
        "██╔══╝   ██╔██╗ ██║   ██║╚════╝██║   ██║╚════██║██║██║╚██╗██║   ██║   \n"
        "███████╗██╔╝ ██╗╚██████╔╝      ╚██████╔╝███████║██║██║ ╚████║   ██║   \n"
        "╚══════╝╚═╝  ╚═╝ ╚═════╝        ╚═════╝ ╚══════╝╚═╝╚═╝  ╚═══╝   ╚═╝\n"
    )
    body = Text()
    body.append(art, style=f"bold {GREEN}")
    body.append("\n           [ Open Source Intelligence Framework ]\n",
                style=f"bold {CYAN}")
    body.append(f"                 // v{__version__}  //  Authorized use only\n",
                style=f"dim {GREEN}")
    console.print(Align.center(body))


MENU_ITEMS: List[Dict[str, str]] = [
    {"key": "1", "title": "IP Investigation",     "desc": "geo, ASN, abuse"},
    {"key": "2", "title": "Domain Recon",         "desc": "WHOIS, DNS, SSL"},
    {"key": "3", "title": "Email Investigation",  "desc": "breach, reputation"},
    {"key": "4", "title": "Username Hunt",        "desc": "85+ platforms"},
    {"key": "5", "title": "Phone Lookup",         "desc": "carrier, format"},
    {"key": "6", "title": "Full Investigation",   "desc": "all modules"},
    {"key": "7", "title": "Batch Scan",           "desc": "multiple targets"},
    {"key": "Q", "title": "Quit",                 "desc": ""},
]


def _render_main_menu(console: Console) -> None:
    table = Table.grid(padding=(0, 2))
    table.add_column(justify="right", style=f"bold {YELLOW}")
    table.add_column(style=f"bold {GREEN}")
    table.add_column(style=DIM)
    for item in MENU_ITEMS:
        table.add_row(f"[{item['key']}]", item["title"], f"— {item['desc']}" if item['desc'] else "")
    panel = Panel(
        Align.center(table),
        title=f"[bold {CYAN}]EXO OSINT  v{__version__}[/]",
        subtitle=f"[{DIM}]select an option[/]",
        border_style=GREEN,
        box=DOUBLE,
        padding=(1, 4),
    )
    console.print(panel)


# ---------------------------------------------------------------------------
# Live investigation dashboard
# ---------------------------------------------------------------------------

class LiveDashboard:
    """Renders a live `rich` dashboard while an investigation runs in a thread."""

    def __init__(
        self,
        console: Console,
        args: argparse.Namespace,
        targets: List[str],
    ) -> None:
        self.console = console
        self.args = args
        self.targets = targets
        self.investigation = Investigation(version=__version__)

        self._log_lines: Deque[str] = deque(maxlen=400)
        self._capture = _LogCapture(self._log_lines)
        self._current_target: Optional[str] = None
        self._current_module: Optional[str] = None
        self._current_index = 0
        self._done = False
        self._error: Optional[str] = None
        # Live finding stream: (target, module_name, Finding) tuples appended
        # via the ModuleResult.add monkey-patch installed by the tap.
        self._live_findings: List[Any] = []
        self._findings_lock = threading.Lock()

        self._progress = Progress(
            SpinnerColumn(style=GREEN),
            TextColumn("[bold {0}]{{task.description}}[/]".format(CYAN)),
            BarColumn(bar_width=None, complete_style=GREEN, finished_style=GREEN),
            TextColumn("{task.completed}/{task.total}"),
            TimeElapsedColumn(),
            expand=True,
        )
        self._overall_task = self._progress.add_task(
            "preparing investigation…", total=max(len(targets), 1)
        )

    # -- panels -----------------------------------------------------------

    def _on_finding(self, target: str, module: str, finding: Any) -> None:
        with self._findings_lock:
            self._live_findings.append((target, module, finding))

    def _findings_table(self) -> Table:
        tbl = Table(
            box=SIMPLE_HEAVY,
            border_style=GREEN,
            header_style=f"bold {CYAN}",
            expand=True,
            show_lines=False,
            pad_edge=False,
        )
        tbl.add_column("sev", width=8)
        tbl.add_column("target", width=22, overflow="fold")
        tbl.add_column("module", width=10)
        tbl.add_column("key", width=22, overflow="fold")
        tbl.add_column("value", overflow="fold", ratio=1)

        with self._findings_lock:
            recent = list(self._live_findings[-14:])

        # Show the most recent ~14 findings so users can watch them stream in.
        for target, module, f in recent:
            sev = (f.severity or "info").lower()
            style = SEV_STYLE.get(sev, CYAN)
            value = f.value
            if isinstance(value, (list, dict)):
                value = str(value)
            value = str(value)
            if len(value) > 80:
                value = value[:77] + "…"
            tbl.add_row(
                Text(sev.upper(), style=style),
                Text(target, style=GREEN),
                Text(module, style=CYAN),
                Text(str(f.key), style="white"),
                Text(value, style=style if sev in ("high", "critical") else "white"),
            )
        if not recent:
            tbl.add_row(
                Text("…", style=DIM),
                Text("(waiting)", style=DIM),
                "", "", Text("findings will appear here in real time", style=DIM),
            )
        return tbl

    def _log_panel(self) -> Panel:
        lines = list(self._log_lines)[-12:]
        if not lines:
            body: Any = Text("idle…", style=DIM)
        else:
            text = Text()
            for line in lines:
                style = CYAN
                low = line.lower()
                if "[+]" in line or "found" in low and "not" not in low:
                    style = GREEN
                elif "[-]" in line or "miss" in low:
                    style = RED
                elif "[!]" in line or "warn" in low:
                    style = YELLOW
                elif "[x]" in line or "error" in low or "failed" in low:
                    style = RED
                text.append(line + "\n", style=style)
            body = text
        return Panel(
            body,
            title=f"[bold {CYAN}]live log[/]",
            border_style=GREEN,
            box=ROUNDED,
            padding=(0, 1),
        )

    def _header(self) -> Panel:
        cur = self._current_target or "—"
        mod = self._current_module or "—"
        text = Text()
        text.append(" target: ", style=DIM)
        text.append(cur, style=f"bold {GREEN}")
        text.append("    module: ", style=DIM)
        text.append(mod, style=f"bold {CYAN}")
        text.append(f"    depth: {_depth_label(self.args.depth)}", style=DIM)
        if self.args.stealth:
            text.append("    stealth: ON", style=YELLOW)
        return Panel(
            text,
            title=f"[bold {GREEN}]EXO OSINT  ::  live investigation[/]",
            border_style=CYAN,
            box=HEAVY,
            padding=(0, 1),
        )

    def _build_layout(self) -> Layout:
        layout = Layout()
        layout.split_column(
            Layout(self._header(), name="header", size=3),
            Layout(self._progress, name="progress", size=3),
            Layout(name="body", ratio=1),
            Layout(self._log_panel(), name="log", size=14),
        )
        layout["body"].update(
            Panel(
                self._findings_table(),
                title=f"[bold {CYAN}]findings (live)[/]",
                border_style=GREEN,
                box=ROUNDED,
                padding=(0, 1),
            )
        )
        return layout

    # -- worker -----------------------------------------------------------

    def _worker(self) -> None:
        # Local import to avoid a circular import at module load time.
        from . import cli as cli_mod

        try:
            for idx, tgt in enumerate(self.targets, start=1):
                self._current_index = idx
                self._current_target = tgt
                forced = self.args.type
                ttype = forced or cli_mod.detect_type(tgt)
                self._current_module = ttype
                self._progress.update(
                    self._overall_task,
                    description=f"investigating {tgt} [{ttype}]",
                    completed=idx - 1,
                )
                tr = cli_mod._run_target(tgt, self.args)
                self.investigation.targets.append(tr)
                self._progress.update(self._overall_task, completed=idx)

            # Correlation
            if self.args.investigate and not self.args.no_correlation:
                self._current_module = "correlation"
                self._progress.update(
                    self._overall_task,
                    description="running correlation engine",
                )
                try:
                    corr_mod.correlate(
                        self.investigation.targets,
                        timeout=min(self.args.timeout, 8),
                        threads=max(self.args.threads // 2, 6),
                    )
                except Exception as exc:
                    self._error = f"correlation failed: {exc}"

            self.investigation.finish()
            self._progress.update(
                self._overall_task,
                description="investigation complete",
                completed=len(self.targets),
            )
        except Exception as exc:
            self._error = str(exc)
        finally:
            self._done = True

    # -- run --------------------------------------------------------------

    def run(self) -> Investigation:
        old_stderr = sys.stderr
        sys.stderr = self._capture  # type: ignore[assignment]
        _install_finding_tap(self)
        try:
            worker = threading.Thread(target=self._worker, daemon=True)
            with Live(
                self._build_layout(),
                console=self.console,
                refresh_per_second=8,
                screen=False,
                transient=False,
            ) as live:
                worker.start()
                while not self._done:
                    live.update(self._build_layout())
                    time.sleep(0.12)
                # Final paint
                live.update(self._build_layout())
        finally:
            _uninstall_finding_tap()
            sys.stderr = old_stderr

        if self._error:
            self.console.print(f"[bold {RED}]error:[/] {self._error}")
        return self.investigation


# ---------------------------------------------------------------------------
# Confirmation screen (Step 2)
# ---------------------------------------------------------------------------

def _confirmation_panel(
    console: Console,
    args: argparse.Namespace,
    target: str,
    ttype: str,
) -> bool:
    table = Table.grid(padding=(0, 2))
    table.add_column(style=DIM, justify="right")
    table.add_column(style=f"bold {GREEN}")

    rep = args.report or "(none)"
    save_loc = args.out_dir if args.save else "(not saved)"

    table.add_row("[*] Target:",  target)
    table.add_row("[*] Type:",    f"{ttype} {('(forced)' if args.type else '(auto-detected)')}")
    table.add_row("[*] Modules:", _modules_for_type(ttype))
    table.add_row("[*] Depth:",   _depth_label(args.depth))
    table.add_row("[*] Stealth:", "ON" if args.stealth else "off")
    table.add_row("[*] Correlate:", "off" if args.no_correlation else "on")
    table.add_row("[*] Report:",  f"{rep}  →  {save_loc}/")

    console.print(Panel(
        table,
        title=f"[bold {CYAN}]ready[/]",
        border_style=GREEN,
        box=DOUBLE,
        padding=(1, 3),
    ))
    return Confirm.ask(f"[bold {YELLOW}][?] Start investigation?[/]", default=True)


# ---------------------------------------------------------------------------
# Summary screen (Step 4)
# ---------------------------------------------------------------------------

_SEV_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def _top_findings(tr: TargetReport, limit: int = 3) -> List[Any]:
    pool: List[Any] = []
    for m in tr.modules:
        for f in m.findings:
            pool.append(f)
    pool.sort(key=lambda f: _SEV_RANK.get((f.severity or "info").lower(), 0), reverse=True)
    return pool[:limit]


def _show_summary(
    console: Console,
    investigation: Investigation,
    report_paths: List[str],
) -> Optional[str]:
    """Render the post-investigation summary panel + post-action menu.

    Returns the user's choice character ('1'..'4', 'q').
    """
    if not investigation.targets:
        console.print(f"[bold {RED}]no targets investigated[/]")
        return "q"

    tr = investigation.targets[0]
    s = investigation.summary or {}
    risk = tr.risk_level()
    risk_style = RISK_STYLE.get(risk, CYAN)

    html_path = next((p for p in report_paths if p.endswith(".html")), None)

    info = Table.grid(padding=(0, 2))
    info.add_column(style=DIM, justify="right")
    info.add_column(style=f"bold {GREEN}")
    info.add_row("Target:",      tr.target)
    info.add_row("Type:",        tr.target_type)
    info.add_row("Findings:",    str(s.get("total_findings", 0)))
    info.add_row("Risk level:",  Text(risk.upper(), style=risk_style))
    info.add_row("Footprint:",   f"{tr.footprint_score()}/100")
    info.add_row("Correlations:", str(s.get("total_correlations", 0)))
    if html_path:
        info.add_row("Report:", html_path)
    elif report_paths:
        info.add_row("Reports:", ", ".join(report_paths))
    else:
        info.add_row("Report:", "(not saved)")

    actions = Table.grid(padding=(0, 2))
    actions.add_column(style=f"bold {YELLOW}", justify="right")
    actions.add_column(style=f"bold {GREEN}")
    actions.add_row("[1]", "Investigate again (same target)")
    actions.add_row("[2]", "New target")
    actions.add_row("[3]", "Open report in browser")
    actions.add_row("[4]", "Run correlation on findings")
    actions.add_row("[Q]", "Quit")

    console.print(Panel(
        Group(info, Text(""), Text("─" * 48, style=DIM), Text(""), actions),
        title=f"[bold {GREEN}]INVESTIGATION COMPLETE[/]",
        border_style=GREEN,
        box=DOUBLE,
        padding=(1, 3),
    ))

    # Top 3 most interesting findings
    top = _top_findings(tr, 3)
    if top:
        ftbl = Table(
            box=ROUNDED, border_style=CYAN, header_style=f"bold {CYAN}",
            title=f"[bold {YELLOW}]Top 3 most interesting findings[/]",
        )
        ftbl.add_column("sev", width=10)
        ftbl.add_column("source", width=18)
        ftbl.add_column("key", width=24, overflow="fold")
        ftbl.add_column("value", overflow="fold")
        for f in top:
            sev = (f.severity or "info").lower()
            style = SEV_STYLE.get(sev, CYAN)
            value = f.value
            if isinstance(value, (list, dict)):
                value = str(value)
            value = str(value)
            if len(value) > 90:
                value = value[:87] + "…"
            ftbl.add_row(
                Text(sev.upper(), style=style),
                f.source or "—",
                str(f.key),
                Text(value, style=style if sev in ("high", "critical") else "white"),
            )
        console.print(ftbl)

    # Auto-open HTML report
    if html_path:
        try:
            abs_path = os.path.abspath(html_path)
            console.print(f"[{DIM}]opening report in browser…[/] [bold {CYAN}]{abs_path}[/]")
            webbrowser.open(f"file://{abs_path}")
        except Exception as exc:
            console.print(f"[{YELLOW}]could not auto-open report: {exc}[/]")

    choice = Prompt.ask(
        f"[bold {CYAN}][?] choose[/]",
        choices=["1", "2", "3", "4", "q", "Q"],
        default="2",
        show_choices=False,
    ).lower()
    return choice


# ---------------------------------------------------------------------------
# Per-option flows
# ---------------------------------------------------------------------------

def _ask_target(console: Console) -> Optional[str]:
    examples = Table.grid(padding=(0, 2))
    examples.add_column(style=DIM, justify="right")
    examples.add_column(style=f"bold {GREEN}")
    examples.add_row("IP:",       "8.8.8.8")
    examples.add_row("Domain:",   "google.com")
    examples.add_row("Email:",    "user@gmail.com")
    examples.add_row("Username:", "elonmusk")
    examples.add_row("Phone:",    "+919876543210")
    console.print(Panel(
        examples,
        title=f"[bold {CYAN}][?] Enter your target[/]",
        subtitle=f"[{DIM}]examples[/]",
        border_style=GREEN,
        box=ROUNDED,
        padding=(1, 3),
    ))
    target = Prompt.ask(f"[bold {YELLOW}]>[/]", default="").strip()
    if not target:
        console.print(f"[{YELLOW}]no target entered — back to main menu[/]")
        return None
    return target


def _quick_flow(
    console: Console,
    forced_type: Optional[str],
    extra_setup: Optional[Any] = None,
) -> str:
    """Common flow for menu items 1–5: ask target, confirm, run, summary.

    `extra_setup(args)` is called after defaults, before confirmation.
    Returns 'continue' to redraw main menu, or 'quit'.
    """
    target = _ask_target(console)
    if not target:
        return "continue"

    args = _default_args()
    args.target = target
    args.type = forced_type
    if extra_setup:
        extra_setup(args)

    # Lazy import to avoid circulars
    from .cli import detect_type
    ttype = forced_type or detect_type(target)
    if not _confirmation_panel(console, args, target, ttype):
        console.print(f"[{YELLOW}]cancelled[/]")
        return "continue"

    return _run_and_summarise(console, args, [target])


def _run_and_summarise(
    console: Console,
    args: argparse.Namespace,
    targets: List[str],
) -> str:
    from .cli import _save_reports

    dash = LiveDashboard(console, args, targets)
    investigation = dash.run()

    report_paths: List[str] = []
    if args.report:
        try:
            report_paths = _save_reports(investigation, args)
        except Exception as exc:
            console.print(f"[bold {RED}]could not save report:[/] {exc}")

    while True:
        choice = _show_summary(console, investigation, report_paths)
        if choice == "1":
            # Re-run on the same target list with the same args
            return _run_and_summarise(console, args, targets)
        if choice == "2":
            return "continue"
        if choice == "3":
            html_path = next((p for p in report_paths if p.endswith(".html")), None)
            if not html_path:
                console.print(f"[{YELLOW}]no HTML report saved this run.[/]")
                continue
            try:
                webbrowser.open(f"file://{os.path.abspath(html_path)}")
                console.print(f"[{GREEN}]opened {html_path}[/]")
            except Exception as exc:
                console.print(f"[{RED}]open failed: {exc}[/]")
            continue
        if choice == "4":
            console.print(f"[{CYAN}]re-running correlation engine…[/]")
            try:
                corr_mod.correlate(
                    investigation.targets,
                    timeout=min(args.timeout, 8),
                    threads=max(args.threads // 2, 6),
                )
                investigation.finish()
                console.print(f"[{GREEN}]correlation refreshed.[/]")
            except Exception as exc:
                console.print(f"[{RED}]correlation failed: {exc}[/]")
            continue
        return "quit"


# ---- Option 4: Username Hunt extras ---------------------------------------

def _ask_username_extras(args: argparse.Namespace) -> None:
    console = Console()
    console.print(
        Panel.fit(
            Text.from_markup(
                f"[bold {CYAN}]Depth?[/]\n"
                f"  [bold {YELLOW}][1][/] Fast      — top 20 platforms\n"
                f"  [bold {YELLOW}][2][/] Standard  — ~50 platforms\n"
                f"  [bold {YELLOW}][3][/] Deep      — full 85+ platforms\n"
            ),
            border_style=GREEN, box=ROUNDED, title=f"[bold {CYAN}]Username Hunt — depth[/]",
        )
    )
    depth = Prompt.ask(f"[bold {YELLOW}]>[/]", choices=["1", "2", "3"], default="2")
    args.depth = int(depth)

    console.print(
        Panel.fit(
            Text.from_markup(
                f"[bold {CYAN}]Filter by category?[/]\n"
                f"  [bold {YELLOW}][1][/] All\n"
                f"  [bold {YELLOW}][2][/] Social\n"
                f"  [bold {YELLOW}][3][/] Gaming\n"
                f"  [bold {YELLOW}][4][/] Professional\n"
                f"  [bold {YELLOW}][5][/] Creative\n"
            ),
            border_style=GREEN, box=ROUNDED, title=f"[bold {CYAN}]Username Hunt — category[/]",
        )
    )
    cat_choice = Prompt.ask(f"[bold {YELLOW}]>[/]", choices=["1", "2", "3", "4", "5"], default="1")
    cat_map = {"2": "social", "3": "gaming", "4": "professional", "5": "creative"}
    if cat_choice in cat_map:
        from .username import PLATFORMS
        wanted_cat = cat_map[cat_choice]
        names = [
            n for n, c in PLATFORMS.items()
            if c.get("category", "").lower() == wanted_cat
        ]
        if names:
            args.username_platforms = ",".join(names)


# ---- Option 6: Full Investigation -----------------------------------------

def _ask_full_extras(args: argparse.Namespace) -> None:
    console = Console()
    depth = Prompt.ask(
        f"[bold {CYAN}][?] Depth?[/] [{DIM}][1] Basic  [2] Standard  [3] Deep[/]",
        choices=["1", "2", "3"], default="2",
    )
    args.depth = int(depth)

    args.stealth = Confirm.ask(
        f"[bold {CYAN}][?] Enable stealth mode?[/] [{DIM}](random delays)[/]",
        default=False,
    )

    correlate_on = Confirm.ask(
        f"[bold {CYAN}][?] Enable correlation engine?[/]",
        default=True,
    )
    args.no_correlation = not correlate_on

    rep = Prompt.ask(
        f"[bold {CYAN}][?] Save report?[/] "
        f"[{DIM}][1] HTML  [2] JSON  [3] CSV  [4] All  [5] No[/]",
        choices=["1", "2", "3", "4", "5"], default="4",
    )
    rep_map = {
        "1": ("html", True),
        "2": ("json", True),
        "3": ("csv",  True),
        "4": ("html,json,csv", True),
        "5": ("", False),
    }
    args.report, args.save = rep_map[rep]


# ---- Option 7: Batch Scan -------------------------------------------------

def _option_batch(console: Console) -> str:
    args = _default_args()
    mode = Prompt.ask(
        f"[bold {CYAN}][?] Source?[/] [{DIM}][1] file  [2] type targets one by one[/]",
        choices=["1", "2"], default="2",
    )
    targets: List[str] = []
    if mode == "1":
        path = Prompt.ask(f"[bold {YELLOW}]> path to targets file[/]").strip()
        if not path or not os.path.exists(path):
            console.print(f"[{RED}]file not found[/]")
            return "continue"
        try:
            with open(path, "r", encoding="utf-8") as f:
                for raw in f:
                    line = raw.strip()
                    if line and not line.startswith("#"):
                        targets.append(line)
        except OSError as exc:
            console.print(f"[{RED}]could not read: {exc}[/]")
            return "continue"
    else:
        console.print(
            f"[{DIM}]Enter one target per line. Type[/] "
            f"[bold {GREEN}]done[/] [{DIM}]when finished.[/]"
        )
        while True:
            line = Prompt.ask(f"[bold {YELLOW}]target[/]", default="done").strip()
            if not line or line.lower() == "done":
                break
            targets.append(line)
    if not targets:
        console.print(f"[{YELLOW}]no targets entered[/]")
        return "continue"

    console.print(f"[{CYAN}]loaded {len(targets)} target(s)[/]")
    if not _confirmation_panel(
        console, args, f"{len(targets)} target(s)", "batch"
    ):
        return "continue"
    return _run_and_summarise(console, args, targets)


# ---------------------------------------------------------------------------
# Main loop
# ---------------------------------------------------------------------------

def run() -> int:
    """Entry-point used when `python exoosint.py` runs with no arguments."""
    console = Console()

    while True:
        console.clear()
        _render_banner(console)
        _render_main_menu(console)
        choice = Prompt.ask(
            f"[bold {YELLOW}]>[/]",
            choices=["1", "2", "3", "4", "5", "6", "7", "q", "Q"],
            default="6",
            show_choices=False,
        ).lower()

        try:
            if choice == "1":
                outcome = _quick_flow(console, "ip")
            elif choice == "2":
                outcome = _quick_flow(console, "domain")
            elif choice == "3":
                outcome = _quick_flow(console, "email")
            elif choice == "4":
                outcome = _quick_flow(console, "username", extra_setup=_ask_username_extras)
            elif choice == "5":
                outcome = _quick_flow(console, "phone")
            elif choice == "6":
                outcome = _quick_flow(console, None, extra_setup=_ask_full_extras)
            elif choice == "7":
                outcome = _option_batch(console)
            else:
                console.print(f"[bold {GREEN}]bye.[/]")
                return 0
        except KeyboardInterrupt:
            console.print(f"\n[{YELLOW}]interrupted — back to menu[/]")
            outcome = "continue"
        except Exception as exc:
            console.print(f"[bold {RED}]menu error:[/] {exc}")
            outcome = "continue"

        if outcome == "quit":
            console.print(f"[bold {GREEN}]bye.[/]")
            return 0

        # small pause so the user can read the post-flow message
        try:
            Prompt.ask(
                f"[{DIM}]press enter to return to main menu[/]",
                default="",
                show_default=False,
            )
        except KeyboardInterrupt:
            return 0
