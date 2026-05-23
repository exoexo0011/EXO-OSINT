"""Terminal UI: banner, colors, thread-safe progress bar."""

from __future__ import annotations

import sys
import threading
from typing import Optional

try:
    from colorama import Fore, Style, init as _colorama_init
    _colorama_init(autoreset=True)
    _HAS_COLOR = True
except Exception:  # pragma: no cover
    _HAS_COLOR = False

    class _Dummy:
        def __getattr__(self, _name: str) -> str:
            return ""

    Fore = _Dummy()  # type: ignore
    Style = _Dummy()  # type: ignore


# Purple-themed palette mapped onto colorama codes
PURPLE = Fore.MAGENTA
LIGHT_PURPLE = Fore.LIGHTMAGENTA_EX
TEAL = Fore.LIGHTCYAN_EX
RED = Fore.LIGHTRED_EX
YELLOW = Fore.LIGHTYELLOW_EX
WHITE = Fore.LIGHTWHITE_EX
DIM = Style.DIM
BRIGHT = Style.BRIGHT
RESET = Style.RESET_ALL


BANNER = r"""
███████╗██╗  ██╗ ██████╗        ██████╗ ███████╗██╗███╗   ██╗████████╗
██╔════╝╚██╗██╔╝██╔═══██╗      ██╔═══██╗██╔════╝██║████╗  ██║╚══██╔══╝
█████╗   ╚███╔╝ ██║   ██║█████╗██║   ██║███████╗██║██╔██╗ ██║   ██║   
██╔══╝   ██╔██╗ ██║   ██║╚════╝██║   ██║╚════██║██║██║╚██╗██║   ██║   
███████╗██╔╝ ██╗╚██████╔╝      ╚██████╔╝███████║██║██║ ╚████║   ██║   
╚══════╝╚═╝  ╚═╝ ╚═════╝        ╚═════╝ ╚══════╝╚═╝╚═╝  ╚═══╝   ╚═╝
"""

TAGLINE = "[ Open Source Intelligence Framework ]"
SUBTAGLINE = "// Authorized intelligence gathering only"


def print_banner(version: str = "1.0.0", stream=None) -> None:
    stream = stream or sys.stderr
    stream.write(f"{PURPLE}{BRIGHT}{BANNER}{RESET}\n")
    stream.write(f"{LIGHT_PURPLE}{BRIGHT}             {TAGLINE}{RESET}\n")
    stream.write(f"{DIM}{LIGHT_PURPLE}                  {SUBTAGLINE}{RESET}\n")
    stream.write(f"{DIM}{LIGHT_PURPLE}                       v{version}{RESET}\n\n")
    stream.flush()


# ---------------------------------------------------------------------------
# Logging helpers — all to stderr so stdout stays pipe-friendly
# ---------------------------------------------------------------------------

_log_lock = threading.Lock()


def _log(prefix_color: str, prefix: str, msg: str) -> None:
    with _log_lock:
        sys.stderr.write(f"{prefix_color}{BRIGHT}[{prefix}]{RESET} {msg}\n")
        sys.stderr.flush()


def info(msg: str) -> None:
    _log(LIGHT_PURPLE, "*", msg)


def found(msg: str) -> None:
    _log(TEAL, "+", msg)


def miss(msg: str) -> None:
    _log(RED, "-", msg)


def warn(msg: str) -> None:
    _log(YELLOW, "!", msg)


def error(msg: str) -> None:
    _log(RED, "x", msg)


def section(title: str) -> None:
    bar = "═" * (len(title) + 4)
    with _log_lock:
        sys.stderr.write(f"\n{PURPLE}{BRIGHT}╔{bar}╗{RESET}\n")
        sys.stderr.write(f"{PURPLE}{BRIGHT}║  {LIGHT_PURPLE}{title}{PURPLE}  ║{RESET}\n")
        sys.stderr.write(f"{PURPLE}{BRIGHT}╚{bar}╝{RESET}\n")
        sys.stderr.flush()


# ---------------------------------------------------------------------------
# Thread-safe progress bar
# ---------------------------------------------------------------------------

class ProgressBar:
    """A simple thread-safe progress bar that writes to stderr."""

    def __init__(self, total: int, label: str = "progress", width: int = 30) -> None:
        self.total = max(int(total), 1)
        self.label = label
        self.width = width
        self.current = 0
        self._lock = threading.Lock()
        self._enabled = sys.stderr.isatty()

    def tick(self, n: int = 1, note: Optional[str] = None) -> None:
        with self._lock:
            self.current = min(self.current + n, self.total)
            if not self._enabled:
                return
            pct = self.current / self.total
            filled = int(self.width * pct)
            bar = "█" * filled + "░" * (self.width - filled)
            tail = f"  {note}" if note else ""
            sys.stderr.write(
                f"\r{PURPLE}{BRIGHT}[{self.label}]{RESET} "
                f"{LIGHT_PURPLE}{bar}{RESET} "
                f"{self.current}/{self.total} ({pct * 100:5.1f}%){tail}     "
            )
            sys.stderr.flush()

    def close(self) -> None:
        with self._lock:
            if self._enabled:
                sys.stderr.write("\n")
                sys.stderr.flush()
