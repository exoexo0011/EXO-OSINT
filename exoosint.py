#!/usr/bin/env python3
"""EXO-OSINT main entry point.

Usage:
  python exoosint.py                 # launches interactive TUI menu
  python exoosint.py --target ...    # classic CLI mode (unchanged)
  python exoosint.py --help
"""

from __future__ import annotations

import sys


def _has_real_args(argv) -> bool:
    """Return True if any meaningful flag/arg was passed on the command line.

    We deliberately treat the no-args case (just the script name) as the
    signal to drop into the interactive menu. Anything else is forwarded to
    the existing argparse-based CLI so old workflows behave identically.
    """
    return len(argv) > 1


if __name__ == "__main__":
    if _has_real_args(sys.argv):
        from exoosint.cli import main
        sys.exit(main())
    else:
        try:
            from exoosint.menu import run as menu_run
        except ImportError as exc:
            sys.stderr.write(
                f"[!] interactive menu unavailable ({exc}); falling back to --help\n"
                "    install dependencies with: pip install -r requirements.txt\n\n"
            )
            from exoosint.cli import main
            sys.exit(main(["--help"]))
        sys.exit(menu_run())
