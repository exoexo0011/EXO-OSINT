#!/usr/bin/env python3
"""EXO-OSINT main entry point.

Run: python exoosint.py --help
"""

from __future__ import annotations

import sys

from exoosint.cli import main


if __name__ == "__main__":
    sys.exit(main())
