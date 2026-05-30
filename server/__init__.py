"""EXO-OSINT FastAPI backend (Phase 1).

A thin HTTP layer over the existing `exoosint` engine. The package adds the
repository root to ``sys.path`` on import so ``import exoosint`` works no
matter which directory uvicorn is launched from.
"""

from __future__ import annotations

import os
import sys

# Make the sibling `exoosint` package importable regardless of CWD.
_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

__all__ = ["__version__"]
__version__ = "0.1.0"
