"""Adapter between the FastAPI layer and the existing `exoosint` engine.

The CLI already knows how to investigate a single target via
``cli._run_target(target, args)`` where ``args`` is an ``argparse.Namespace``.
Rather than re-implement that orchestration, we synthesise an equivalent
Namespace from an API request and reuse the exact same code path the CLI and
interactive menu rely on. This keeps the HTTP surface a thin wrapper and avoids
drift between interfaces.
"""

from __future__ import annotations

import argparse
import threading
from typing import Any, Dict, Optional

# `server/__init__.py` puts the repo root on sys.path, so these resolve.
from exoosint import __version__ as ENGINE_VERSION
from exoosint import cli as cli_mod
from exoosint import correlation as corr_mod
from exoosint import ui as exo_ui
from exoosint.cli import VALID_TYPES, detect_type  # noqa: F401  (re-exported)
from exoosint.types import Investigation, TargetReport

# `ui.set_stealth` flips a process-global flag, so guard mutation of it with a
# lock to keep concurrent requests from clobbering each other's setting.
_STEALTH_LOCK = threading.Lock()


def _build_args(
    *,
    target_type: Optional[str],
    depth: int,
    modules: str,
    timeout: int,
    threads: int,
    country: str,
    username_platforms: Optional[str],
    correlation: bool,
) -> argparse.Namespace:
    """Mirror the argparse defaults the CLI/menu produce, overriding per request."""
    return argparse.Namespace(
        target=None,
        type=target_type,
        targets_file=None,
        modules=modules or "all",
        username_platforms=username_platforms or "",
        report="",            # the API never writes report files to disk
        save=False,
        output="json",
        threads=threads,
        timeout=timeout,
        no_banner=True,
        out_dir="exo_reports",
        country=country,
        region=None,
        depth=depth,
        stealth=False,        # stealth handled explicitly below via ui.set_stealth
        investigate=True,
        no_correlation=not correlation,
    )


def detect_target_type(target: str) -> str:
    """Auto-detect the target type using the engine's own heuristic."""
    return detect_type(target.strip())


def investigate(
    *,
    target: str,
    target_type: Optional[str] = None,
    depth: int = 2,
    stealth: bool = False,
    modules: str = "all",
    correlation: bool = True,
    timeout: int = 10,
    threads: int = 20,
    country: str = "IN",
    username_platforms: Optional[str] = None,
) -> Dict[str, Any]:
    """Run a full single-target investigation and return the engine dict.

    This is a blocking, network-bound call. Callers in async request handlers
    should dispatch it to a threadpool.
    """
    target = target.strip()
    args = _build_args(
        target_type=target_type,
        depth=depth,
        modules=modules,
        timeout=timeout,
        threads=threads,
        country=country,
        username_platforms=username_platforms,
        correlation=correlation,
    )

    investigation = Investigation(version=ENGINE_VERSION)

    with _STEALTH_LOCK:
        previous_stealth = exo_ui.is_stealth()
        exo_ui.set_stealth(stealth)
        try:
            tr: TargetReport = cli_mod._run_target(target, args)
            investigation.targets.append(tr)

            if correlation:
                corr_mod.correlate(
                    investigation.targets,
                    timeout=min(timeout, 8),
                    threads=max(threads // 2, 6),
                )
        finally:
            exo_ui.set_stealth(previous_stealth)

    investigation.finish()
    return investigation.to_dict()
