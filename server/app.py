"""EXO-OSINT FastAPI backend — Phase 1.

A thin, well-typed HTTP layer over the existing `exoosint` engine. Run with:

    uvicorn server.app:app --reload --port 8000      # from the repo root

Interactive docs are served at /docs (Swagger) and /redoc.
"""

from __future__ import annotations

import logging

from fastapi import FastAPI, HTTPException
from fastapi.concurrency import run_in_threadpool
from fastapi.middleware.cors import CORSMiddleware

from . import __version__ as API_VERSION
from . import engine
from .models import (
    DetectRequest,
    DetectResponse,
    HealthResponse,
    InvestigateRequest,
    InvestigateResponse,
    ModulesResponse,
    VersionResponse,
)

try:
    from exoosint import __author__ as ENGINE_AUTHOR
    from exoosint import __license__ as ENGINE_LICENSE
except Exception:  # pragma: no cover - defensive only
    ENGINE_AUTHOR = "unknown"
    ENGINE_LICENSE = "unknown"

logger = logging.getLogger("exoosint.server")

MODULE_NAMES = ["ip", "domain", "email", "username", "phone", "correlation"]

app = FastAPI(
    title="EXO-OSINT API",
    description="HTTP backend for the EXO-OSINT intelligence framework (Phase 1).",
    version=API_VERSION,
)

# Permissive CORS so a future frontend (any dev origin) can call the API.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/", tags=["meta"])
async def root() -> dict:
    """Landing payload pointing clients at the docs and key endpoints."""
    return {
        "name": "EXO-OSINT API",
        "api_version": API_VERSION,
        "engine_version": engine.ENGINE_VERSION,
        "docs": "/docs",
        "endpoints": [
            "/api/health",
            "/api/version",
            "/api/modules",
            "/api/detect",
            "/api/investigate",
        ],
    }


@app.get("/api/health", response_model=HealthResponse, tags=["meta"])
async def health() -> HealthResponse:
    return HealthResponse(
        status="ok",
        api_version=API_VERSION,
        engine_version=engine.ENGINE_VERSION,
    )


@app.get("/api/version", response_model=VersionResponse, tags=["meta"])
async def version() -> VersionResponse:
    return VersionResponse(
        name="EXO-OSINT",
        api_version=API_VERSION,
        engine_version=engine.ENGINE_VERSION,
        author=ENGINE_AUTHOR,
        license=ENGINE_LICENSE,
    )


@app.get("/api/modules", response_model=ModulesResponse, tags=["meta"])
async def modules() -> ModulesResponse:
    return ModulesResponse(
        modules=MODULE_NAMES,
        target_types=list(engine.VALID_TYPES),
    )


@app.post("/api/detect", response_model=DetectResponse, tags=["osint"])
async def detect(req: DetectRequest) -> DetectResponse:
    """Auto-detect the type of a target without running any network probes."""
    target_type = engine.detect_target_type(req.target)
    return DetectResponse(target=req.target.strip(), target_type=target_type)


@app.post("/api/investigate", response_model=InvestigateResponse, tags=["osint"])
async def investigate(req: InvestigateRequest) -> InvestigateResponse:
    """Run a full single-target investigation.

    This is network-bound and can take from a few seconds (IP/phone) to a
    minute or more (deep username/domain sweeps). The blocking engine call is
    dispatched to a threadpool so the event loop stays responsive.
    """
    try:
        result = await run_in_threadpool(
            engine.investigate,
            target=req.target,
            target_type=req.type,
            depth=req.depth,
            stealth=req.stealth,
            modules=req.modules,
            correlation=req.correlation,
            timeout=req.timeout,
            threads=req.threads,
            country=req.country,
            username_platforms=req.username_platforms,
        )
    except Exception as exc:  # surface engine failures as 500s with context
        logger.exception("investigation failed for target=%r", req.target)
        raise HTTPException(status_code=500, detail=f"investigation failed: {exc}") from exc

    return InvestigateResponse(investigation=result)
