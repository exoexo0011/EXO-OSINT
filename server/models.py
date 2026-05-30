"""Pydantic request/response models for the EXO-OSINT API."""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field, field_validator

VALID_TYPES = ("ip", "domain", "email", "username", "phone")


class DetectRequest(BaseModel):
    """Request body for target-type auto-detection."""

    target: str = Field(..., min_length=1, description="Target to classify")


class DetectResponse(BaseModel):
    target: str
    target_type: str


class InvestigateRequest(BaseModel):
    """Request body for running an investigation against a single target."""

    target: str = Field(..., min_length=1, description="IP, domain, email, username or phone")
    type: Optional[str] = Field(
        default=None,
        description="Force the target type. Auto-detected when omitted.",
    )
    depth: int = Field(default=2, ge=1, le=3, description="1=fast, 2=standard, 3=deep")
    stealth: bool = Field(default=False, description="Insert random delays between requests")
    modules: str = Field(default="all", description="Comma-separated modules or 'all'")
    correlation: bool = Field(default=True, description="Run the correlation engine")
    timeout: int = Field(default=10, ge=1, le=120, description="Per-request timeout (seconds)")
    threads: int = Field(default=20, ge=1, le=100, description="Concurrent worker threads")
    country: str = Field(default="IN", description="Default region for phone parsing")
    username_platforms: Optional[str] = Field(
        default=None, description="Comma-separated platform names to limit username hunt"
    )

    @field_validator("type")
    @classmethod
    def _validate_type(cls, v: Optional[str]) -> Optional[str]:
        if v is None or v == "":
            return None
        v = v.strip().lower()
        if v not in VALID_TYPES:
            raise ValueError(f"type must be one of {VALID_TYPES}")
        return v

    @field_validator("country")
    @classmethod
    def _normalize_country(cls, v: str) -> str:
        return (v or "IN").strip().upper() or "IN"


class HealthResponse(BaseModel):
    status: str
    api_version: str
    engine_version: str


class VersionResponse(BaseModel):
    name: str
    api_version: str
    engine_version: str
    author: str
    license: str


class ModulesResponse(BaseModel):
    modules: List[str]
    target_types: List[str]


class InvestigateResponse(BaseModel):
    """The investigation result is the engine's native dict structure."""

    investigation: Dict[str, Any]
