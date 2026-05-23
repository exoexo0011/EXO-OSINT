"""Data classes for EXO-OSINT results."""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import Any, Dict, List, Optional


TARGET_TYPES = ("ip", "domain", "email", "username", "phone")


@dataclass
class Finding:
    """A single intelligence finding."""

    key: str
    value: Any
    severity: str = "info"  # info, low, medium, high, critical
    source: str = ""
    note: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ModuleResult:
    """Result of running a single module against a target."""

    module: str
    target: str
    target_type: str
    started_at: str = field(default_factory=lambda: datetime.utcnow().isoformat() + "Z")
    finished_at: str = ""
    success: bool = True
    error: Optional[str] = None
    data: Dict[str, Any] = field(default_factory=dict)
    findings: List[Finding] = field(default_factory=list)

    def add(self, key: str, value: Any, severity: str = "info", source: str = "", note: str = "") -> None:
        self.findings.append(Finding(key=key, value=value, severity=severity, source=source, note=note))

    def finish(self, success: bool = True, error: Optional[str] = None) -> None:
        self.finished_at = datetime.utcnow().isoformat() + "Z"
        self.success = success
        if error:
            self.error = error

    def to_dict(self) -> Dict[str, Any]:
        return {
            "module": self.module,
            "target": self.target,
            "target_type": self.target_type,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "success": self.success,
            "error": self.error,
            "data": self.data,
            "findings": [f.to_dict() for f in self.findings],
        }


@dataclass
class TargetReport:
    """Aggregated report for a single target across all modules."""

    target: str
    target_type: str
    started_at: str = field(default_factory=lambda: datetime.utcnow().isoformat() + "Z")
    finished_at: str = ""
    modules: List[ModuleResult] = field(default_factory=list)

    def finish(self) -> None:
        self.finished_at = datetime.utcnow().isoformat() + "Z"

    def risk_level(self) -> str:
        """Roll up severity across modules."""
        order = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
        worst = "info"
        for m in self.modules:
            for f in m.findings:
                if order.get(f.severity, 0) > order.get(worst, 0):
                    worst = f.severity
        return worst

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target": self.target,
            "target_type": self.target_type,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "risk": self.risk_level(),
            "modules": [m.to_dict() for m in self.modules],
        }


@dataclass
class Investigation:
    """Top-level container for a full EXO-OSINT investigation run."""

    version: str = "1.0.0"
    started_at: str = field(default_factory=lambda: datetime.utcnow().isoformat() + "Z")
    finished_at: str = ""
    targets: List[TargetReport] = field(default_factory=list)
    summary: Dict[str, Any] = field(default_factory=dict)

    def finish(self) -> None:
        self.finished_at = datetime.utcnow().isoformat() + "Z"
        self.summary = self._build_summary()

    def _build_summary(self) -> Dict[str, Any]:
        total_findings = sum(len(m.findings) for t in self.targets for m in t.modules)
        risk_counts: Dict[str, int] = {}
        for t in self.targets:
            r = t.risk_level()
            risk_counts[r] = risk_counts.get(r, 0) + 1
        return {
            "total_targets": len(self.targets),
            "total_findings": total_findings,
            "risk_breakdown": risk_counts,
        }

    def to_dict(self) -> Dict[str, Any]:
        return {
            "version": self.version,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "summary": self.summary,
            "targets": [t.to_dict() for t in self.targets],
        }
