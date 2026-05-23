"""Data classes for EXO-OSINT results."""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import Any, Dict, List, Optional


TARGET_TYPES = ("ip", "domain", "email", "username", "phone")

SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


@dataclass
class Finding:
    """A single intelligence finding."""

    key: str
    value: Any
    severity: str = "info"  # info, low, medium, high, critical
    source: str = ""
    note: str = ""
    # Optional UI hints for the HTML report:
    profile_url: Optional[str] = None
    avatar_url: Optional[str] = None

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
    summary: str = ""  # one-line human summary for executive view

    def add(
        self,
        key: str,
        value: Any,
        severity: str = "info",
        source: str = "",
        note: str = "",
        profile_url: Optional[str] = None,
        avatar_url: Optional[str] = None,
    ) -> None:
        self.findings.append(
            Finding(
                key=key,
                value=value,
                severity=severity,
                source=source,
                note=note,
                profile_url=profile_url,
                avatar_url=avatar_url,
            )
        )

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
            "summary": self.summary,
            "data": self.data,
            "findings": [f.to_dict() for f in self.findings],
        }


@dataclass
class CorrelationLink:
    """A single derived/correlated identifier."""

    seed_target: str
    seed_type: str
    derived_value: str
    derived_type: str
    confidence: str = "low"  # low, medium, high
    confirmed: bool = False
    source: str = ""
    note: str = ""
    profile_url: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class TargetReport:
    """Aggregated report for a single target across all modules."""

    target: str
    target_type: str
    started_at: str = field(default_factory=lambda: datetime.utcnow().isoformat() + "Z")
    finished_at: str = ""
    modules: List[ModuleResult] = field(default_factory=list)
    correlations: List[CorrelationLink] = field(default_factory=list)

    def finish(self) -> None:
        self.finished_at = datetime.utcnow().isoformat() + "Z"

    def risk_level(self) -> str:
        worst = "info"
        for m in self.modules:
            for f in m.findings:
                if SEVERITY_ORDER.get(f.severity, 0) > SEVERITY_ORDER.get(worst, 0):
                    worst = f.severity
        return worst

    def footprint_score(self) -> int:
        """0-100 digital footprint score, computed from findings + diversity + correlations.

        Heuristic:
          - critical findings × 12
          - high findings × 8
          - medium findings × 4
          - low findings × 2
          - info findings × 0.5
          - unique source diversity × 3
          - confirmed correlations × 6
        Capped at 100.
        """
        weights = {"critical": 12, "high": 8, "medium": 4, "low": 2, "info": 0.5}
        score = 0.0
        sources = set()
        for m in self.modules:
            for f in m.findings:
                # Skip "unavailable" sentinels
                if isinstance(f.value, str) and f.value.lower() in ("unavailable", "rate_limited", "blocked"):
                    continue
                score += weights.get(f.severity, 0.5)
                if f.source:
                    sources.add(f.source)
        score += 3 * len(sources)
        score += 6 * sum(1 for c in self.correlations if c.confirmed)
        return min(100, int(round(score)))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target": self.target,
            "target_type": self.target_type,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "risk": self.risk_level(),
            "footprint_score": self.footprint_score(),
            "correlations": [c.to_dict() for c in self.correlations],
            "modules": [m.to_dict() for m in self.modules],
        }


@dataclass
class Investigation:
    """Top-level container for a full EXO-OSINT investigation run."""

    version: str = "2.0.0"
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
        sev_counts: Dict[str, int] = {"info": 0, "low": 0, "medium": 0, "high": 0, "critical": 0}
        for t in self.targets:
            r = t.risk_level()
            risk_counts[r] = risk_counts.get(r, 0) + 1
            for m in t.modules:
                for f in m.findings:
                    if f.severity in sev_counts:
                        sev_counts[f.severity] += 1
        avg_score = (
            int(sum(t.footprint_score() for t in self.targets) / len(self.targets))
            if self.targets else 0
        )
        return {
            "total_targets": len(self.targets),
            "total_findings": total_findings,
            "risk_breakdown": risk_counts,
            "severity_breakdown": sev_counts,
            "avg_footprint_score": avg_score,
            "total_correlations": sum(len(t.correlations) for t in self.targets),
        }

    def to_dict(self) -> Dict[str, Any]:
        return {
            "version": self.version,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "summary": self.summary,
            "targets": [t.to_dict() for t in self.targets],
        }
