"""Shared result types."""

from __future__ import annotations

import datetime as _dt
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional, Tuple

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


@dataclass
class Finding:
    id: str
    title: str
    severity: str
    category: str
    detail: str
    evidence: str = ""
    remediation: str = ""
    references: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class EvidenceItem:
    """One observed HTTP interaction, kept so reports are auditable."""

    label: str
    url: str
    status: Optional[int] = None
    headers: Dict[str, str] = field(default_factory=dict)
    note: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ScanResult:
    target: str
    started_at: str = field(
        default_factory=lambda: _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds")
    )
    resolved_ip: Optional[str] = None
    is_php: bool = False
    php_confidence: int = 0
    php_version: Optional[Tuple[int, int, int]] = None
    version_source: str = ""
    server_software: str = ""
    sapi: str = ""
    cms: str = ""
    cms_version: str = ""
    status: str = "UNKNOWN"          # VULNERABLE | PATCHED | UNKNOWN
    status_reason: str = ""
    findings: List[Finding] = field(default_factory=list)
    evidence: List[EvidenceItem] = field(default_factory=list)
    probes_run: int = 0
    notes: List[str] = field(default_factory=list)

    # -- helpers ----------------------------------------------------------
    @property
    def verdict(self) -> str:
        if not self.is_php:
            return "NOT_PHP"
        return self.status

    @property
    def risk_score(self) -> int:
        """0-100, used for the summary banner and report sorting."""
        if not self.is_php:
            return 0
        base = {"VULNERABLE": 95, "UNKNOWN": 55, "PATCHED": 15}.get(self.status, 40)
        for f in self.findings:
            if f.severity == "CRITICAL" and f.id.startswith("PHP2SHELL"):
                base = max(base, 95)
            elif f.severity == "HIGH":
                base = min(100, base + 5)
        return base

    def sorted_findings(self) -> List[Finding]:
        return sorted(self.findings, key=lambda f: SEVERITY_ORDER.get(f.severity, 9))

    def add(self, finding: Finding) -> None:
        self.findings.append(finding)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["php_version"] = (
            ".".join(str(p) for p in self.php_version) if self.php_version else None
        )
        d["verdict"] = self.verdict
        d["risk_score"] = self.risk_score
        return d


@dataclass
class CodebaseFix:
    """A proposed change to a file in the user's code base."""

    path: str
    reason: str
    original: str
    patched: str
    source: str = "rules"      # "rules" (deterministic) or "llm"
    applied: bool = False
    backup: Optional[str] = None

    @property
    def changed(self) -> bool:
        return self.original != self.patched
