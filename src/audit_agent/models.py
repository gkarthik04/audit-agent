"""Core data types shared by every layer. No logic beyond ordering and serialisation."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        """Numeric order (info=0 ... critical=4). Compare ranks, never the string values."""
        return _SEVERITY_ORDER.index(self)


_SEVERITY_ORDER = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]


class Category(str, Enum):
    SECURITY = "security"
    SLOP = "slop"
    GAP = "gap"


@dataclass(frozen=True)
class Finding:
    rule_id: str
    title: str
    severity: Severity
    category: Category
    message: str
    path: str  # POSIX path relative to the scan root ("." for repo-level findings)
    line: int = 0  # 1-based; 0 means "whole file / whole repo"
    snippet: str = ""
    note: str = ""  # optional explanation added by the LLM triage pass

    @property
    def location(self) -> str:
        return f"{self.path}:{self.line}" if self.line else self.path

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["severity"] = self.severity.value
        data["category"] = self.category.value
        return data


@dataclass
class ScanResult:
    root: str
    files_scanned: int
    findings: list[Finding]
    rules_run: int = 0
    dismissed: list[Finding] = field(default_factory=list)  # false positives removed by LLM
    summary: str = ""  # prioritised summary written by the LLM pass, if it ran
    llm_used: bool = False

    def counts(self) -> dict[str, int]:
        out = {s.value: 0 for s in reversed(_SEVERITY_ORDER)}
        for f in self.findings:
            out[f.severity.value] += 1
        return out

    def by_category(self) -> dict[str, int]:
        out = {c.value: 0 for c in Category}
        for f in self.findings:
            out[f.category.value] += 1
        return out

    def max_severity(self) -> Severity | None:
        return max((f.severity for f in self.findings), key=lambda s: s.rank, default=None)
