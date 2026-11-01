"""Modeles de donnees du module report."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class ReportFinding:
    target: str
    title: str
    description: str
    severity: str
    risk_score: float | None
    risk_level: str | None
    remediation: str
    cve_refs: tuple[str, ...]
    cwe_refs: tuple[str, ...]
    mitre_refs: tuple[str, ...]
    source_citation: str
    citation_verified: bool
    command_used: str | None = None  # commande exacte (nmap/nuclei/ffuf) qui a produit la detection source


_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


@dataclass(frozen=True)
class ReportContext:
    engagement: str
    generated_at: str
    findings: tuple[ReportFinding, ...] = field(default_factory=tuple)
    scope_allowed_targets: tuple[str, ...] = field(default_factory=tuple)
    scope_excluded_targets: tuple[str, ...] = field(default_factory=tuple)

    def sorted_by_severity(self) -> tuple[ReportFinding, ...]:
        return tuple(sorted(self.findings, key=lambda f: _SEVERITY_ORDER.get(f.severity, 99)))

    def counts_by_severity(self) -> dict[str, int]:
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in self.findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        return counts
