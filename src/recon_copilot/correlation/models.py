"""Modeles de donnees du module correlation.

`Finding.source_citation` est cense etre un extrait EXACT d'un
`source_fragment` (Nmap) ou `raw_line` (Nuclei) issu du module parser.
`citation_verified` n'est PAS une confiance aveugle dans le LLM : c'est
le resultat d'une verification programmatique (voir response_parser.py)
qui confirme que la citation existe reellement dans les donnees fournies
en entree. Un finding avec `citation_verified=False` est conserve (pas
jete) mais signale a l'analyste -- c'est a lui de trancher en revue.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Finding:
    title: str
    description: str
    severity: str  # info|low|medium|high|critical
    cvss_score: float | None
    confidence: str  # low|medium|high
    source_type: str  # 'nmap' | 'nuclei'
    source_citation: str
    citation_verified: bool
    cve_refs: tuple[str, ...]
    cwe_refs: tuple[str, ...]
    mitre_refs: tuple[str, ...]
    remediation: str


@dataclass(frozen=True)
class CorrelationResult:
    findings: tuple[Finding, ...]
    raw_llm_response: str
    warnings: tuple[str, ...]  # erreurs de parsing JSON, citations non verifiees, etc.
