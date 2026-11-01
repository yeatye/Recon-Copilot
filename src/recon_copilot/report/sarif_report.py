"""Export SARIF 2.1.0 (Static Analysis Results Interchange Format).

Format standard pour l'injection de findings dans GitHub Security, VS Code,
ou DefectDojo. SARIF a ete concu pour l'analyse statique de code (fichiers
+ lignes) -- un pentest reseau n'a pas de "fichier source", donc on utilise
la cible (IP/URL) comme `artifactLocation.uri`, convention courante des
outils DAST/pentest qui produisent du SARIF (ex: OWASP ZAP).

Structure validee contre le schema officiel OASIS (voir
tests/report/schemas/sarif-schema-2.1.0.json et
tests/report/test_sarif_report.py).
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from recon_copilot.report.models import ReportContext, ReportFinding

_SEVERITY_TO_SARIF_LEVEL = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}

# GitHub Security (et d'autres consommateurs SARIF) lisent cette propriete
# non-standard mais largement adoptee pour classer par score CVSS plutot
# que par le seul niveau error/warning/note.
_SEVERITY_TO_DEFAULT_SCORE = {
    "critical": 9.5,
    "high": 7.5,
    "medium": 5.0,
    "low": 2.5,
    "info": 0.0,
}


def _slugify(text: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")
    return slug or "finding"


def _rule_id(finding: ReportFinding) -> str:
    """CVE en priorite (identifiant stable et reconnu), sinon slug du titre."""
    if finding.cve_refs:
        return finding.cve_refs[0]
    return _slugify(finding.title)


def _build_rule(finding: ReportFinding) -> dict:
    security_severity = (
        finding.risk_score if finding.risk_score is not None else _SEVERITY_TO_DEFAULT_SCORE.get(finding.severity, 0.0)
    )
    tags = ["security", finding.severity] + list(finding.cwe_refs) + list(finding.mitre_refs)
    return {
        "id": _rule_id(finding),
        "name": finding.title,
        "shortDescription": {"text": finding.title},
        "fullDescription": {"text": finding.description or finding.title},
        "help": {"text": finding.remediation or "Aucune remediation renseignee."},
        "properties": {
            "security-severity": str(security_severity),
            "tags": tags,
        },
    }


def _build_result(finding: ReportFinding) -> dict:
    message_text = finding.description or finding.title
    if not finding.citation_verified:
        message_text += " [ATTENTION: citation non verifiee automatiquement contre les donnees sources]"

    properties = {
        "citation_verified": finding.citation_verified,
        "source_citation": finding.source_citation,
        "risk_score": finding.risk_score,
        "risk_level": finding.risk_level,
    }
    if finding.command_used:
        properties["command_used"] = finding.command_used

    return {
        "ruleId": _rule_id(finding),
        "level": _SEVERITY_TO_SARIF_LEVEL.get(finding.severity, "warning"),
        "message": {"text": message_text},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": f"target://{finding.target}"},
                }
            }
        ],
        "properties": properties,
    }


def build_sarif(context: ReportContext) -> dict:
    """Construit le document SARIF 2.1.0 complet (dict, a serialiser en JSON)."""
    findings = context.sorted_by_severity()

    # Une regle par finding logiquement distinct (deduplique par ruleId) --
    # deux findings identiques (meme CVE ou meme titre) partagent la meme
    # regle, comme le fait tout scanner SARIF standard (CodeQL, Semgrep...).
    rules_by_id: dict[str, dict] = {}
    for f in findings:
        rule_id = _rule_id(f)
        if rule_id not in rules_by_id:
            rules_by_id[rule_id] = _build_rule(f)

    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "recon-copilot",
                        "rules": list(rules_by_id.values()),
                    }
                },
                "results": [_build_result(f) for f in findings],
                "properties": {
                    "engagement": context.engagement,
                    "generated_at": context.generated_at,
                },
            }
        ],
    }


def save_sarif(context: ReportContext, output_path: str | Path) -> Path:
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(build_sarif(context), indent=2), encoding="utf-8")
    return path
