"""Export CycloneDX VEX (Vulnerability Exploitability eXchange), format
JSON base sur le schema CycloneDX 1.5.

Le CycloneDX VEX est concu pour communiquer le statut de vulnerabilites
associees a des COMPOSANTS logiciels (bibliotheques, paquets). Un pentest
reseau n'a pas de composants au sens SBOM -- on modelise chaque cible
scannee comme un composant synthetique de type "application", ce qui
reste dans le schema (`component.type`/`component.name` sont les seuls
champs requis).

Chaque finding devient une entree `vulnerabilities[]` avec
`analysis.state = "exploitable"` : seuls les findings 'accepted'/'edited'
atteignent le rapport (voir report/data.py), donc chaque finding present
ici a deja ete valide par un analyste humain -- "exploitable" est le
statut correct, pas "in_triage".

Structure validee contre le schema officiel CycloneDX (voir
tests/report/schemas/cyclonedx-bom-1.5.schema.json et
tests/report/test_vex_report.py).
"""

from __future__ import annotations

import json
import uuid
from pathlib import Path

from recon_copilot.report.models import ReportContext, ReportFinding


def _component_bom_ref(target: str) -> str:
    return f"target:{target}"


def _build_component(target: str) -> dict:
    return {
        "type": "application",
        "bom-ref": _component_bom_ref(target),
        "name": target,
    }


def _build_vulnerability(finding: ReportFinding, index: int) -> dict:
    vuln_id = finding.cve_refs[0] if finding.cve_refs else f"RECON-COPILOT-{index}"

    rating = {
        "source": {"name": "recon-copilot"},
        "severity": finding.severity if finding.severity in ("critical", "high", "medium", "low", "info") else "unknown",
    }
    if finding.risk_score is not None:
        rating["score"] = finding.risk_score
        rating["method"] = "other"  # notre score composite n'est pas un CVSS standard -- voir scoring/

    analysis_detail = f"Constat valide par revue humaine. Preuve : {finding.source_citation}"
    if not finding.citation_verified:
        analysis_detail += " [ATTENTION: citation non verifiee automatiquement contre les donnees sources]"

    return {
        "bom-ref": f"vuln:{index}",
        "id": vuln_id,
        "source": {"name": "recon-copilot"},
        "ratings": [rating],
        "cwes": [int(c.split("-")[-1]) for c in finding.cwe_refs if c.upper().startswith("CWE-") and c.split("-")[-1].isdigit()],
        "description": finding.description or finding.title,
        "recommendation": finding.remediation or None,
        "analysis": {
            "state": "exploitable",
            "detail": analysis_detail,
        },
        "affects": [{"ref": _component_bom_ref(finding.target)}],
    }


def build_vex(context: ReportContext) -> dict:
    """Construit le document CycloneDX VEX complet (dict, a serialiser en JSON)."""
    findings = context.sorted_by_severity()
    targets = sorted({f.target for f in findings})

    doc = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": context.generated_at,
            "component": {
                "type": "application",
                "bom-ref": "engagement",
                "name": context.engagement,
            },
        },
        "components": [_build_component(t) for t in targets],
        "vulnerabilities": [_build_vulnerability(f, i) for i, f in enumerate(findings, start=1)],
    }

    # Nettoie les cles a None (recommendation absente, etc.) -- CycloneDX
    # les accepte absentes mais pas explicitement null.
    for vuln in doc["vulnerabilities"]:
        for key in list(vuln.keys()):
            if vuln[key] is None:
                del vuln[key]
        if not vuln.get("cwes"):
            vuln.pop("cwes", None)

    return doc


def save_vex(context: ReportContext, output_path: str | Path) -> Path:
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(build_vex(context), indent=2), encoding="utf-8")
    return path
