"""Construction du ReportContext a partir de la base SQLite.

Regle non-negociable : seuls les findings 'accepted' ou 'edited' entrent
dans un rapport. Un finding 'rejected' ou encore 'pending' n'y figure
jamais -- generer un rapport avant la fin de la revue humaine serait
contraire au principe "l'outil assiste l'analyste, il ne le remplace pas".
"""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone

from recon_copilot.report.models import ReportContext, ReportFinding
from recon_copilot.scope import ScopeConfig


def _lookup_command(conn: sqlite3.Connection, engagement: str, target: str, tool: str) -> str | None:
    """Retrouve la commande la plus recente pour ce couple (cible, outil).

    Limite connue : si une meme cible a ete scannee plusieurs fois avec des
    parametres differents avant la revue, c'est la commande du scan le PLUS
    RECENT qui est affichee -- pas forcement celle qui a produit exactement
    cette detection. Dans l'usage normal (un scan par cible avant revue),
    c'est la meme chose.
    """
    row = conn.execute(
        """
        SELECT command FROM raw_scan_results
        WHERE engagement = ? AND target = ? AND tool = ?
        ORDER BY id DESC LIMIT 1
        """,
        (engagement, target, tool),
    ).fetchone()
    return row["command"] if row else None


def build_report_context(
    conn: sqlite3.Connection, engagement: str, scope: ScopeConfig | None = None
) -> ReportContext:
    rows = conn.execute(
        """
        SELECT target, title, description, severity, risk_score, risk_level, remediation,
               cve_refs, cwe_refs, mitre_refs, source_citation, citation_verified, source_type,
               review_status, edited_title, edited_description
        FROM correlated_findings
        WHERE engagement = ? AND review_status IN ('accepted', 'edited')
        """,
        (engagement,),
    ).fetchall()

    findings = []
    for r in rows:
        title = r["edited_title"] if r["review_status"] == "edited" and r["edited_title"] else r["title"]
        description = (
            r["edited_description"]
            if r["review_status"] == "edited" and r["edited_description"]
            else r["description"]
        )
        command_used = _lookup_command(conn, engagement, r["target"], r["source_type"])
        findings.append(
            ReportFinding(
                target=r["target"],
                title=title,
                description=description,
                severity=r["severity"],
                risk_score=r["risk_score"],
                risk_level=r["risk_level"],
                remediation=r["remediation"] or "",
                cve_refs=tuple(json.loads(r["cve_refs"]) if r["cve_refs"] else []),
                cwe_refs=tuple(json.loads(r["cwe_refs"]) if r["cwe_refs"] else []),
                mitre_refs=tuple(json.loads(r["mitre_refs"]) if r["mitre_refs"] else []),
                source_citation=r["source_citation"],
                citation_verified=bool(r["citation_verified"]),
                command_used=command_used,
            )
        )

    return ReportContext(
        engagement=engagement,
        generated_at=datetime.now(timezone.utc).isoformat(),
        findings=tuple(findings),
        scope_allowed_targets=scope.allowed_targets if scope else (),
        scope_excluded_targets=scope.excluded_targets if scope else (),
    )
