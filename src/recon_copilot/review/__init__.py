"""Module review : file d'attente accepter/editer/rejeter avant rapport.

Design volontairement simple : une couche de donnees testable (ce fichier)
plus une petite CLI interactive (cli.py) pour l'analyste. Le cahier des
charges ne precise pas de framework web pour cette interface -- en
construire un serait hors du perimetre technique defini (Python +
asyncio/subprocess + SQLite, pas de mention de FastAPI/Flask). La CLI est
un point de depart fonctionnel ; une interface web pourra reutiliser ces
memes fonctions plus tard sans rien changer ici.

Regle importante : rien ne passe au module report sans etre 'accepted' ou
'edited'. Un finding 'rejected' reste en base (traçabilite) mais n'apparait
jamais dans un rapport genere.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum


class ReviewDecision(str, Enum):
    ACCEPTED = "accepted"
    EDITED = "edited"
    REJECTED = "rejected"


@dataclass(frozen=True)
class PendingFinding:
    id: int
    target: str
    title: str
    description: str
    severity: str
    risk_score: float | None
    risk_level: str | None
    citation_verified: bool
    source_citation: str


def get_pending_findings(conn: sqlite3.Connection, engagement: str) -> list[PendingFinding]:
    """Findings 'pending', tries par risk_score decroissant (les plus urgents d'abord).

    Les findings sans score (pas encore passes par le module scoring)
    apparaissent en dernier plutot que d'etre exclus -- l'analyste doit
    pouvoir les voir aussi.
    """
    rows = conn.execute(
        """
        SELECT id, target, title, description, severity, risk_score, risk_level,
               citation_verified, source_citation
        FROM correlated_findings
        WHERE engagement = ? AND review_status = 'pending'
        ORDER BY (risk_score IS NULL), risk_score DESC
        """,
        (engagement,),
    ).fetchall()
    return [
        PendingFinding(
            id=r["id"],
            target=r["target"],
            title=r["title"],
            description=r["description"],
            severity=r["severity"],
            risk_score=r["risk_score"],
            risk_level=r["risk_level"],
            citation_verified=bool(r["citation_verified"]),
            source_citation=r["source_citation"],
        )
        for r in rows
    ]


def _apply_decision(
    conn: sqlite3.Connection,
    finding_id: int,
    analyst: str,
    decision: ReviewDecision,
    comment: str,
    edited_title: str | None = None,
    edited_description: str | None = None,
) -> None:
    exists = conn.execute("SELECT id FROM correlated_findings WHERE id = ?", (finding_id,)).fetchone()
    if exists is None:
        raise ValueError(f"aucun finding avec id={finding_id}")

    now = datetime.now(timezone.utc).isoformat()
    conn.execute(
        """
        UPDATE correlated_findings
        SET review_status = ?, reviewed_by = ?, reviewed_at = ?, review_comment = ?,
            edited_title = ?, edited_description = ?
        WHERE id = ?
        """,
        (decision.value, analyst, now, comment, edited_title, edited_description, finding_id),
    )
    conn.execute(
        "INSERT INTO review_log (timestamp, finding_id, analyst, decision, comment) VALUES (?, ?, ?, ?, ?)",
        (now, finding_id, analyst, decision.value, comment),
    )
    conn.commit()


def accept_finding(conn: sqlite3.Connection, finding_id: int, analyst: str, comment: str = "") -> None:
    _apply_decision(conn, finding_id, analyst, ReviewDecision.ACCEPTED, comment)


def edit_finding(
    conn: sqlite3.Connection,
    finding_id: int,
    analyst: str,
    edited_title: str | None = None,
    edited_description: str | None = None,
    comment: str = "",
) -> None:
    if edited_title is None and edited_description is None:
        raise ValueError("edit_finding necessite au moins edited_title ou edited_description")
    _apply_decision(conn, finding_id, analyst, ReviewDecision.EDITED, comment, edited_title, edited_description)


def reject_finding(conn: sqlite3.Connection, finding_id: int, analyst: str, comment: str = "") -> None:
    if not comment:
        raise ValueError("un rejet doit etre justifie (comment) -- pour l'audit et pour ne pas perdre le contexte plus tard")
    _apply_decision(conn, finding_id, analyst, ReviewDecision.REJECTED, comment)
