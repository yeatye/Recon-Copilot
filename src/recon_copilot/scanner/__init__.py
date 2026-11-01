"""Facade du module scanner.

C'est le seul point d'entree que les autres modules (parser, et plus tard
le pipeline complet) doivent importer : `run_scan()`. Elle enchaine Nmap
puis Nuclei sur une cible, dans le respect du scope et du profil choisi,
et persiste les resultats bruts en base pour que le parser puisse les
reprendre sans dependre de la sortie encore en memoire.
"""

from __future__ import annotations

import dataclasses
import sqlite3
from datetime import datetime, timezone

from recon_copilot.audit import AuditTrail
from recon_copilot.scanner.models import RawScanResult, ScanRequest
from recon_copilot.scanner.nmap_wrapper import NmapWrapper
from recon_copilot.scanner.nuclei_wrapper import NucleiWrapper
from recon_copilot.scope import ScopeGuard

__all__ = ["ScanRequest", "RawScanResult", "run_scan"]


def _persist(conn: sqlite3.Connection, engagement: str, result: RawScanResult) -> int:
    """Insere le resultat brut et retourne l'id de la ligne (utilise par le parser)."""
    cursor = conn.execute(
        """
        INSERT INTO raw_scan_results
            (timestamp, engagement, tool, target, aggressiveness, command, raw_output, exit_code)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            datetime.now(timezone.utc).isoformat(),
            engagement,
            result.tool,
            result.target,
            result.aggressiveness,
            " ".join(result.command),
            result.raw_output,
            result.exit_code,
        ),
    )
    conn.commit()
    return cursor.lastrowid


async def run_scan(
    request: ScanRequest,
    scope_guard: ScopeGuard,
    conn: sqlite3.Connection,
    nmap_timeout: float = 300.0,
    nuclei_timeout: float = 600.0,
    min_interval_seconds: float = 0.0,
) -> list[RawScanResult]:
    """Lance Nmap puis Nuclei sur `request.target`, persiste et retourne les resultats bruts.

    Nuclei s'execute meme si Nmap echoue (outil independant), mais chaque
    resultat individuel est marque `succeeded=False` si son execution a
    echoue plutot que de faire tomber tout le scan -- c'est au parser /
    a l'analyste de decider quoi faire d'un resultat partiel.
    """
    audit = AuditTrail(conn, chosen_by=request.chosen_by)
    if request.comment:
        audit.log_scan_start(
            tool="pipeline",
            target=request.target,
            aggressiveness=request.aggressiveness,
            command="run_scan",
            comment=request.comment,
        )

    nmap = NmapWrapper(
        scope_guard, audit=audit, timeout_seconds=nmap_timeout, min_interval_seconds=min_interval_seconds
    )
    nuclei = NucleiWrapper(
        scope_guard, audit=audit, timeout_seconds=nuclei_timeout, min_interval_seconds=min_interval_seconds
    )

    results: list[RawScanResult] = []

    nmap_result = await nmap.run(request.target, request.aggressiveness, request.port)
    nmap_id = _persist(conn, request.engagement, nmap_result)
    results.append(dataclasses.replace(nmap_result, db_id=nmap_id))

    nuclei_result = await nuclei.run(request.target, request.aggressiveness, request.port)
    nuclei_id = _persist(conn, request.engagement, nuclei_result)
    results.append(dataclasses.replace(nuclei_result, db_id=nuclei_id))

    return results
