"""Piste d'audit.

Toutes les actions qui touchent une cible (scan, fuzzing, ou tentative
bloquee par le scope) passent par ici. Rien dans le pipeline n'est cense
ecrire directement dans `audit_log` ailleurs que via ces fonctions, pour
garder un format d'entree coherent.
"""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class AuditTrail:
    """Petite facade autour de la table audit_log.

    Instanciee une fois par run avec une connexion SQLite partagee (voir db.py),
    et injectee dans le scanner / futur fuzzer.
    """

    def __init__(self, conn: sqlite3.Connection, chosen_by: str) -> None:
        self._conn = conn
        self._chosen_by = chosen_by

    def log_scan_start(
        self,
        *,
        tool: str,
        target: str,
        aggressiveness: str,
        command: str,
        comment: str = "",
    ) -> None:
        self._insert(
            event_type=f"{tool}_scan_start",
            target=target,
            aggressiveness=aggressiveness,
            command=command,
            comment=comment,
        )

    def log_scan_complete(
        self,
        *,
        tool: str,
        target: str,
        aggressiveness: str,
        command: str,
        exit_code: int,
    ) -> None:
        self._insert(
            event_type=f"{tool}_scan_complete",
            target=target,
            aggressiveness=aggressiveness,
            command=command,
            detail=json.dumps({"exit_code": exit_code}),
        )

    def log_scan_error(self, *, tool: str, target: str, command: str, error: str) -> None:
        self._insert(
            event_type=f"{tool}_scan_error",
            target=target,
            command=command,
            detail=json.dumps({"error": error}),
        )

    def log_scope_violation(self, target: str, reason: str) -> None:
        """Signature compatible avec `ScopeGuard(on_violation=...)` — voir scope.py."""
        self._insert(event_type="scope_violation", target=target, comment=reason)

    def _insert(
        self,
        *,
        event_type: str,
        target: str | None = None,
        port: int | None = None,
        aggressiveness: str | None = None,
        command: str | None = None,
        comment: str = "",
        detail: str | None = None,
    ) -> None:
        self._conn.execute(
            """
            INSERT INTO audit_log
                (timestamp, event_type, target, port, aggressiveness, chosen_by, comment, command, detail)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                _now(),
                event_type,
                target,
                port,
                aggressiveness,
                self._chosen_by,
                comment,
                command,
                detail,
            ),
        )
        self._conn.commit()
