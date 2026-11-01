"""Base commune pour tous les wrappers d'outils externes du pipeline
(Nmap, Nuclei, et ffuf pour le fuzzing).

Tous partagent le meme besoin : verifier le scope avant de lancer quoi que
ce soit, respecter un throttling minimal entre deux executions, imposer un
timeout dur (les outils externes plantent ou restent bloques), et logger
systematiquement le resultat dans l'audit trail — succes ou echec.

Centraliser cette logique ici (plutot que dans scanner/ ou fuzzing/) evite
qu'un des modules "oublie" une verification que l'autre applique -- c'est
la meme raison qui a fait sortir scope.py et audit.py du dossier scanner/.
"""

from __future__ import annotations

import asyncio
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime, timezone

from recon_copilot.audit import AuditTrail
from recon_copilot.scope import ScopeGuard

logger = logging.getLogger("recon_copilot.external_tool")


class ToolExecutionError(Exception):
    """Leve quand l'outil externe ne peut pas etre execute du tout (binaire absent, etc.)."""


@dataclass(frozen=True)
class RawScanResult:
    """Resultat brut generique d'un outil externe (Nmap, Nuclei, ffuf...).

    Vit ici plutot que dans `scanner.models` : ffuf (module fuzzing) en a
    besoin exactement comme Nmap/Nuclei, et le mettre sous `scanner/`
    aurait force `fuzzing` a dependre du package `scanner` pour un simple
    type de donnees, sans lien logique avec le scan reseau.
    """

    tool: str  # "nmap" | "nuclei" | "ffuf"
    target: str
    aggressiveness: str
    command: tuple[str, ...]
    raw_output: str
    exit_code: int
    started_at: datetime
    finished_at: datetime
    timed_out: bool = False
    stderr: str = ""
    db_id: int | None = None  # id de la ligne de persistance, rempli par l'appelant apres insertion

    @property
    def succeeded(self) -> bool:
        return self.exit_code == 0 and not self.timed_out


class ExternalToolWrapper(ABC):
    tool_name: str  # "nmap" | "nuclei" | "ffuf", defini par la sous-classe

    def __init__(
        self,
        scope_guard: ScopeGuard,
        audit: AuditTrail | None = None,
        timeout_seconds: float = 300.0,
        min_interval_seconds: float = 0.0,
    ) -> None:
        self._scope_guard = scope_guard
        self._audit = audit
        self._timeout_seconds = timeout_seconds
        self._min_interval_seconds = min_interval_seconds
        self._throttle_lock = asyncio.Lock()
        self._last_run_monotonic: float | None = None

    @abstractmethod
    def build_command(self, target: str, aggressiveness: str, port: int | None) -> list[str]:
        """Construit la commande exacte (liste d'argv) pour cette cible/profil."""

    async def run(
        self,
        target: str,
        aggressiveness: str,
        port: int | None = None,
    ) -> RawScanResult:
        # 1. Scope : jamais contournable, quel que soit le profil d'agressivite.
        #    enforce() leve ScopeViolation ET notifie l'audit via son callback.
        self._scope_guard.enforce(target, port)

        # 2. Throttling : espace les executions, meme en rafale d'appels concurrents.
        await self._throttle()

        command = self.build_command(target, aggressiveness, port)
        started_at = datetime.now(timezone.utc)

        if self._audit:
            self._audit.log_scan_start(
                tool=self.tool_name,
                target=target,
                aggressiveness=aggressiveness,
                command=" ".join(command),
            )

        try:
            proc = await asyncio.create_subprocess_exec(
                *command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
        except FileNotFoundError as exc:
            # Fallback explicite : binaire absent du PATH. On ne masque pas
            # l'erreur, mais on la journalise proprement au lieu de laisser
            # remonter une trace Python brute a l'analyste.
            if self._audit:
                self._audit.log_scan_error(
                    tool=self.tool_name, target=target, command=" ".join(command), error=str(exc)
                )
            raise ToolExecutionError(
                f"Binaire '{command[0]}' introuvable. Verifie qu'il est installe et dans le PATH."
            ) from exc

        timed_out = False
        try:
            stdout_b, stderr_b = await asyncio.wait_for(
                proc.communicate(), timeout=self._timeout_seconds
            )
        except asyncio.TimeoutError:
            timed_out = True
            proc.kill()
            await proc.wait()
            stdout_b, stderr_b = b"", b"timeout"
            logger.warning(
                "%s: timeout apres %.0fs sur %s", self.tool_name, self._timeout_seconds, target
            )

        finished_at = datetime.now(timezone.utc)
        exit_code = proc.returncode if proc.returncode is not None else -1
        stdout = stdout_b.decode(errors="replace")
        stderr = stderr_b.decode(errors="replace")

        result = RawScanResult(
            tool=self.tool_name,
            target=target,
            aggressiveness=aggressiveness,
            command=tuple(command),
            raw_output=stdout,
            exit_code=exit_code,
            started_at=started_at,
            finished_at=finished_at,
            timed_out=timed_out,
            stderr=stderr,
        )

        if self._audit:
            if result.succeeded:
                self._audit.log_scan_complete(
                    tool=self.tool_name,
                    target=target,
                    aggressiveness=aggressiveness,
                    command=" ".join(command),
                    exit_code=exit_code,
                )
            else:
                self._audit.log_scan_error(
                    tool=self.tool_name,
                    target=target,
                    command=" ".join(command),
                    error=f"exit_code={exit_code} timed_out={timed_out} stderr={stderr[:500]}",
                )

        return result

    async def _throttle(self) -> None:
        if self._min_interval_seconds <= 0:
            return
        async with self._throttle_lock:
            loop = asyncio.get_event_loop()
            now = loop.time()
            if self._last_run_monotonic is not None:
                elapsed = now - self._last_run_monotonic
                wait = self._min_interval_seconds - elapsed
                if wait > 0:
                    await asyncio.sleep(wait)
            self._last_run_monotonic = loop.time()
