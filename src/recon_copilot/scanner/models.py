"""Modeles de donnees du module scanner.

`RawScanResult` vit desormais dans `recon_copilot.external_tool` (c'est un
resultat generique d'outil externe, reutilise par ffuf dans le module
fuzzing -- pas seulement par Nmap/Nuclei). Reexporte ici pour ne pas
casser le code existant qui l'importe depuis `scanner.models`.
"""

from __future__ import annotations

from dataclasses import dataclass

from recon_copilot.external_tool import RawScanResult

__all__ = ["RawScanResult", "ScanRequest"]


@dataclass(frozen=True)
class ScanRequest:
    """Une demande de scan sur UNE cible (le scanner ne prend jamais de plage a l'aveugle)."""

    target: str
    aggressiveness: str
    engagement: str
    chosen_by: str
    comment: str = ""
    port: int | None = None
