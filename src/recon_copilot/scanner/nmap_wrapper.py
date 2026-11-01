"""Wrapper Nmap.

Construit une commande Nmap a partir du profil d'agressivite (voir
profiles.py) et de la cible demandee. Sortie en XML (-oX -) sur stdout pour
que le module `parser` (prochaine etape) puisse s'appuyer sur un format
structure plutot que sur du texte libre.
"""

from __future__ import annotations

from recon_copilot.profiles import get_profile
from recon_copilot.external_tool import ExternalToolWrapper


class NmapWrapper(ExternalToolWrapper):
    tool_name = "nmap"

    def build_command(self, target: str, aggressiveness: str, port: int | None) -> list[str]:
        profile = get_profile(aggressiveness)
        command = ["nmap", profile.nmap_timing, *profile.nmap_extra_args]
        if port is not None:
            command += ["-p", str(port)]
        command += ["-oX", "-", target]
        return command
