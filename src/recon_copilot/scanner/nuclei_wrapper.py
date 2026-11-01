"""Wrapper Nuclei.

S'execute normalement APRES Nmap, sur les hotes/services que le parser
aura extraits du XML Nmap — mais reste utilisable seul (ex: cible deja
connue comme etant un service HTTP). Sortie JSONL (-jsonl) pour rester
facilement parsable ligne par ligne.
"""

from __future__ import annotations

from recon_copilot.profiles import get_profile
from recon_copilot.external_tool import ExternalToolWrapper


class NucleiWrapper(ExternalToolWrapper):
    tool_name = "nuclei"

    def build_command(self, target: str, aggressiveness: str, port: int | None) -> list[str]:
        profile = get_profile(aggressiveness)
        url = target if port is None else f"{target}:{port}"
        command = [
            "nuclei",
            "-target",
            url,
            "-severity",
            ",".join(profile.nuclei_severity),
            "-jsonl",
            "-silent",
        ]
        if profile.nuclei_tags_exclude:
            command += ["-etags", ",".join(profile.nuclei_tags_exclude)]
        return command
