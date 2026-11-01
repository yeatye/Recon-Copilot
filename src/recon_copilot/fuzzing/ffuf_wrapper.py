"""Wrapper ffuf.

Reutilise `ExternalToolWrapper` (scope, throttling, timeout, audit,
fallback binaire absent -- voir external_tool.py) exactement comme
`NmapWrapper`/`NucleiWrapper`. La seule particularite : `target`/`port`
passes a `run()` restent l'hote/port BRUT (pour que la verification de
scope reste identique a celle des autres wrappers -- jamais d'URL complete
passee au scope guard, qui ne sait interpreter que des hotes/CIDR), et
l'URL de fuzzing complete est reconstruite en interne a partir de ces
memes valeurs plus un template de chemin.

ffuf ecrit ses resultats dans un fichier JSON (-o) plutot que sur stdout ;
`run()` est donc surcharge pour relire ce fichier apres l'execution et le
placer dans `RawScanResult.raw_output`, puis nettoyer les fichiers
temporaires.
"""

from __future__ import annotations

import dataclasses
import tempfile
from pathlib import Path

from recon_copilot.external_tool import ExternalToolWrapper, RawScanResult


class FfufWrapper(ExternalToolWrapper):
    tool_name = "ffuf"

    def __init__(
        self,
        scope_guard,
        payloads: list[str],
        audit=None,
        timeout_seconds: float = 180.0,
        min_interval_seconds: float = 0.0,
        rate_limit_per_sec: int = 10,
        url_scheme: str = "http",
        path_template: str = "/FUZZ",
    ) -> None:
        super().__init__(scope_guard, audit=audit, timeout_seconds=timeout_seconds, min_interval_seconds=min_interval_seconds)
        self._payloads = payloads
        self._rate_limit = rate_limit_per_sec
        self._url_scheme = url_scheme
        self._path_template = path_template
        self._wordlist_path: Path | None = None
        self._output_path: Path | None = None

    def _build_url(self, target: str, port: int | None) -> str:
        netloc = target if port is None else f"{target}:{port}"
        return f"{self._url_scheme}://{netloc}{self._path_template}"

    def build_command(self, target: str, aggressiveness: str, port: int | None) -> list[str]:
        wordlist_fd, wordlist_name = tempfile.mkstemp(suffix=".txt", prefix="recon_copilot_ffuf_wordlist_")
        output_fd, output_name = tempfile.mkstemp(suffix=".json", prefix="recon_copilot_ffuf_out_")
        import os

        with os.fdopen(wordlist_fd, "w") as fh:
            fh.write("\n".join(self._payloads))
        os.close(output_fd)  # ffuf ecrit lui-meme le fichier, on n'a besoin que du chemin

        self._wordlist_path = Path(wordlist_name)
        self._output_path = Path(output_name)

        url = self._build_url(target, port)
        return [
            "ffuf",
            "-w", str(self._wordlist_path),
            "-u", url,
            "-o", str(self._output_path),
            "-of", "json",
            "-rate", str(self._rate_limit),
            "-mc", "all",
            "-s",
        ]

    async def run(self, target: str, aggressiveness: str, port: int | None = None) -> RawScanResult:
        try:
            result = await super().run(target, aggressiveness, port)
        finally:
            if self._wordlist_path and self._wordlist_path.exists():
                self._wordlist_path.unlink(missing_ok=True)

        if self._output_path and self._output_path.exists():
            output_content = self._output_path.read_text()
            self._output_path.unlink(missing_ok=True)
            result = dataclasses.replace(result, raw_output=output_content)

        return result
