"""Parseur de la sortie JSON de ffuf (-of json -o fichier).

ffuf ecrit ses resultats dans le FICHIER indique par -o, pas sur stdout
(qui reste silencieux avec -s). C'est ce fichier que `FfufWrapper` relit
et que cette fonction transforme en `FuzzHit` (sans encore comparer a la
baseline -- voir diff.py pour ca).
"""

from __future__ import annotations

import json

from recon_copilot.fuzzing.models import FuzzHit


def parse_ffuf_json(raw_json: str) -> tuple[list[FuzzHit], list[str]]:
    warnings: list[str] = []
    if not raw_json or not raw_json.strip():
        warnings.append("sortie ffuf vide -- aucun resultat exploitable (fuzzing probablement echoue/timeout)")
        return [], warnings

    try:
        payload = json.loads(raw_json)
    except json.JSONDecodeError as exc:
        warnings.append(f"sortie ffuf non-JSON ou tronquee: {exc}")
        return [], warnings

    if "results" not in payload:
        warnings.append("champ 'results' absent dans la sortie ffuf")
        return [], warnings
    results = payload.get("results")
    if not isinstance(results, list):
        warnings.append("champ 'results' present mais invalide (pas un tableau) dans la sortie ffuf")
        return [], warnings

    hits: list[FuzzHit] = []
    for i, item in enumerate(results, start=1):
        if not isinstance(item, dict):
            warnings.append(f"resultat ffuf #{i}: element invalide -- ignore")
            continue
        fuzz_value = item.get("input", {}).get("FUZZ") if isinstance(item.get("input"), dict) else None
        if fuzz_value is None:
            fuzz_value = item.get("url", f"resultat-{i}")
        duration_ns = item.get("duration")
        response_time_ms = duration_ns / 1_000_000 if isinstance(duration_ns, (int, float)) else None
        hits.append(
            FuzzHit(
                payload=str(fuzz_value),
                status_code=item.get("status"),
                body_size=item.get("length"),
                response_time_ms=response_time_ms,
                is_anomaly=False,  # calcule ensuite par diff.annotate_anomalies()
            )
        )

    return hits, warnings
