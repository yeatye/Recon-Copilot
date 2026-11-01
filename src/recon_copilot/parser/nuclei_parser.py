"""Parseur de la sortie JSONL Nuclei (-jsonl) vers le schema interne du parser.

Chaque ligne JSONL est independante : une ligne invalide n'invalide pas les
autres. Elle est simplement consignee dans `parse_errors` avec son numero
de ligne et un extrait, jamais ignoree en silence.

Nuclei a legerement fait evoluer ses noms de champs selon les versions
(ex: "template-id" vs "template_id"). `_get_any` essaie plusieurs cles
plutot que de supposer une version precise.
"""

from __future__ import annotations

import json
from typing import Any

from recon_copilot.parser.models import NucleiDetection, NucleiParseResult


def _get_any(d: dict[str, Any], *keys: str, default: Any = None) -> Any:
    for key in keys:
        if key in d and d[key] not in (None, ""):
            return d[key]
    return default


def _parse_line(line: str, line_number: int, errors: list[str]) -> NucleiDetection | None:
    try:
        payload = json.loads(line)
    except json.JSONDecodeError as exc:
        preview = line[:120].replace("\n", " ")
        errors.append(f"ligne {line_number}: JSON invalide ({exc.msg}) -- extrait: {preview!r}")
        return None

    if not isinstance(payload, dict):
        errors.append(f"ligne {line_number}: JSON valide mais pas un objet -- ignoree")
        return None

    template_id = _get_any(payload, "template-id", "template_id", "templateID")
    if not template_id:
        errors.append(f"ligne {line_number}: champ template-id absent -- ligne ignoree")
        return None

    info = payload.get("info") if isinstance(payload.get("info"), dict) else {}
    name = _get_any(info, "name")
    severity = _get_any(info, "severity", default="unknown")
    tags_raw = _get_any(info, "tags", default=[])
    tags = tuple(tags_raw) if isinstance(tags_raw, (list, tuple)) else tuple()
    description = _get_any(info, "description")

    matched_at = _get_any(payload, "matched-at", "matched_at", "host", default="")

    return NucleiDetection(
        template_id=template_id,
        name=name,
        severity=severity,
        matched_at=matched_at,
        tags=tags,
        description=description,
        raw_line=line,
        line_number=line_number,
    )


def parse_nuclei_jsonl(raw_jsonl: str) -> NucleiParseResult:
    """Normalise une sortie Nuclei -jsonl en NucleiParseResult.

    Une sortie vide n'est PAS une erreur ici (contrairement au parseur
    Nmap) : Nuclei qui ne trouve rien produit legitimement une sortie vide,
    ce qui est un resultat valide (aucune detection), pas un echec.
    """
    detections: list[NucleiDetection] = []
    errors: list[str] = []

    for i, line in enumerate(raw_jsonl.splitlines(), start=1):
        if not line.strip():
            continue
        detection = _parse_line(line, i, errors)
        if detection is not None:
            detections.append(detection)

    return NucleiParseResult(detections=tuple(detections), parse_errors=tuple(errors))
