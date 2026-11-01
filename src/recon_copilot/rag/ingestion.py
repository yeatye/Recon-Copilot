"""Ingestion des sources RAG : catalogue CISA KEV et templates Nuclei.

Meme philosophie que le module `parser` : une entree malformee n'invalide
jamais tout l'ingestion, elle est consignee dans `errors` et sautee.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from recon_copilot.rag.models import KbDocument


def parse_cisa_kev_json(raw_json: str) -> tuple[list[KbDocument], list[str]]:
    """Parse le catalogue CISA KEV (format JSON officiel, cle 'vulnerabilities').

    Source : https://www.cisa.gov/known-exploited-vulnerabilities-catalog
    (fichier JSON telechargeable, ingestion hors-ligne -- pas d'appel reseau ici).
    """
    import json

    errors: list[str] = []
    try:
        payload = json.loads(raw_json)
    except json.JSONDecodeError as exc:
        return [], [f"catalogue CISA KEV: JSON invalide ({exc.msg})"]

    vulnerabilities = payload.get("vulnerabilities")
    if not isinstance(vulnerabilities, list):
        return [], ["catalogue CISA KEV: champ 'vulnerabilities' absent ou invalide"]

    docs: list[KbDocument] = []
    for i, entry in enumerate(vulnerabilities, start=1):
        if not isinstance(entry, dict):
            errors.append(f"CISA KEV entree #{i}: pas un objet -- ignoree")
            continue
        cve_id = entry.get("cveID")
        if not cve_id:
            errors.append(f"CISA KEV entree #{i}: champ 'cveID' absent -- ignoree")
            continue

        name = entry.get("vulnerabilityName", cve_id)
        short_desc = entry.get("shortDescription", "")
        required_action = entry.get("requiredAction", "")
        content = f"{short_desc} Action requise : {required_action}".strip()

        docs.append(
            KbDocument(
                id=cve_id,
                source="cisa_kev",
                title=name,
                content=content or name,
                metadata={
                    "cve_id": cve_id,
                    "vendor": entry.get("vendorProject", ""),
                    "product": entry.get("product", ""),
                    "date_added": entry.get("dateAdded", ""),
                    "known_ransomware": entry.get("knownRansomwareCampaignUse", "Unknown"),
                },
            )
        )

    return docs, errors


def parse_nuclei_template_yaml(raw_yaml: str, template_path: str = "") -> tuple[KbDocument | None, str | None]:
    """Parse UN template Nuclei (.yaml) en KbDocument. Retourne (None, erreur) si inexploitable."""
    try:
        payload = yaml.safe_load(raw_yaml)
    except yaml.YAMLError as exc:
        return None, f"template Nuclei {template_path or '(chemin inconnu)'}: YAML invalide ({exc})"

    if not isinstance(payload, dict):
        return None, f"template Nuclei {template_path or '(chemin inconnu)'}: contenu YAML inattendu (pas un objet)"

    template_id = payload.get("id")
    if not template_id:
        return None, f"template Nuclei {template_path or '(chemin inconnu)'}: champ 'id' absent -- ignore"

    info = payload.get("info") if isinstance(payload.get("info"), dict) else {}
    name = info.get("name", template_id)
    description = info.get("description", "")
    severity = info.get("severity", "unknown")
    tags_raw = info.get("tags", "")
    tags = tags_raw if isinstance(tags_raw, str) else ",".join(tags_raw) if isinstance(tags_raw, list) else ""

    return (
        KbDocument(
            id=template_id,
            source="nuclei_template",
            title=name,
            content=description or name,
            metadata={"severity": severity, "tags": tags, "path": template_path},
        ),
        None,
    )


def ingest_nuclei_templates_dir(directory: str | Path) -> tuple[list[KbDocument], list[str]]:
    """Parcourt un dossier de templates Nuclei (.yaml/.yml) recursivement."""
    directory = Path(directory)
    docs: list[KbDocument] = []
    errors: list[str] = []

    if not directory.is_dir():
        return [], [f"dossier de templates Nuclei introuvable : {directory}"]

    for path in sorted(directory.rglob("*.yaml")) + sorted(directory.rglob("*.yml")):
        try:
            raw = path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            errors.append(f"{path}: lecture impossible ({exc})")
            continue
        doc, error = parse_nuclei_template_yaml(raw, template_path=str(path))
        if doc is not None:
            docs.append(doc)
        if error is not None:
            errors.append(error)

    return docs, errors
