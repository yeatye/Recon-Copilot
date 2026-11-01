"""Parsing et verification de la reponse du LLM de correlation.

La verification de citation est le coeur de la garantie anti-hallucination :
`source_citation` doit etre une SOUS-CHAINE d'au moins un des extraits
sources reellement fournis au LLM (voir prompt.py). Si ce n'est pas le cas,
le finding est CONSERVE (l'analyste peut quand meme vouloir le voir) mais
`citation_verified=False`, et un warning est remonte -- jamais silencieux.
"""

from __future__ import annotations
import re 
import json
import unicodedata
from recon_copilot.correlation.models import Finding
from recon_copilot.json_utils import strip_markdown_fences

_ALLOWED_SEVERITIES = {"info", "low", "medium", "high", "critical"}
_ALLOWED_CONFIDENCE = {"low", "medium", "high"}


def _normalize(s: str) -> str:
    s = unicodedata.normalize("NFKC", s)
    s = s.replace("\u201c", '"').replace("\u201d", '"')
    s = s.replace("\u2018", "'").replace("\u2019", "'")
    return re.sub(r'[\s"\'{}\[\],]+', "", s)


def _verify_citation(citation: str, valid_sources: list[str]) -> bool:
    citation = citation.strip()
    if not citation:
        return False

    # 1. match exact
    if any(citation in source for source in valid_sources):
        return True

    # 2. match normalise global
    cit_norm = _normalize(citation)
    if cit_norm:
        for source in valid_sources:
            if cit_norm in _normalize(source):
                return True

    # 3. match par tokens 'cle:valeur' -- le LLM peut avoir concatene
    #    des champs non adjacents de la raw_line JSONL.
    tokens = re.findall(r'[A-Za-z0-9_\-\.]+:[^\s]+', citation)
    if not tokens:
        return False

    for source in valid_sources:
        src_norm = _normalize(source)
        if all(_normalize(tok) in src_norm for tok in tokens):
            return True

    return False


def _build_finding(item: dict, valid_sources: list[str], warnings: list[str], index: int) -> Finding | None:
    title = item.get("title")
    citation = item.get("source_citation")
    if not title or not citation:
        warnings.append(f"finding #{index}: champ 'title' ou 'source_citation' manquant -- ignore")
        return None

    severity = item.get("severity", "info")
    if severity not in _ALLOWED_SEVERITIES:
        warnings.append(f"finding #{index}: severite '{severity}' invalide -- ramenee a 'info'")
        severity = "info"

    confidence = item.get("confidence", "low")
    if confidence not in _ALLOWED_CONFIDENCE:
        warnings.append(f"finding #{index}: confidence '{confidence}' invalide -- ramenee a 'low'")
        confidence = "low"

    verified = _verify_citation(citation, valid_sources)
    if not verified:
        warnings.append(
            f"finding #{index} ('{title}'): citation non retrouvee mot pour mot dans les donnees "
            f"sources -- finding conserve mais marque citation_verified=False"
        )

    cvss = item.get("cvss_score")
    if cvss is not None:
        try:
            cvss = float(cvss)
        except (TypeError, ValueError):
            warnings.append(f"finding #{index}: cvss_score non numerique -- mis a null")
            cvss = None

    def _str_list(value) -> tuple[str, ...]:
        if isinstance(value, list):
            return tuple(str(v) for v in value)
        return tuple()

    return Finding(
        title=str(title),
        description=str(item.get("description", "")),
        severity=severity,
        cvss_score=cvss,
        confidence=confidence,
        source_type=str(item.get("source_type", "unknown")),
        source_citation=str(citation),
        citation_verified=verified,
        cve_refs=_str_list(item.get("cve_refs")),
        cwe_refs=_str_list(item.get("cwe_refs")),
        mitre_refs=_str_list(item.get("mitre_refs")),
        remediation=str(item.get("remediation", "")),
    )

def parse_llm_response(raw_text: str, valid_sources: list[str]) -> tuple[list[Finding], list[str]]:
    from ._json_utils import extract_json

    warnings: list[str] = []

    try:
        payload = extract_json(raw_text)
    except ValueError:
        warnings.append(
            "reponse LLM non-JSON -- aucun finding extrait, voir raw_llm_response"
        )
        return [], warnings

    # Gérer le cas où le LLM renvoie un objet au lieu d'un tableau
    if isinstance(payload, dict):
        for key in ("findings", "results", "data"):
            if key in payload and isinstance(payload[key], list):
                payload = payload[key]
                break

    if not isinstance(payload, list):
        warnings.append(
            "reponse LLM valide en JSON mais pas un tableau -- aucun finding extrait"
        )
        return [], warnings

    # ... le reste de ta fonction existante (boucle sur les items) reste inchangé
    # ... le reste du code (boucle for i, item in enumerate(payload...)) reste identique   

    findings: list[Finding] = []
    for i, item in enumerate(payload, start=1):
        if not isinstance(item, dict):
            warnings.append(f"finding #{i}: element du tableau n'est pas un objet -- ignore")
            continue
        finding = _build_finding(item, valid_sources, warnings, i)
        if finding is not None:
            findings.append(finding)

    return findings, warnings
