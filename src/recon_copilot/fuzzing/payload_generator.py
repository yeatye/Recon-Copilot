"""Generation des payloads de fuzzing -- UN SEUL appel LLM.

Le prompt de conception explicite du pipeline interdit tout appel LLM dans
la boucle de fuzzing elle-meme : les payloads sont generes une fois, ici,
a partir de la technologie detectee par Nmap/Nuclei, puis executes en
masse par ffuf sans repasser par le LLM avant le triage des anomalies
(voir triage.py).
"""

from __future__ import annotations

import json

from recon_copilot.fuzzing.models import FuzzPayload
from recon_copilot.json_utils import strip_markdown_fences
from recon_copilot.llm_client import LlmClient

SYSTEM_PROMPT = (
    "Tu es un assistant qui genere des payloads de fuzzing web cibles pour "
    "un pentester autorise. Tu recois la technologie detectee sur la cible "
    "et tu proposes une liste de payloads pertinents (chemins, parametres, "
    "techniques d'injection classiques adaptees a cette techno). Reponds "
    "UNIQUEMENT avec un tableau JSON valide, sans texte avant/apres, sans "
    "balises markdown."
)

_SCHEMA_HINT = """\
Chaque element du tableau JSON doit avoir exactement ces champs :
{"payload": "chemin ou valeur a tester", "description": "pourquoi ce payload est pertinent pour cette techno"}
Genere entre 10 et 40 payloads selon la pertinence, jamais un nombre absurde. Ne repete jamais le meme payload.
"""


def build_payload_prompt(tech_hint: str) -> str:
    return (
        f"Technologie/service detecte sur la cible : {tech_hint}\n\n"
        f"{_SCHEMA_HINT}"
    )


def parse_payload_response(raw_text: str) -> tuple[list[FuzzPayload], list[str]]:
    warnings: list[str] = []
    cleaned = strip_markdown_fences(raw_text)

    try:
        payload_list = json.loads(cleaned)
    except json.JSONDecodeError as exc:
        warnings.append(f"reponse LLM non-JSON pour la generation de payloads ({exc.msg})")
        return [], warnings

    if not isinstance(payload_list, list):
        warnings.append("reponse LLM valide en JSON mais pas un tableau -- aucun payload extrait")
        return [], warnings

    payloads: list[FuzzPayload] = []
    seen: set[str] = set()
    for i, item in enumerate(payload_list, start=1):
        if not isinstance(item, dict) or not item.get("payload"):
            warnings.append(f"payload #{i}: element invalide ou champ 'payload' manquant -- ignore")
            continue
        value = str(item["payload"])
        if value in seen:
            continue  # doublon silencieux : pas une erreur, juste evite de fuzzer deux fois la meme chose
        seen.add(value)
        payloads.append(FuzzPayload(payload=value, description=str(item.get("description", ""))))

    return payloads, warnings


async def generate_payloads(tech_hint: str, llm_client: LlmClient) -> tuple[list[FuzzPayload], list[str]]:
    """Fait l'UNIQUE appel LLM de generation de payloads pour ce run de fuzzing."""
    prompt = build_payload_prompt(tech_hint)
    raw_response = await llm_client.generate(prompt, system=SYSTEM_PROMPT)
    return parse_payload_response(raw_response)
