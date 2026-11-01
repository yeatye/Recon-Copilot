"""Triage des anomalies -- UN SEUL appel LLM (groupe), et SEULEMENT si des
anomalies existent. C'est la seconde et derniere sollicitation du LLM dans
tout le module fuzzing (la premiere etant la generation des payloads) :
jamais d'appel par requete individuelle.
"""

from __future__ import annotations

import json

from recon_copilot.fuzzing.models import AnomalyTriage, FuzzHit
from recon_copilot.json_utils import strip_markdown_fences
from recon_copilot.llm_client import LlmClient

SYSTEM_PROMPT = (
    "Tu es un assistant qui aide un pentester a trier des anomalies de "
    "fuzzing web. Tu recois une liste de reponses qui different de la "
    "reponse de reference (code HTTP, taille, ou temps de reponse "
    "anormal). Pour chacune, explique brievement pourquoi elle est "
    "potentiellement interessante et propose une severite indicative. "
    "Reponds UNIQUEMENT avec un tableau JSON valide, sans texte "
    "avant/apres, sans balises markdown."
)

_SCHEMA_HINT = """\
Pour chaque anomalie ci-dessous, reponds avec un objet :
{"payload": "<identique a celui fourni>", "explanation": "pourquoi c'est potentiellement interessant", "severity_guess": "info|low|medium|high|critical"}
Reponds avec un tableau contenant UN objet par anomalie fournie, dans le meme ordre.
"""


def build_triage_prompt(anomalies: list[FuzzHit], baseline_status: int, baseline_size: int) -> str:
    lines = [
        f"Reference (baseline) : status={baseline_status}, taille_reponse={baseline_size} octets",
        "Anomalies detectees :",
    ]
    for hit in anomalies:
        lines.append(
            f"- payload={hit.payload!r} status={hit.status_code} taille={hit.body_size} "
            f"temps_ms={hit.response_time_ms}"
        )
    lines.append("")
    lines.append(_SCHEMA_HINT)
    return "\n".join(lines)


def parse_triage_response(raw_text: str) -> tuple[list[AnomalyTriage], list[str]]:
    warnings: list[str] = []
    cleaned = strip_markdown_fences(raw_text)

    try:
        payload = json.loads(cleaned)
    except json.JSONDecodeError as exc:
        warnings.append(f"reponse LLM non-JSON pour le triage d'anomalies ({exc.msg})")
        return [], warnings

    if not isinstance(payload, list):
        warnings.append("reponse LLM de triage valide en JSON mais pas un tableau")
        return [], warnings

    triages: list[AnomalyTriage] = []
    for i, item in enumerate(payload, start=1):
        if not isinstance(item, dict) or not item.get("payload"):
            warnings.append(f"triage #{i}: element invalide ou champ 'payload' manquant -- ignore")
            continue
        triages.append(
            AnomalyTriage(
                payload=str(item["payload"]),
                explanation=str(item.get("explanation", "")),
                severity_guess=str(item.get("severity_guess", "info")),
            )
        )
    return triages, warnings


async def triage_anomalies(
    anomalies: list[FuzzHit],
    baseline_status: int,
    baseline_size: int,
    llm_client: LlmClient,
) -> tuple[list[AnomalyTriage], list[str]]:
    if not anomalies:
        return [], []  # aucun appel LLM si rien d'anormal -- exactement la regle du cahier des charges
    prompt = build_triage_prompt(anomalies, baseline_status, baseline_size)
    raw_response = await llm_client.generate(prompt, system=SYSTEM_PROMPT)
    return parse_triage_response(raw_response)
