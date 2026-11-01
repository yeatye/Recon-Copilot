"""Petit utilitaire partage : les reponses LLM (correlation ET fuzzing)
arrivent parfois entourees de balises markdown ```json ... ``` malgre la
consigne de repondre en JSON pur. Centralise ici pour eviter que les deux
modules divergent sur ce nettoyage.
"""

from __future__ import annotations

import re


def strip_markdown_fences(text: str) -> str:
    text = text.strip()
    match = re.search(r'```(?:json)?\s*\n?(.*?)\n?\s*```', text, re.DOTALL)
    if match:
        return match.group(1).strip()
    return text   
