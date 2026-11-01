"""Modeles de donnees du module RAG.

Un seul type de document pour les deux sources ingerees (CISA KEV et
templates Nuclei) -- volontairement homogene pour que le store vectoriel
et la recherche par similarite n'aient pas a distinguer les sources.
`source` et `metadata` gardent la tracabilite de l'origine.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class KbDocument:
    id: str  # identifiant stable (CVE-ID pour KEV, template-id pour Nuclei) -- utilise comme id Chroma
    source: str  # "cisa_kev" | "nuclei_template"
    title: str
    content: str  # texte utilise pour l'embedding et affiche comme contexte au LLM
    metadata: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class RagSearchResult:
    document: KbDocument
    score: float  # similarite cosinus, plus haut = plus proche (converti depuis la distance Chroma)
