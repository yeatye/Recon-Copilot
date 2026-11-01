"""Facade du module RAG.

`RagIndex` combine `EmbeddingClient` (calcul des vecteurs) et `VectorStore`
(stockage/recherche local) derriere une API simple : `index_documents()`
pour l'ingestion, `search()` pour la recuperation semantique consommee par
`correlation/`.

Ce module est OPTIONNEL et ADDITIF : rien dans `scanner`, `parser`,
`scoring`, `fuzzing`, `review` ou `report` n'en depend. `correlation/`
accepte un `RagIndex | None` -- a `None` (defaut), tout se comporte
exactement comme avant ce module (voir correlation/__init__.py).
"""

from __future__ import annotations

from pathlib import Path

from recon_copilot.rag.embeddings import EmbeddingClient, LocalEmbeddingClient
from recon_copilot.rag.ingestion import (
    ingest_nuclei_templates_dir,
    parse_cisa_kev_json,
    parse_nuclei_template_yaml,
)
from recon_copilot.rag.models import KbDocument, RagSearchResult
from recon_copilot.rag.store import VectorStore

__all__ = [
    "KbDocument",
    "RagSearchResult",
    "RagIndex",
    "LocalEmbeddingClient",
    "parse_cisa_kev_json",
    "parse_nuclei_template_yaml",
    "ingest_nuclei_templates_dir",
    "format_rag_context",
]


def format_rag_context(results: list[RagSearchResult]) -> str:
    """Formate des resultats de recherche RAG en texte pret pour le prompt.

    Le score de similarite est affiche pour que le LLM (et l'analyste qui
    relit le prompt en audit) puisse juger de la pertinence -- un resultat
    a similarite faible ne doit pas peser autant qu'un match tres proche.
    """
    if not results:
        return ""
    lines = []
    for r in results:
        d = r.document
        excerpt = d.content[:300]
        lines.append(f"- [{d.source}] {d.title} (similarite={r.score:.2f}) : {excerpt}")
    return "\n".join(lines)


class RagIndex:
    def __init__(self, embedding_client: EmbeddingClient, persist_directory: str | Path) -> None:
        self._embedding_client = embedding_client
        self._store = VectorStore(persist_directory)

    async def index_documents(self, documents: list[KbDocument], batch_size: int = 64) -> int:
        """Calcule les embeddings et indexe `documents`. Retourne le nombre indexe.

        Traite par lots (`batch_size`) pour eviter d'envoyer des milliers de
        textes en un seul appel HTTP au serveur d'embeddings -- le catalogue
        CISA KEV complet fait plusieurs milliers d'entrees.
        """
        total = 0
        for i in range(0, len(documents), batch_size):
            batch = documents[i : i + batch_size]
            embeddings = await self._embedding_client.embed([d.content for d in batch])
            self._store.add_documents(batch, embeddings)
            total += len(batch)
        return total

    async def search(self, query_text: str, n_results: int = 5) -> list[RagSearchResult]:
        if not query_text.strip():
            return []
        embeddings = await self._embedding_client.embed([query_text])
        if not embeddings:
            return []
        return self._store.query(embeddings[0], n_results=n_results)

    def count(self) -> int:
        return self._store.count()
