"""Store vectoriel local (ChromaDB, mode embedded/persistant -- pas de serveur).

Les embeddings sont TOUJOURS fournis par l'appelant (via `EmbeddingClient`),
jamais calcules par Chroma lui-meme -- ca evite toute dependance a un
modele d'embedding telecharge depuis HuggingFace au premier usage, et ca
garde le controle total sur quel modele produit les vecteurs (coherent
avec la contrainte "ecosysteme Ollama uniquement").
"""

from __future__ import annotations

from pathlib import Path

import chromadb

from recon_copilot.rag.models import KbDocument, RagSearchResult

_COLLECTION_NAME = "recon_copilot_kb"


class VectorStore:
    def __init__(self, persist_directory: str | Path) -> None:
        self._client = chromadb.PersistentClient(path=str(persist_directory))
        self._collection = self._client.get_or_create_collection(
            _COLLECTION_NAME, metadata={"hnsw:space": "cosine"}
        )

    def add_documents(self, documents: list[KbDocument], embeddings: list[list[float]]) -> None:
        if not documents:
            return
        if len(documents) != len(embeddings):
            raise ValueError("documents et embeddings doivent avoir la meme longueur")

        # Cle Chroma = source+id, jamais l'id seul : un template Nuclei nomme
        # d'apres un CVE (ex: id: CVE-2021-44228) et l'entree CISA KEV du
        # meme CVE partagent souvent le meme `id` -- deux documents
        # DIFFERENTS. Utiliser l'id brut comme cle primaire les ferait
        # silencieusement s'ecraser l'un l'autre (constate en usage reel).
        chroma_ids = [f"{d.source}:{d.id}" for d in documents]

        # upsert (pas add) : re-ingerer un document existant (meme cle) met a
        # jour son contenu plutot que d'echouer ou de dupliquer -- utile pour
        # rafraichir le catalogue CISA KEV periodiquement sans tout purger.
        self._collection.upsert(
            ids=chroma_ids,
            embeddings=embeddings,
            documents=[d.content for d in documents],
            metadatas=[{"source": d.source, "title": d.title, "kb_id": d.id, **d.metadata} for d in documents],
        )

    def query(self, query_embedding: list[float], n_results: int = 5) -> list[RagSearchResult]:
        if self._collection.count() == 0:
            return []
        n_results = min(n_results, self._collection.count())
        result = self._collection.query(query_embeddings=[query_embedding], n_results=n_results)

        results: list[RagSearchResult] = []
        ids = result["ids"][0]
        documents = result["documents"][0]
        metadatas = result["metadatas"][0]
        distances = result["distances"][0]

        for chroma_id, content, meta, distance in zip(ids, documents, metadatas, distances):
            meta = dict(meta)
            source = meta.pop("source", "unknown")
            title = meta.pop("title", chroma_id)
            kb_id = meta.pop("kb_id", chroma_id)  # filet de securite si jamais absent
            kb_doc = KbDocument(id=kb_id, source=source, title=title, content=content, metadata=meta)
            # Chroma renvoie une distance cosinus (0 = identique) ; on convertit
            # en score de similarite (1 = identique) plus intuitif a lire/tester.
            similarity = 1.0 - distance
            results.append(RagSearchResult(document=kb_doc, score=similarity))

        return results

    def count(self) -> int:
        return self._collection.count()

    def clear(self) -> None:
        self._client.delete_collection(_COLLECTION_NAME)
        self._collection = self._client.get_or_create_collection(
            _COLLECTION_NAME, metadata={"hnsw:space": "cosine"}
        )
