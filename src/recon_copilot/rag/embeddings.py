"""Client d'embeddings pour le module RAG.

Meme pattern que `llm_client.py` (interface abstraite + implementations
reelles) pour que les tests puissent injecter un double sans jamais
toucher au reseau.

Trois implementations reelles :
- `OpenAIEmbeddingClient` : API OpenAI (`/v1/embeddings`), autorisation par cle API.
- `OllamaEmbeddingClient` : instance Ollama locale (`/api/embed`),
  necessite un modele d'embedding telecharge (ex: `ollama pull nomic-embed-text`)
  -- PAS Qwen, qui est un modele de generation, pas d'embedding.
- `LocalEmbeddingClient` : calcul local sur CPU (ONNX all-MiniLM-L6-v2 via
  ChromaDB), aucune cle API, aucun appel reseau -- c'est l'option quand la
  cle LLM n'expose pas de endpoint `/embeddings` (ex: cle OpenCode).
"""

from __future__ import annotations

from abc import ABC, abstractmethod

import httpx

from recon_copilot.llm_client import LlmError


class EmbeddingClient(ABC):
    @abstractmethod
    async def embed(self, texts: list[str]) -> list[list[float]]:
        """Retourne un vecteur d'embedding par texte d'entree, meme ordre."""


class OpenAIEmbeddingClient(EmbeddingClient):
    """Client pour l'API OpenAI d'embeddings (`/embeddings`).

    Se configure avec une cle API (`api_key`) et un modele d'embedding
    (defaut: "text-embedding-3-small").
    """

    def __init__(
        self,
        api_key: str,
        model: str = "text-embedding-3-small",
        base_url: str = "https://api.openai.com/v1",
        timeout_seconds: float = 120.0,
    ) -> None:
        self._api_key = api_key
        self._model = model
        self._base_url = base_url.rstrip("/")
        self._timeout_seconds = timeout_seconds

    async def embed(self, texts: list[str]) -> list[list[float]]:
        if not texts:
            return []
        payload = {"model": self._model, "input": texts}
        headers = {"Authorization": f"Bearer {self._api_key}"}
        try:
            async with httpx.AsyncClient(timeout=self._timeout_seconds) as client:
                response = await client.post(
                    f"{self._base_url}/embeddings", json=payload, headers=headers
                )
                response.raise_for_status()
        except httpx.ConnectError as exc:
            raise LlmError(
                f"Impossible de joindre l'API OpenAI (embeddings) sur {self._base_url} -- "
                f"verifie la cle API et l'acces reseau."
            ) from exc
        except httpx.TimeoutException as exc:
            raise LlmError(
                f"L'API OpenAI (embeddings) n'a pas repondu apres {self._timeout_seconds}s."
            ) from exc
        except httpx.HTTPStatusError as exc:
            raise LlmError(
                f"L'API OpenAI (embeddings) a renvoye une erreur HTTP {exc.response.status_code}: "
                f"{exc.response.text[:300]}"
            ) from exc

        data = response.json()
        try:
            embeddings = [item["embedding"] for item in data["data"]]
        except (KeyError, TypeError) as exc:
            raise LlmError(f"Reponse OpenAI (embeddings) sans champ 'data[].embedding': {data!r}") from exc
        if len(embeddings) != len(texts):
            raise LlmError(
                f"Reponse OpenAI (embeddings) avec {len(embeddings)} vecteurs pour {len(texts)} textes."
            )
        return embeddings


class OllamaEmbeddingClient(EmbeddingClient):
    def __init__(
        self,
        host: str = "http://localhost:11434",
        model: str = "nomic-embed-text",
        timeout_seconds: float = 120.0,
    ) -> None:
        self._host = host.rstrip("/")
        self._model = model
        self._timeout_seconds = timeout_seconds

    async def embed(self, texts: list[str]) -> list[list[float]]:
        if not texts:
            return []
        payload = {"model": self._model, "input": texts}
        try:
            async with httpx.AsyncClient(timeout=self._timeout_seconds) as client:
                response = await client.post(f"{self._host}/api/embed", json=payload)
                response.raise_for_status()
        except httpx.ConnectError as exc:
            raise LlmError(
                f"Impossible de joindre Ollama sur {self._host} pour les embeddings -- "
                f"verifie que le modele '{self._model}' est telecharge ('ollama pull {self._model}')."
            ) from exc
        except httpx.TimeoutException as exc:
            raise LlmError(f"Ollama (embeddings) n'a pas repondu apres {self._timeout_seconds}s.") from exc
        except httpx.HTTPStatusError as exc:
            raise LlmError(
                f"Ollama (embeddings) a renvoye une erreur HTTP {exc.response.status_code}: {exc.response.text[:300]}"
            ) from exc

        data = response.json()
        embeddings = data.get("embeddings")
        if embeddings is None:
            raise LlmError(f"Reponse Ollama (embeddings) sans champ 'embeddings': {data!r}")
        return embeddings


class LocalEmbeddingClient(EmbeddingClient):
    """Embeddings 100% locaux (CPU), aucune cle API ni appel reseau.

    S'appuie sur le modele ONNX `all-MiniLM-L6-v2` (384 dimensions)
    embarque par ChromaDB : telecharge une seule fois dans le cache
    ChromaDB (~80 Mo), puis calcule les vecteurs localement.

    C'est l'implementation a choisir quand la cle LLM n'expose pas de
    endpoint `/embeddings` (ex: cle OpenCode, verifiee absente en 404) :
    la RAG reste fonctionnelle avec uniquement la cle de generation.
    """

    def __init__(self) -> None:
        # Import differe : Chroma embarque onnxruntime et telecharge le
        # modele au premier usage -- on ne doit pas toucher au reseau a
        # l'import du module.
        from chromadb.utils.embedding_functions import DefaultEmbeddingFunction

        self._fn = DefaultEmbeddingFunction()

    async def embed(self, texts: list[str]) -> list[list[float]]:
        if not texts:
            return []
        return self._fn(texts)
