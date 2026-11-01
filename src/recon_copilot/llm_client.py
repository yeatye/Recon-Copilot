"""Client LLM partage (correlation ET fuzzing en ont chacun besoin).

Interface minimale `LlmClient.generate(prompt, system=None) -> str` pour
que correlation/ et fuzzing/ puissent etre testes avec un double de test
(voir tests/*/conftest.py) sans jamais dependre d'un vrai service LLM.

Deux implementations reelles :
- `OpenAIClient` : toute API compatible OpenAI (`/chat/completions`) --
  OpenAI, OpenCode Zen, proxies, etc. Autorisation par cle API.
- `OllamaClient` : instance Ollama locale, en HTTP (`/api/generate`).
"""

from __future__ import annotations

from abc import ABC, abstractmethod

import httpx


class LlmError(Exception):
    """Leve quand le service LLM n'est pas joignable ou renvoie une erreur HTTP."""


class LlmClient(ABC):
    @abstractmethod
    async def generate(self, prompt: str, system: str | None = None) -> str:
        """Retourne la reponse texte brute du modele pour ce prompt."""


class OpenAIClient(LlmClient):
    """Client pour toute API compatible OpenAI (`/chat/completions`).

    Se configure avec une cle API (`api_key`), le modele a utiliser
    (`model`) et eventuellement une base_url alternative (OpenAI,
    OpenCode Zen / Go, Azure, proxy...).
    `extra_headers` permet d'ajouter des en-tetes specifiques au
    fournisseur (ex: `x-opencode-session` pour OpenCode Go).
    """

    def __init__(
        self,
        api_key: str,
        model: str = "gpt-4",
        base_url: str = "https://api.openai.com/v1",
        timeout_seconds: float = 300.0,
        extra_headers: dict[str, str] | None = None,
    ) -> None:
        self._api_key = api_key
        self._model = model
        self._base_url = base_url.rstrip("/")
        self._timeout_seconds = timeout_seconds
        self._extra_headers = dict(extra_headers or {})

    async def generate(self, prompt: str, system: str | None = None) -> str:
        messages: list[dict] = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})

        payload: dict = {"model": self._model, "messages": messages, "temperature": 0}
        headers = {
            "Authorization": f"Bearer {self._api_key}",
            "User-Agent": "recon-copilot/0.1",
        }
        headers.update(self._extra_headers)

        try:
            async with httpx.AsyncClient(timeout=self._timeout_seconds) as client:
                response = await client.post(
                    f"{self._base_url}/chat/completions", json=payload, headers=headers
                )
                response.raise_for_status()
        except httpx.ConnectError as exc:
            raise LlmError(
                f"Impossible de joindre l'API OpenAI sur {self._base_url} -- "
                f"verifie la cle API et l'acces reseau."
            ) from exc
        except httpx.TimeoutException as exc:
            raise LlmError(f"L'API OpenAI n'a pas repondu apres {self._timeout_seconds}s.") from exc
        except httpx.HTTPStatusError as exc:
            raise LlmError(
                f"L'API OpenAI a renvoye une erreur HTTP {exc.response.status_code}: "
                f"{exc.response.text[:300]}"
            ) from exc

        data = response.json()
        try:
            text = data["choices"][0]["message"]["content"]
        except (KeyError, IndexError, TypeError) as exc:
            raise LlmError(f"Reponse OpenAI sans champ 'choices[0].message.content': {data!r}") from exc
        if text is None:
            raise LlmError(f"Reponse OpenAI sans contenu: {data!r}")
        return text


class OllamaClient(LlmClient):
    def __init__(self, host: str = "http://localhost:11434", model: str = "llama3", timeout_seconds: float = 600.0) -> None:
        self._host = host.rstrip("/")
        self._model = model
        self._timeout_seconds = timeout_seconds

    async def generate(self, prompt: str, system: str | None = None) -> str:
        payload: dict = {"model": self._model, "prompt": prompt, "stream": False}
        if system:
            payload["system"] = system

        try:
            async with httpx.AsyncClient(timeout=self._timeout_seconds) as client:
                response = await client.post(f"{self._host}/api/generate", json=payload)
                response.raise_for_status()
        except httpx.ConnectError as exc:
            raise LlmError(
                f"Impossible de joindre Ollama sur {self._host} -- verifie qu'il tourne "
                f"('ollama serve') et que le modele '{self._model}' est telecharge ('ollama pull {self._model}')."
            ) from exc
        except httpx.TimeoutException as exc:
            raise LlmError(f"Ollama n'a pas repondu apres {self._timeout_seconds}s.") from exc
        except httpx.HTTPStatusError as exc:
            raise LlmError(f"Ollama a renvoye une erreur HTTP {exc.response.status_code}: {exc.response.text[:300]}") from exc

        data = response.json()
        text = data.get("response")
        if text is None:
            raise LlmError(f"Reponse Ollama sans champ 'response': {data!r}")
        return text
