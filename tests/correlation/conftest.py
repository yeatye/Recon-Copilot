from __future__ import annotations

import pytest

from recon_copilot.llm_client import LlmClient, LlmError


class FakeLlmClient(LlmClient):
    """Double de test : renvoie une reponse pre-configuree, ne fait jamais de reseau."""

    def __init__(self, response: str = "[]", raise_error: bool = False):
        self.response = response
        self.raise_error = raise_error
        self.calls: list[tuple[str, str | None]] = []

    async def generate(self, prompt: str, system: str | None = None) -> str:
        self.calls.append((prompt, system))
        if self.raise_error:
            raise LlmError("Ollama injoignable (simule)")
        return self.response


@pytest.fixture
def fake_llm_client():
    return FakeLlmClient()
