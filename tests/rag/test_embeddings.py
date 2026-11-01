from __future__ import annotations

import httpx
import pytest

from recon_copilot.llm_client import LlmError
from recon_copilot.rag.embeddings import (
    LocalEmbeddingClient,
    OpenAIEmbeddingClient,
    OllamaEmbeddingClient,
)


class _FakeLocalFn:
    """Double du callable ONNX de Chroma (DefaultEmbeddingFunction)."""

    def __init__(self, vectors):
        self._vectors = vectors
        self.calls = []

    def __call__(self, texts):
        self.calls.append(list(texts))
        return self._vectors


async def test_local_embed_returns_vectors():
    fake = _FakeLocalFn([[0.1, 0.2], [0.3, 0.4]])
    client = LocalEmbeddingClient.__new__(LocalEmbeddingClient)
    client._fn = fake

    result = await client.embed(["texte 1", "texte 2"])
    assert result == [[0.1, 0.2], [0.3, 0.4]]
    assert fake.calls == [["texte 1", "texte 2"]]


async def test_local_embed_empty_list_skips_local_model():
    fake = _FakeLocalFn([])
    client = LocalEmbeddingClient.__new__(LocalEmbeddingClient)
    client._fn = fake

    result = await client.embed([])
    assert result == []
    assert fake.calls == []


async def test_openai_embed_returns_vectors(monkeypatch):
    async def fake_post(self, url, json=None, headers=None, **kwargs):
        request = httpx.Request("POST", url)
        payload = {"data": [{"embedding": [0.1, 0.2]}, {"embedding": [0.3, 0.4]}]}
        return httpx.Response(200, json=payload, request=request)

    monkeypatch.setattr(httpx.AsyncClient, "post", fake_post)

    client = OpenAIEmbeddingClient(api_key="sk-test")
    result = await client.embed(["texte 1", "texte 2"])
    assert result == [[0.1, 0.2], [0.3, 0.4]]


async def test_openai_embed_sends_bearer_and_uses_embeddings_endpoint(monkeypatch):
    captured = {}

    async def fake_post(self, url, json=None, headers=None, **kwargs):
        captured["url"] = url
        captured["json"] = json
        captured["headers"] = headers
        request = httpx.Request("POST", url)
        payload = {"data": [{"embedding": [1.0]}]}
        return httpx.Response(200, json=payload, request=request)

    monkeypatch.setattr(httpx.AsyncClient, "post", fake_post)

    client = OpenAIEmbeddingClient(api_key="sk-secret", model="text-embedding-3-small")
    await client.embed(["hello"])

    assert captured["url"] == "https://api.openai.com/v1/embeddings"
    assert captured["headers"]["Authorization"] == "Bearer sk-secret"
    assert captured["json"]["model"] == "text-embedding-3-small"
    assert captured["json"]["input"] == ["hello"]


async def test_openai_embed_empty_list_returns_empty_without_http_call(monkeypatch):
    called = {"n": 0}

    async def fake_post(self, url, json=None, headers=None, **kwargs):
        called["n"] += 1
        return httpx.Response(200, json={"data": []})

    monkeypatch.setattr(httpx.AsyncClient, "post", fake_post)

    client = OpenAIEmbeddingClient(api_key="sk-test")
    result = await client.embed([])
    assert result == []
    assert called["n"] == 0


async def test_openai_embed_connect_error_raises_llm_error(monkeypatch):
    async def fake_post(self, url, json=None, headers=None, **kwargs):
        raise httpx.ConnectError("connection refused")

    monkeypatch.setattr(httpx.AsyncClient, "post", fake_post)

    client = OpenAIEmbeddingClient(api_key="sk-test")
    with pytest.raises(LlmError):
        await client.embed(["x"])


async def test_openai_embed_too_few_vectors_raises_llm_error(monkeypatch):
    async def fake_post(self, url, json=None, headers=None, **kwargs):
        request = httpx.Request("POST", url)
        return httpx.Response(200, json={"data": [{"embedding": [1.0]}]}, request=request)

    monkeypatch.setattr(httpx.AsyncClient, "post", fake_post)

    client = OpenAIEmbeddingClient(api_key="sk-test")
    with pytest.raises(LlmError):
        await client.embed(["a", "b"])


async def test_embed_returns_vectors(monkeypatch):
    async def fake_post(self, url, json=None, **kwargs):
        request = httpx.Request("POST", url)
        return httpx.Response(200, json={"embeddings": [[0.1, 0.2], [0.3, 0.4]]}, request=request)

    monkeypatch.setattr(httpx.AsyncClient, "post", fake_post)

    client = OllamaEmbeddingClient(host="http://fake-ollama:11434")
    result = await client.embed(["texte 1", "texte 2"])
    assert result == [[0.1, 0.2], [0.3, 0.4]]


async def test_embed_empty_list_returns_empty_without_http_call(monkeypatch):
    called = {"n": 0}

    async def fake_post(self, url, json=None, **kwargs):
        called["n"] += 1
        return httpx.Response(200, json={"embeddings": []})

    monkeypatch.setattr(httpx.AsyncClient, "post", fake_post)

    client = OllamaEmbeddingClient(host="http://fake-ollama:11434")
    result = await client.embed([])
    assert result == []
    assert called["n"] == 0


async def test_embed_missing_field_raises_llm_error(monkeypatch):
    async def fake_post(self, url, json=None, **kwargs):
        request = httpx.Request("POST", url)
        return httpx.Response(200, json={"unexpected": "shape"}, request=request)

    monkeypatch.setattr(httpx.AsyncClient, "post", fake_post)

    client = OllamaEmbeddingClient(host="http://fake-ollama:11434")
    with pytest.raises(LlmError):
        await client.embed(["x"])


async def test_embed_connect_error_raises_llm_error_with_helpful_message(monkeypatch):
    async def fake_post(self, url, json=None, **kwargs):
        raise httpx.ConnectError("connection refused")

    monkeypatch.setattr(httpx.AsyncClient, "post", fake_post)

    client = OllamaEmbeddingClient(host="http://fake-ollama:11434", model="nomic-embed-text")
    with pytest.raises(LlmError, match="nomic-embed-text"):
        await client.embed(["x"])


async def test_embed_http_error_status_raises_llm_error(monkeypatch):
    async def fake_post(self, url, json=None, **kwargs):
        request = httpx.Request("POST", url)
        response = httpx.Response(500, text="internal error", request=request)
        raise httpx.HTTPStatusError("500", request=request, response=response)

    monkeypatch.setattr(httpx.AsyncClient, "post", fake_post)

    client = OllamaEmbeddingClient(host="http://fake-ollama:11434")
    with pytest.raises(LlmError):
        await client.embed(["x"])


async def test_embed_sends_correct_model_and_input(monkeypatch):
    captured = {}

    async def fake_post(self, url, json=None, **kwargs):
        captured["url"] = url
        captured["json"] = json
        request = httpx.Request("POST", url)
        return httpx.Response(200, json={"embeddings": [[1.0]]}, request=request)

    monkeypatch.setattr(httpx.AsyncClient, "post", fake_post)

    client = OllamaEmbeddingClient(host="http://100.64.0.5:11434", model="nomic-embed-text")
    await client.embed(["hello"])

    assert captured["url"] == "http://100.64.0.5:11434/api/embed"
    assert captured["json"]["model"] == "nomic-embed-text"
    assert captured["json"]["input"] == ["hello"]
