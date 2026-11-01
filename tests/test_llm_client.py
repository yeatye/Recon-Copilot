from __future__ import annotations

import httpx
import pytest

from recon_copilot.llm_client import LlmError, OpenAIClient


def _completion_response(content: str) -> dict:
    return {"choices": [{"message": {"content": content}}]}


async def test_openai_generate_returns_content(monkeypatch):
    async def fake_post(self, url, json=None, headers=None, **kwargs):
        request = httpx.Request("POST", url)
        return httpx.Response(200, json=_completion_response("hello world"), request=request)

    monkeypatch.setattr(httpx.AsyncClient, "post", fake_post)

    client = OpenAIClient(api_key="sk-test")
    result = await client.generate("bonjour")
    assert result == "hello world"


async def test_openai_generate_includes_system_and_bearer(monkeypatch):
    captured = {}

    async def fake_post(self, url, json=None, headers=None, **kwargs):
        captured["url"] = url
        captured["json"] = json
        captured["headers"] = headers
        request = httpx.Request("POST", url)
        return httpx.Response(200, json=_completion_response("ok"), request=request)

    monkeypatch.setattr(httpx.AsyncClient, "post", fake_post)

    client = OpenAIClient(
        api_key="sk-secret",
        model="gpt-4o",
        base_url="https://api.openai.com/v1",
        timeout_seconds=10.0,
    )
    await client.generate("prompt", system="sois concis")

    assert captured["url"] == "https://api.openai.com/v1/chat/completions"
    assert captured["headers"]["Authorization"] == "Bearer sk-secret"
    assert captured["json"]["model"] == "gpt-4o"
    assert captured["json"]["messages"][0] == {"role": "system", "content": "sois concis"}
    assert captured["json"]["messages"][1] == {"role": "user", "content": "prompt"}


async def test_openai_generate_connect_error_raises_llm_error(monkeypatch):
    async def fake_post(self, url, json=None, headers=None, **kwargs):
        raise httpx.ConnectError("connection refused")

    monkeypatch.setattr(httpx.AsyncClient, "post", fake_post)

    client = OpenAIClient(api_key="sk-test")
    with pytest.raises(LlmError):
        await client.generate("prompt")


async def test_openai_generate_http_error_raises_llm_error(monkeypatch):
    async def fake_post(self, url, json=None, headers=None, **kwargs):
        request = httpx.Request("POST", url)
        response = httpx.Response(401, text="invalid api key", request=request)
        raise httpx.HTTPStatusError("401", request=request, response=response)

    monkeypatch.setattr(httpx.AsyncClient, "post", fake_post)

    client = OpenAIClient(api_key="sk-test")
    with pytest.raises(LlmError):
        await client.generate("prompt")


async def test_openai_generate_missing_content_raises_llm_error(monkeypatch):
    async def fake_post(self, url, json=None, headers=None, **kwargs):
        request = httpx.Request("POST", url)
        return httpx.Response(200, json={"choices": []}, request=request)

    monkeypatch.setattr(httpx.AsyncClient, "post", fake_post)

    client = OpenAIClient(api_key="sk-test")
    with pytest.raises(LlmError):
        await client.generate("prompt")


async def test_openai_generate_extra_headers_are_sent(monkeypatch):
    captured = {}

    async def fake_post(self, url, json=None, headers=None, **kwargs):
        captured["headers"] = headers
        request = httpx.Request("POST", url)
        return httpx.Response(200, json=_completion_response("ok"), request=request)

    monkeypatch.setattr(httpx.AsyncClient, "post", fake_post)

    client = OpenAIClient(
        api_key="sk-test",
        extra_headers={"x-opencode-session": "abc123", "User-Agent": "custom/2.0"},
    )
    await client.generate("prompt")

    assert captured["headers"]["x-opencode-session"] == "abc123"
    assert captured["headers"]["Authorization"] == "Bearer sk-test"