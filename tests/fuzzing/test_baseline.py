from __future__ import annotations

import httpx

from recon_copilot.fuzzing.baseline import fetch_baseline


async def test_fetch_baseline_captures_status_and_size():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=b"hello world")

    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport) as client:
        baseline = await fetch_baseline("http://10.0.0.5/", http_client=client)

    assert baseline.status_code == 200
    assert baseline.body_size == len(b"hello world")
    assert baseline.response_time_ms >= 0


async def test_fetch_baseline_captures_non_200_status():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(404, content=b"not found")

    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport) as client:
        baseline = await fetch_baseline("http://10.0.0.5/nope", http_client=client)

    assert baseline.status_code == 404
