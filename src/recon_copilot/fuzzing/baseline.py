"""Etablissement de la baseline avant fuzzing.

La comparaison anomalie/normal (voir diff.py) n'a de sens que par rapport
a une reponse "normale" mesuree sur la cible elle-meme, pas sur des seuils
fixes en dur -- une appli qui renvoie 500 pour tout n'a pas les memes
codes "normaux" qu'une autre.
"""

from __future__ import annotations

import time

import httpx

from recon_copilot.fuzzing.models import BaselineResponse


async def fetch_baseline(url: str, http_client: httpx.AsyncClient | None = None, timeout_seconds: float = 15.0) -> BaselineResponse:
    """Effectue une requete non-fuzzee sur `url` pour etablir la reponse de reference.

    `http_client` est injectable pour les tests (httpx.AsyncClient avec un
    MockTransport) -- en usage reel, un client par defaut est cree.
    """
    owns_client = http_client is None
    client = http_client or httpx.AsyncClient(timeout=timeout_seconds)
    try:
        started = time.monotonic()
        response = await client.get(url)
        elapsed_ms = (time.monotonic() - started) * 1000
        return BaselineResponse(
            status_code=response.status_code,
            body_size=len(response.content),
            response_time_ms=elapsed_ms,
        )
    finally:
        if owns_client:
            await client.aclose()
