from __future__ import annotations

import json

from recon_copilot.fuzzing.payload_generator import generate_payloads, parse_payload_response
from tests.correlation.conftest import FakeLlmClient


def test_parse_valid_payload_response():
    response = json.dumps(
        [
            {"payload": "/admin", "description": "chemin admin classique"},
            {"payload": "/.env", "description": "fichier de config expose"},
        ]
    )
    payloads, warnings = parse_payload_response(response)
    assert len(payloads) == 2
    assert warnings == []
    assert payloads[0].payload == "/admin"


def test_parse_deduplicates_payloads():
    response = json.dumps([{"payload": "/admin"}, {"payload": "/admin"}])
    payloads, warnings = parse_payload_response(response)
    assert len(payloads) == 1


def test_parse_invalid_json_returns_empty_with_warning():
    payloads, warnings = parse_payload_response("pas du json")
    assert payloads == []
    assert len(warnings) == 1


def test_parse_missing_payload_field_is_skipped():
    response = json.dumps([{"description": "sans payload"}])
    payloads, warnings = parse_payload_response(response)
    assert payloads == []
    assert "manquant" in warnings[0]


async def test_generate_payloads_calls_llm_once_with_tech_hint():
    llm = FakeLlmClient(response=json.dumps([{"payload": "/admin", "description": "x"}]))

    payloads, warnings = await generate_payloads("nginx 1.24.0", llm)

    assert len(llm.calls) == 1
    prompt, system = llm.calls[0]
    assert "nginx 1.24.0" in prompt
    assert len(payloads) == 1
