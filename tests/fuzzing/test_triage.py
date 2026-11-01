from __future__ import annotations

import json

from recon_copilot.fuzzing.models import FuzzHit
from recon_copilot.fuzzing.triage import parse_triage_response, triage_anomalies
from tests.correlation.conftest import FakeLlmClient

ANOMALY = FuzzHit(payload="/admin", status_code=200, body_size=5000, response_time_ms=40.0, is_anomaly=True)


def test_no_anomalies_means_no_llm_call():
    pass  # couvert par test_triage_anomalies_skips_llm_call_when_no_anomalies (async)


async def test_triage_anomalies_skips_llm_call_when_no_anomalies():
    llm = FakeLlmClient(response="[]")
    triage, warnings = await triage_anomalies([], 404, 100, llm)
    assert triage == []
    assert warnings == []
    assert len(llm.calls) == 0  # exigence du cahier des charges : zero appel si zero anomalie


async def test_triage_anomalies_makes_exactly_one_call_for_multiple_anomalies():
    anomalies = [ANOMALY, FuzzHit(payload="/.env", status_code=200, body_size=300, response_time_ms=30.0, is_anomaly=True)]
    llm = FakeLlmClient(response=json.dumps([
        {"payload": "/admin", "explanation": "panel expose", "severity_guess": "medium"},
        {"payload": "/.env", "explanation": "fichier de config", "severity_guess": "high"},
    ]))

    triage, warnings = await triage_anomalies(anomalies, 404, 100, llm)

    assert len(llm.calls) == 1  # un seul appel groupe, jamais un par anomalie
    assert len(triage) == 2


def test_parse_triage_response_valid():
    response = json.dumps([{"payload": "/admin", "explanation": "x", "severity_guess": "medium"}])
    triage, warnings = parse_triage_response(response)
    assert len(triage) == 1
    assert warnings == []


def test_parse_triage_response_invalid_json():
    triage, warnings = parse_triage_response("not json")
    assert triage == []
    assert len(warnings) == 1
