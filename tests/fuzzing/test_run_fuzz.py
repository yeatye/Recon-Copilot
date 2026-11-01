from __future__ import annotations

import json

import httpx
import pytest

from recon_copilot.fuzzing import FuzzingDisabledError, run_fuzz
from tests.correlation.conftest import FakeLlmClient


def _baseline_client(status: int = 404, body: bytes = b"not found") -> httpx.AsyncClient:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(status, content=body)

    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


async def test_stealth_profile_blocks_fuzzing_by_default(fake_ffuf_subprocess, db_conn, scope_guard):
    llm = FakeLlmClient(response="[]")
    with pytest.raises(FuzzingDisabledError):
        async with _baseline_client() as http_client:
            await run_fuzz(
                db_conn, "eng-1", "10.0.0.5", 80, "furtif", "nginx",
                llm, scope_guard, chosen_by="houda", http_client=http_client,
            )
    assert fake_ffuf_subprocess.captured_commands == []  # jamais lance


async def test_standard_profile_allows_fuzzing(fake_ffuf_subprocess, db_conn, scope_guard):
    fake_ffuf_subprocess(json.dumps({"results": []}))
    llm = FakeLlmClient(response=json.dumps([{"payload": "/admin", "description": "x"}]))

    async with _baseline_client() as http_client:
        result = await run_fuzz(
            db_conn, "eng-1", "10.0.0.5", 80, "standard", "nginx",
            llm, scope_guard, chosen_by="houda", http_client=http_client,
        )

    assert result.hits == ()
    assert len(fake_ffuf_subprocess.captured_commands) == 1


async def test_force_enable_overrides_stealth_profile(fake_ffuf_subprocess, db_conn, scope_guard):
    fake_ffuf_subprocess(json.dumps({"results": []}))
    llm = FakeLlmClient(response="[]")

    async with _baseline_client() as http_client:
        result = await run_fuzz(
            db_conn, "eng-1", "10.0.0.5", 80, "furtif", "nginx",
            llm, scope_guard, chosen_by="houda", force_enable=True, http_client=http_client,
        )
    assert len(fake_ffuf_subprocess.captured_commands) == 1


async def test_anomaly_triggers_exactly_one_triage_call(fake_ffuf_subprocess, db_conn, scope_guard):
    ffuf_output = json.dumps(
        {"results": [{"input": {"FUZZ": "admin"}, "status": 200, "length": 9999, "duration": 5_000_000}]}
    )
    fake_ffuf_subprocess(ffuf_output)
    llm = FakeLlmClient(response="[]")  # utilise pour generation ET triage (2 appels au total attendus)

    async with _baseline_client(status=404, body=b"x" * 50) as http_client:
        result = await run_fuzz(
            db_conn, "eng-1", "10.0.0.5", 80, "standard", "nginx",
            llm, scope_guard, chosen_by="houda", http_client=http_client,
        )

    assert len(result.anomalies) == 1
    # 1 appel generation payloads + 1 appel triage (car >=1 anomalie) = 2
    assert len(llm.calls) == 2


async def test_no_anomaly_means_no_triage_call(fake_ffuf_subprocess, db_conn, scope_guard):
    ffuf_output = json.dumps(
        {"results": [{"input": {"FUZZ": "admin"}, "status": 404, "length": 50, "duration": 5_000_000}]}
    )
    fake_ffuf_subprocess(ffuf_output)
    llm = FakeLlmClient(response="[]")

    async with _baseline_client(status=404, body=b"x" * 50) as http_client:
        result = await run_fuzz(
            db_conn, "eng-1", "10.0.0.5", 80, "standard", "nginx",
            llm, scope_guard, chosen_by="houda", http_client=http_client,
        )

    assert result.anomalies == ()
    # seulement l'appel de generation de payloads, pas de triage
    assert len(llm.calls) == 1


async def test_results_persisted_to_fuzz_results_table(fake_ffuf_subprocess, db_conn, scope_guard):
    ffuf_output = json.dumps(
        {"results": [{"input": {"FUZZ": "admin"}, "status": 404, "length": 50, "duration": 5_000_000}]}
    )
    fake_ffuf_subprocess(ffuf_output)
    llm = FakeLlmClient(response="[]")

    async with _baseline_client(status=404, body=b"x" * 50) as http_client:
        await run_fuzz(
            db_conn, "eng-1", "10.0.0.5", 80, "standard", "nginx",
            llm, scope_guard, chosen_by="houda", http_client=http_client,
        )

    rows = db_conn.execute("SELECT * FROM fuzz_results").fetchall()
    assert len(rows) == 1
    assert rows[0]["engagement"] == "eng-1"
    assert rows[0]["is_anomaly"] == 0


async def test_scope_violation_raised_before_any_llm_or_network_call(fake_ffuf_subprocess, db_conn):
    from recon_copilot.scope import ScopeViolation
    from tests.conftest import make_scope_guard

    guard = make_scope_guard(allowed=("10.0.0.0/24",))
    llm = FakeLlmClient(response="[]")

    with pytest.raises(ScopeViolation):
        await run_fuzz(
            db_conn, "eng-1", "8.8.8.8", 80, "standard", "nginx",
            llm, guard, chosen_by="houda",
        )

    assert fake_ffuf_subprocess.captured_commands == []
    assert len(llm.calls) == 0  # ni la generation de payloads ni le triage n'ont ete appeles
