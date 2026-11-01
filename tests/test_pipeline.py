from __future__ import annotations

import json

from recon_copilot.pipeline import (
    load_engagement_config,
    run_pipeline,
)
from tests.correlation.conftest import FakeLlmClient
from tests.scanner.conftest import FakeProcess

NMAP_XML = """<?xml version="1.0"?>
<nmaprun>
<host>
<status state="up"/>
<address addr="10.0.0.5" addrtype="ipv4"/>
<hostnames><hostname name="app.client.local"/></hostnames>
<ports>
<port protocol="tcp" portid="80">
<state state="open"/>
<service name="http" product="nginx" version="1.24.0"/>
</port>
</ports>
</host>
</nmaprun>"""

NUCLEI_JSONL = (
    '{"template-id": "exposed-panel-generic", "info": {"name": "Exposed Admin Panel", '
    '"severity": "medium", "tags": ["panel"]}, "matched-at": "http://10.0.0.5:80/admin"}'
)


def _write_engagement_config(tmp_path, db_path) -> str:
    config = tmp_path / "engagement.yaml"
    config.write_text(
        f"""
engagement:
  name: eng-pipeline-test
  analyst: houda
scope:
  allowed_targets:
    - "10.0.0.0/24"
  allowed_ports: []
  excluded_targets: []
aggressiveness:
  default_profile: standard
  allow_cli_override: true
audit:
  db_path: "{db_path}"
llm:
  provider: "openai"
  api_key: "sk-test"
  base_url: "https://api.openai.com/v1"
  model: "gpt-4"
  timeout_seconds: 300
"""
    )
    return str(config)


def test_load_engagement_config_parses_all_fields(tmp_path):
    config_path = _write_engagement_config(tmp_path, str(tmp_path / "db.sqlite"))
    config = load_engagement_config(config_path)
    assert config.name == "eng-pipeline-test"
    assert config.scope.allowed_targets == ("10.0.0.0/24",)
    assert config.default_profile == "standard"
    assert config.llm_provider == "openai"
    assert config.llm_api_key == "sk-test"
    assert config.llm_model == "gpt-4"


def test_load_engagement_config_opencode_provider_defaults(tmp_path, monkeypatch):
    monkeypatch.delenv("OPENCODE_API_KEY", raising=False)
    config = tmp_path / "engagement.yaml"
    config.write_text(
        """
engagement:
  name: eng-opencode
  analyst: houda
scope:
  allowed_targets: ["10.0.0.1"]
  allowed_ports: []
  excluded_targets: []
aggressiveness:
  default_profile: standard
audit:
  db_path: "./data/db.sqlite"
llm:
  provider: "opencode"
  api_key: "sk-test-opencode"
"""
    )
    loaded = load_engagement_config(str(config))
    assert loaded.llm_provider == "opencode"
    assert loaded.llm_base_url == "https://opencode.ai/zen/v1"
    assert loaded.llm_model == "deepseek-v4-flash-free"
    assert loaded.llm_api_key == "sk-test-opencode"


def test_load_engagement_config_parses_rag_section(tmp_path):
    config = tmp_path / "engagement.yaml"
    config.write_text(
        """
engagement:
  name: eng-rag
  analyst: houda
scope:
  allowed_targets: ["10.0.0.1"]
  allowed_ports: []
  excluded_targets: []
aggressiveness:
  default_profile: standard
audit:
  db_path: "./data/db.sqlite"
llm:
  provider: "opencode"
  api_key: "sk-test-opencode"
rag:
  enabled: true
  persist_directory: "/tmp/custom_rag_index"
  cisa_kev_path: "/tmp/kev.json"
  nuclei_templates_dir: "/tmp/nuclei"
"""
    )
    loaded = load_engagement_config(str(config))
    assert loaded.rag.enabled is True
    assert loaded.rag.persist_directory == "/tmp/custom_rag_index"
    assert loaded.rag.cisa_kev_path == "/tmp/kev.json"
    assert loaded.rag.nuclei_templates_dir == "/tmp/nuclei"


def test_load_engagement_config_rag_disabled_by_default(tmp_path):
    config = tmp_path / "engagement.yaml"
    config.write_text(
        """
engagement:
  name: eng-no-rag
  analyst: houda
scope:
  allowed_targets: ["10.0.0.1"]
  allowed_ports: []
  excluded_targets: []
aggressiveness:
  default_profile: standard
audit:
  db_path: "./data/db.sqlite"
llm:
  provider: "opencode"
  api_key: "sk-test-opencode"
"""
    )
    loaded = load_engagement_config(str(config))
    assert loaded.rag.enabled is False
    assert loaded.rag.persist_directory == "./data/rag_index"


async def test_build_rag_index_disabled_returns_none(tmp_path):
    from recon_copilot.pipeline import _build_rag_index

    config = tmp_path / "engagement.yaml"
    config.write_text(
        """
engagement:
  name: eng-no-rag
  analyst: houda
scope:
  allowed_targets: ["10.0.0.1"]
  allowed_ports: []
  excluded_targets: []
aggressiveness:
  default_profile: standard
audit:
  db_path: "./data/db.sqlite"
llm:
  provider: "opencode"
  api_key: "sk-test-opencode"
"""
    )
    loaded = load_engagement_config(str(config))
    index, warnings = await _build_rag_index(loaded)
    assert index is None
    assert warnings == []


async def test_build_rag_index_enabled_indexes_sources_once(tmp_path, monkeypatch):
    from recon_copilot.pipeline import _build_rag_index

    kev = tmp_path / "known_exploited_vulnerabilities.json"
    kev.write_text(
        json.dumps(
            {
                "vulnerabilities": [
                    {
                        "cveID": "CVE-2021-44228",
                        "vulnerabilityName": "Log4Shell",
                        "shortDescription": "RCE dans Log4j.",
                        "requiredAction": "Patiner les logs.",
                        "vendorProject": "Apache",
                        "product": "Log4j",
                    }
                ]
            }
        )
    )
    nuclei_dir = tmp_path / "nuclei"
    nuclei_dir.mkdir()
    (nuclei_dir / "log4j.yaml").write_text(
        "id: log4shell-probe\ninfo:\n  name: Log4Shell\n  description: Detecte Log4Shell.\n  severity: critical\n"
    )

    persist_dir = tmp_path / "rag_index"
    config = tmp_path / "engagement.yaml"
    config.write_text(
        f"""
engagement:
  name: eng-rag
  analyst: houda
scope:
  allowed_targets: ["10.0.0.1"]
  allowed_ports: []
  excluded_targets: []
aggressiveness:
  default_profile: standard
audit:
  db_path: "{tmp_path}/db.sqlite"
llm:
  provider: "opencode"
  api_key: "sk-test-opencode"
rag:
  enabled: true
  persist_directory: "{persist_dir}"
  cisa_kev_path: "{kev}"
  nuclei_templates_dir: "{nuclei_dir}"
"""
    )

    from tests.conftest import FakeEmbeddingClient

    monkeypatch.setattr(
        "recon_copilot.pipeline.LocalEmbeddingClient", lambda: FakeEmbeddingClient()
    )

    loaded = load_engagement_config(str(config))
    index, warnings = await _build_rag_index(loaded)
    assert index is not None
    assert index.count() == 2  # 1 KEV + 1 template Nuclei
    assert any("documents indexes" in w for w in warnings)

    index2, warnings2 = await _build_rag_index(loaded)
    assert index2.count() == 2  # reutilise, pas re-indexe
    assert not any("documents indexes" in w for w in warnings2)


async def test_build_rag_index_enabled_missing_sources_warns(tmp_path, monkeypatch):
    from recon_copilot.pipeline import _build_rag_index

    persist_dir = tmp_path / "rag_index"
    config = tmp_path / "engagement.yaml"
    config.write_text(
        f"""
engagement:
  name: eng-rag
  analyst: houda
scope:
  allowed_targets: ["10.0.0.1"]
  allowed_ports: []
  excluded_targets: []
aggressiveness:
  default_profile: standard
audit:
  db_path: "{tmp_path}/db.sqlite"
llm:
  provider: "opencode"
  api_key: "sk-test-opencode"
rag:
  enabled: true
  persist_directory: "{persist_dir}"
  cisa_kev_path: "{tmp_path}/missing_kev.json"
  nuclei_templates_dir: "{tmp_path}/missing_nuclei"
"""
    )

    from tests.conftest import FakeEmbeddingClient

    monkeypatch.setattr(
        "recon_copilot.pipeline.LocalEmbeddingClient", lambda: FakeEmbeddingClient()
    )

    loaded = load_engagement_config(str(config))
    index, warnings = await _build_rag_index(loaded)
    assert index is not None
    assert any("CISA KEV absent" in w for w in warnings)
    assert any("aucun document ingere" in w for w in warnings)


async def test_run_pipeline_passes_rag_index_to_correlation(tmp_path, monkeypatch):
    import recon_copilot.pipeline as pipeline

    async def fake_create_subprocess_exec(*command, **kwargs):
        if "nmap" in command[0]:
            return FakeProcess(stdout=NMAP_XML.encode(), returncode=0)
        return FakeProcess(stdout=NUCLEI_JSONL.encode(), returncode=0)

    monkeypatch.setattr(
        "recon_copilot.external_tool.asyncio.create_subprocess_exec", fake_create_subprocess_exec
    )

    async def fake_build_rag_index(config):
        return ("FAKE_INDEX", [])

    monkeypatch.setattr(pipeline, "_build_rag_index", fake_build_rag_index)

    original_correlate = pipeline.correlate_and_store
    captured = {}

    async def spy_correlate(conn, engagement, target, llm_client, host, nuclei_detections,
                            rag_index=None, rag_n_results=3):
        captured["rag_index"] = rag_index
        return await original_correlate(conn, engagement, target, llm_client, host, nuclei_detections)

    monkeypatch.setattr(pipeline, "correlate_and_store", spy_correlate)

    db_path = str(tmp_path / "engagement.db")
    config_path = tmp_path / "engagement.yaml"
    config_path.write_text(
        f"""
engagement:
  name: eng-rag
  analyst: houda
scope:
  allowed_targets:
    - "10.0.0.0/24"
  allowed_ports: []
  excluded_targets: []
aggressiveness:
  default_profile: standard
audit:
  db_path: "{db_path}"
llm:
  provider: "openai"
  api_key: "sk-test"
  base_url: "https://api.openai.com/v1"
  model: "gpt-4"
rag:
  enabled: true
  persist_directory: "{tmp_path}/rag_index"
"""
    )
    llm = FakeLlmClient(response=_valid_finding_response())

    summary = await run_pipeline(str(config_path), "10.0.0.5", "houda", llm_client=llm)

    assert summary.findings_proposed == 1
    assert captured["rag_index"] == "FAKE_INDEX"


def _valid_finding_response() -> str:
    return json.dumps(
        [
            {
                "title": "Panneau admin expose",
                "description": "Panel accessible sans authentification.",
                "severity": "medium",
                "cvss_score": 5.3,
                "confidence": "high",
                "source_type": "nuclei",
                "source_citation": NUCLEI_JSONL,
                "cve_refs": [],
                "cwe_refs": ["CWE-284"],
                "mitre_refs": ["T1595.002"],
                "remediation": "Restreindre l'acces.",
            }
        ]
    )


async def test_run_pipeline_full_flow(tmp_path, monkeypatch):
    call_count = {"n": 0}

    async def fake_create_subprocess_exec(*command, **kwargs):
        call_count["n"] += 1
        if "nmap" in command[0]:
            return FakeProcess(stdout=NMAP_XML.encode(), returncode=0)
        return FakeProcess(stdout=NUCLEI_JSONL.encode(), returncode=0)

    monkeypatch.setattr(
        "recon_copilot.external_tool.asyncio.create_subprocess_exec", fake_create_subprocess_exec
    )

    db_path = str(tmp_path / "engagement.db")
    config_path = _write_engagement_config(tmp_path, db_path)
    llm = FakeLlmClient(response=_valid_finding_response())

    summary = await run_pipeline(
        config_path, "10.0.0.5", "houda", aggressiveness="standard",
        comment="test pipeline", llm_client=llm,
    )

    assert summary.hosts_parsed == 1
    assert summary.nuclei_detections_parsed == 1
    assert summary.findings_proposed == 1
    assert summary.findings_unverified_citations == 0
    assert call_count["n"] == 2  # nmap + nuclei


async def test_run_pipeline_persists_scored_pending_finding(tmp_path, monkeypatch):
    async def fake_create_subprocess_exec(*command, **kwargs):
        if "nmap" in command[0]:
            return FakeProcess(stdout=NMAP_XML.encode(), returncode=0)
        return FakeProcess(stdout=NUCLEI_JSONL.encode(), returncode=0)

    monkeypatch.setattr(
        "recon_copilot.external_tool.asyncio.create_subprocess_exec", fake_create_subprocess_exec
    )

    db_path = str(tmp_path / "engagement.db")
    config_path = _write_engagement_config(tmp_path, db_path)
    llm = FakeLlmClient(response=_valid_finding_response())

    await run_pipeline(config_path, "10.0.0.5", "houda", llm_client=llm)

    from recon_copilot.db import get_connection
    conn = get_connection(db_path)
    row = conn.execute("SELECT review_status, risk_score, risk_level FROM correlated_findings").fetchone()
    assert row["review_status"] == "pending"
    assert row["risk_score"] is not None
    assert row["risk_level"] is not None


async def test_run_pipeline_scope_violation_blocks_before_llm_call(tmp_path, monkeypatch):
    calls = {"n": 0}

    async def fake_create_subprocess_exec(*command, **kwargs):
        calls["n"] += 1
        return FakeProcess(stdout=b"", returncode=0)

    monkeypatch.setattr(
        "recon_copilot.external_tool.asyncio.create_subprocess_exec", fake_create_subprocess_exec
    )

    db_path = str(tmp_path / "engagement.db")
    config_path = _write_engagement_config(tmp_path, db_path)
    llm = FakeLlmClient(response="[]")

    import pytest
    from recon_copilot.scope import ScopeViolation

    with pytest.raises(ScopeViolation):
        await run_pipeline(config_path, "8.8.8.8", "houda", llm_client=llm)

    assert calls["n"] == 0
    assert len(llm.calls) == 0
