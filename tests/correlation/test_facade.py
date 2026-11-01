from __future__ import annotations

import json

import pytest

from recon_copilot.correlation import correlate_and_store
from recon_copilot.llm_client import LlmError
from recon_copilot.parser.nmap_parser import parse_nmap_xml
from recon_copilot.parser.nuclei_parser import parse_nuclei_jsonl
from tests.correlation.conftest import FakeLlmClient

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


def _valid_llm_response(citation: str) -> str:
    return json.dumps(
        [
            {
                "title": "Panneau admin expose",
                "description": "Panel accessible sans authentification.",
                "severity": "medium",
                "cvss_score": 5.3,
                "confidence": "high",
                "source_type": "nuclei",
                "source_citation": citation,
                "cve_refs": [],
                "cwe_refs": ["CWE-284"],
                "mitre_refs": ["T1595.002"],
                "remediation": "Restreindre l'acces.",
            }
        ]
    )


async def test_correlate_and_store_persists_verified_finding(db_conn):
    host = parse_nmap_xml(NMAP_XML).hosts[0]
    detections = parse_nuclei_jsonl(NUCLEI_JSONL).detections
    llm = FakeLlmClient(response=_valid_llm_response(NUCLEI_JSONL))

    result = await correlate_and_store(db_conn, "eng-1", "10.0.0.5", llm, host, list(detections))

    assert len(result.findings) == 1
    assert result.findings[0].citation_verified is True

    rows = db_conn.execute("SELECT * FROM correlated_findings").fetchall()
    assert len(rows) == 1
    assert rows[0]["citation_verified"] == 1
    assert rows[0]["engagement"] == "eng-1"
    assert rows[0]["target"] == "10.0.0.5"
    assert json.loads(rows[0]["cwe_refs"]) == ["CWE-284"]
    assert rows[0]["review_status"] == "pending"
    assert rows[0]["raw_llm_response"] == llm.response


async def test_correlate_and_store_calls_llm_exactly_once(db_conn):
    host = parse_nmap_xml(NMAP_XML).hosts[0]
    detections = parse_nuclei_jsonl(NUCLEI_JSONL).detections
    llm = FakeLlmClient(response="[]")

    await correlate_and_store(db_conn, "eng-1", "10.0.0.5", llm, host, list(detections))

    assert len(llm.calls) == 1


async def test_correlate_and_store_includes_kb_context_in_prompt(db_conn):
    host = parse_nmap_xml(NMAP_XML).hosts[0]
    detections = parse_nuclei_jsonl(NUCLEI_JSONL).detections
    llm = FakeLlmClient(response="[]")

    await correlate_and_store(db_conn, "eng-1", "10.0.0.5", llm, host, list(detections))

    prompt, system = llm.calls[0]
    assert "exposed-panel-generic" in prompt  # la KB match sur ce template
    assert system is not None and "JSON" in system


async def test_correlate_and_store_propagates_llm_error_and_logs(db_conn):
    host = parse_nmap_xml(NMAP_XML).hosts[0]
    llm = FakeLlmClient(raise_error=True)

    with pytest.raises(LlmError):
        await correlate_and_store(db_conn, "eng-1", "10.0.0.5", llm, host, [])

    errors = db_conn.execute("SELECT * FROM parse_errors WHERE tool='correlation'").fetchall()
    assert len(errors) == 1
    assert "injoignable" in errors[0]["detail"]


async def test_correlate_and_store_logs_warnings_for_unverified_citation(db_conn):
    host = parse_nmap_xml(NMAP_XML).hosts[0]
    detections = parse_nuclei_jsonl(NUCLEI_JSONL).detections
    llm = FakeLlmClient(response=_valid_llm_response("citation totalement inventee"))

    result = await correlate_and_store(db_conn, "eng-1", "10.0.0.5", llm, host, list(detections))

    assert result.findings[0].citation_verified is False
    errors = db_conn.execute("SELECT * FROM parse_errors WHERE tool='correlation'").fetchall()
    assert any("citation non retrouvee" in e["detail"] for e in errors)


async def test_correlate_and_store_handles_no_host_nuclei_only(db_conn):
    detections = parse_nuclei_jsonl(NUCLEI_JSONL).detections
    llm = FakeLlmClient(response=_valid_llm_response(NUCLEI_JSONL))

    result = await correlate_and_store(db_conn, "eng-1", "10.0.0.5", llm, None, list(detections))

    assert len(result.findings) == 1
