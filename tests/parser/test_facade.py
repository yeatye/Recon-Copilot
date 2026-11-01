from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from recon_copilot.parser import parse_and_store, parse_raw_result
from recon_copilot.parser.models import NmapParseResult, NucleiParseResult
from recon_copilot.scanner.models import RawScanResult

FIXTURES = Path(__file__).parent / "fixtures"
NMAP_XML = (FIXTURES / "sample_nmap.xml").read_text()
NUCLEI_JSONL = (FIXTURES / "sample_nuclei.jsonl").read_text()


def _raw_result(tool: str, raw_output: str, db_id: int | None = None) -> RawScanResult:
    now = datetime.now(timezone.utc)
    return RawScanResult(
        tool=tool,
        target="10.0.0.5",
        aggressiveness="standard",
        command=(tool,),
        raw_output=raw_output,
        exit_code=0,
        started_at=now,
        finished_at=now,
        db_id=db_id,
    )


def _insert_raw_scan_result(conn, tool: str, raw_output: str) -> int:
    cursor = conn.execute(
        """
        INSERT INTO raw_scan_results (timestamp, engagement, tool, target, aggressiveness, command, raw_output, exit_code)
        VALUES (?, 'test-engagement', ?, '10.0.0.5', 'standard', ?, ?, 0)
        """,
        (datetime.now(timezone.utc).isoformat(), tool, tool, raw_output),
    )
    conn.commit()
    return cursor.lastrowid


def test_parse_raw_result_dispatches_nmap():
    parsed = parse_raw_result(_raw_result("nmap", NMAP_XML))
    assert isinstance(parsed, NmapParseResult)


def test_parse_raw_result_dispatches_nuclei():
    parsed = parse_raw_result(_raw_result("nuclei", NUCLEI_JSONL))
    assert isinstance(parsed, NucleiParseResult)


def test_parse_raw_result_unknown_tool_raises():
    with pytest.raises(ValueError):
        parse_raw_result(_raw_result("ffuf", "whatever"))


def test_parse_and_store_requires_db_id(db_conn):
    result = _raw_result("nmap", NMAP_XML, db_id=None)
    with pytest.raises(ValueError):
        parse_and_store(db_conn, "test-engagement", result)


def test_parse_and_store_persists_nmap_hosts_and_ports(db_conn):
    raw_id = _insert_raw_scan_result(db_conn, "nmap", NMAP_XML)
    result = _raw_result("nmap", NMAP_XML, db_id=raw_id)

    parsed = parse_and_store(db_conn, "test-engagement", result)

    assert isinstance(parsed, NmapParseResult)
    hosts = db_conn.execute("SELECT * FROM parsed_hosts").fetchall()
    assert len(hosts) == 2
    ports = db_conn.execute("SELECT * FROM parsed_ports").fetchall()
    assert len(ports) == 3
    scripts = db_conn.execute("SELECT * FROM nmap_script_outputs").fetchall()
    assert len(scripts) == 1
    extraports = db_conn.execute("SELECT * FROM parsed_extraports").fetchall()
    assert len(extraports) == 1
    assert extraports[0]["state"] == "filtered"
    assert extraports[0]["count"] == 97

    up_host = next(h for h in hosts if h["ip"] == "10.0.0.5")
    assert json.loads(up_host["hostnames"]) == ["app.client.local"]
    assert up_host["raw_scan_result_id"] == raw_id
    assert up_host["engagement"] == "test-engagement"


def test_parse_and_store_persists_nuclei_detections(db_conn):
    raw_id = _insert_raw_scan_result(db_conn, "nuclei", NUCLEI_JSONL)
    result = _raw_result("nuclei", NUCLEI_JSONL, db_id=raw_id)

    parsed = parse_and_store(db_conn, "test-engagement", result)

    assert isinstance(parsed, NucleiParseResult)
    rows = db_conn.execute("SELECT * FROM nuclei_detections ORDER BY id").fetchall()
    assert len(rows) == 3  # 5 lignes - 1 JSON invalide - 1 template-id vide
    critical = next(r for r in rows if r["template_id"] == "critical-rce-cve-2026-0001")
    assert critical["severity"] == "critical"
    assert critical["raw_scan_result_id"] == raw_id


def test_parse_and_store_logs_nuclei_line_errors_to_parse_errors_table(db_conn):
    raw_id = _insert_raw_scan_result(db_conn, "nuclei", NUCLEI_JSONL)
    result = _raw_result("nuclei", NUCLEI_JSONL, db_id=raw_id)

    parse_and_store(db_conn, "test-engagement", result)

    errors = db_conn.execute("SELECT * FROM parse_errors WHERE tool='nuclei'").fetchall()
    assert len(errors) == 2  # 1 ligne non-JSON + 1 template-id manquant
    assert all(e["raw_scan_result_id"] == raw_id for e in errors)


def test_parse_and_store_returns_none_and_logs_on_unparseable_nmap(db_conn):
    raw_id = _insert_raw_scan_result(db_conn, "nmap", "")
    result = _raw_result("nmap", "", db_id=raw_id)

    parsed = parse_and_store(db_conn, "test-engagement", result)

    assert parsed is None
    errors = db_conn.execute("SELECT * FROM parse_errors WHERE tool='nmap'").fetchall()
    assert len(errors) == 1
    assert errors[0]["raw_scan_result_id"] == raw_id
    hosts = db_conn.execute("SELECT * FROM parsed_hosts").fetchall()
    assert hosts == []
