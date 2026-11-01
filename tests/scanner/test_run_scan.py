from __future__ import annotations

from recon_copilot.scanner import ScanRequest, run_scan
from tests.scanner.conftest import FakeProcess


async def test_run_scan_persists_and_returns_db_ids(fake_subprocess_exec, db_conn, scope_guard):
    fake_subprocess_exec(FakeProcess(stdout=b"<nmaprun/>", returncode=0))
    request = ScanRequest(
        target="10.0.0.5",
        aggressiveness="standard",
        engagement="test-engagement",
        chosen_by="houda",
        comment="test manuel",
    )

    results = await run_scan(request, scope_guard, db_conn)

    assert len(results) == 2  # nmap puis nuclei
    assert {r.tool for r in results} == {"nmap", "nuclei"}
    for r in results:
        assert r.db_id is not None

    rows = db_conn.execute("SELECT id, tool, engagement FROM raw_scan_results ORDER BY id").fetchall()
    assert len(rows) == 2
    assert {row["tool"] for row in rows} == {"nmap", "nuclei"}
    assert all(row["engagement"] == "test-engagement" for row in rows)
    db_ids_from_rows = {row["id"] for row in rows}
    db_ids_from_results = {r.db_id for r in results}
    assert db_ids_from_rows == db_ids_from_results


async def test_run_scan_logs_pipeline_comment_to_audit(fake_subprocess_exec, db_conn, scope_guard):
    fake_subprocess_exec(FakeProcess(stdout=b"", returncode=0))
    request = ScanRequest(
        target="10.0.0.5",
        aggressiveness="furtif",
        engagement="test-engagement",
        chosen_by="houda",
        comment="raison du choix furtif",
    )

    await run_scan(request, scope_guard, db_conn)

    row = db_conn.execute(
        "SELECT comment, chosen_by FROM audit_log WHERE event_type='pipeline_scan_start'"
    ).fetchone()
    assert row is not None
    assert row["comment"] == "raison du choix furtif"
    assert row["chosen_by"] == "houda"
