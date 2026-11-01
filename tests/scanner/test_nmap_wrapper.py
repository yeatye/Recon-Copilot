from __future__ import annotations

import pytest

from recon_copilot.external_tool import ToolExecutionError
from recon_copilot.scanner.nmap_wrapper import NmapWrapper
from recon_copilot.scope import ScopeViolation
from tests.conftest import make_scope_guard
from tests.scanner.conftest import FakeProcess


async def test_scope_violation_blocks_before_any_subprocess_call(fake_subprocess_exec, audit_trail):
    fake_subprocess_exec(FakeProcess(returncode=0))
    guard = make_scope_guard(allowed=("10.0.0.0/24",))
    wrapper = NmapWrapper(guard, audit=audit_trail)

    with pytest.raises(ScopeViolation):
        await wrapper.run("8.8.8.8", "standard")

    assert fake_subprocess_exec.captured_commands == []  # jamais lance


async def test_command_uses_stealth_profile_timing(fake_subprocess_exec, audit_trail, scope_guard):
    fake_subprocess_exec(FakeProcess(stdout=b"<xml/>", returncode=0))
    wrapper = NmapWrapper(scope_guard, audit=audit_trail)

    await wrapper.run("10.0.0.5", "furtif")

    command = fake_subprocess_exec.captured_commands[0]
    assert command[0] == "nmap"
    assert "-T2" in command
    assert "10.0.0.5" in command


async def test_command_includes_port_when_specified(fake_subprocess_exec, audit_trail, scope_guard):
    fake_subprocess_exec(FakeProcess(stdout=b"<xml/>", returncode=0))
    wrapper = NmapWrapper(scope_guard, audit=audit_trail)

    await wrapper.run("10.0.0.5", "standard", port=443)

    command = fake_subprocess_exec.captured_commands[0]
    assert "-p" in command
    assert "443" in command


async def test_successful_scan_returns_populated_result(fake_subprocess_exec, audit_trail, scope_guard):
    fake_subprocess_exec(FakeProcess(stdout=b"<nmaprun/>", returncode=0))
    wrapper = NmapWrapper(scope_guard, audit=audit_trail)

    result = await wrapper.run("10.0.0.5", "standard")

    assert result.succeeded
    assert result.raw_output == "<nmaprun/>"
    assert result.tool == "nmap"
    assert result.exit_code == 0


async def test_timeout_marks_result_as_failed(fake_subprocess_exec, audit_trail, scope_guard):
    fake_subprocess_exec(FakeProcess(hang=True))
    wrapper = NmapWrapper(scope_guard, audit=audit_trail, timeout_seconds=0.05)

    result = await wrapper.run("10.0.0.5", "standard")

    assert result.timed_out
    assert not result.succeeded


async def test_missing_binary_raises_tool_execution_error(monkeypatch, audit_trail, scope_guard):
    async def raise_not_found(*command, **kwargs):
        raise FileNotFoundError("nmap not found")

    monkeypatch.setattr(
        "recon_copilot.external_tool.asyncio.create_subprocess_exec", raise_not_found
    )
    wrapper = NmapWrapper(scope_guard, audit=audit_trail)

    with pytest.raises(ToolExecutionError):
        await wrapper.run("10.0.0.5", "standard")


async def test_audit_log_records_scan_start_and_complete(fake_subprocess_exec, db_conn, scope_guard):
    from recon_copilot.audit import AuditTrail

    fake_subprocess_exec(FakeProcess(stdout=b"<xml/>", returncode=0))
    audit = AuditTrail(db_conn, chosen_by="houda")
    wrapper = NmapWrapper(scope_guard, audit=audit)

    await wrapper.run("10.0.0.5", "standard")

    rows = db_conn.execute(
        "SELECT event_type, chosen_by FROM audit_log ORDER BY id"
    ).fetchall()
    event_types = [r["event_type"] for r in rows]
    assert "nmap_scan_start" in event_types
    assert "nmap_scan_complete" in event_types
    assert all(r["chosen_by"] == "houda" for r in rows)


async def test_scope_violation_is_logged_to_audit(db_conn, audit_trail):
    guard = make_scope_guard(allowed=("10.0.0.0/24",), on_violation=audit_trail.log_scope_violation)
    wrapper = NmapWrapper(guard, audit=audit_trail)

    with pytest.raises(ScopeViolation):
        await wrapper.run("8.8.8.8", "standard")

    row = db_conn.execute(
        "SELECT event_type, target, comment FROM audit_log WHERE event_type='scope_violation'"
    ).fetchone()
    assert row is not None
    assert row["target"] == "8.8.8.8"
