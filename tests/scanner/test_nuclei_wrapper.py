from __future__ import annotations

import pytest

from recon_copilot.scanner.nuclei_wrapper import NucleiWrapper
from recon_copilot.scope import ScopeViolation
from tests.conftest import make_scope_guard
from tests.scanner.conftest import FakeProcess


async def test_scope_violation_blocks_before_any_subprocess_call(fake_subprocess_exec, audit_trail):
    fake_subprocess_exec(FakeProcess(returncode=0))
    guard = make_scope_guard(allowed=("10.0.0.0/24",))
    wrapper = NucleiWrapper(guard, audit=audit_trail)

    with pytest.raises(ScopeViolation):
        await wrapper.run("8.8.8.8", "standard")

    assert fake_subprocess_exec.captured_commands == []


async def test_command_includes_target_and_severity(fake_subprocess_exec, audit_trail, scope_guard):
    fake_subprocess_exec(FakeProcess(stdout=b'{"info": "line1"}\n', returncode=0))
    wrapper = NucleiWrapper(scope_guard, audit=audit_trail)

    await wrapper.run("10.0.0.5", "standard")

    command = fake_subprocess_exec.captured_commands[0]
    assert command[0] == "nuclei"
    assert "-target" in command
    assert "10.0.0.5" in command
    assert "-severity" in command


async def test_stealth_profile_excludes_intrusive_and_fuzz_tags(fake_subprocess_exec, audit_trail, scope_guard):
    fake_subprocess_exec(FakeProcess(stdout=b"", returncode=0))
    wrapper = NucleiWrapper(scope_guard, audit=audit_trail)

    await wrapper.run("10.0.0.5", "furtif")

    command = fake_subprocess_exec.captured_commands[0]
    assert "-etags" in command
    etags_value = command[command.index("-etags") + 1]
    assert "intrusive" in etags_value
    assert "fuzz" in etags_value


async def test_aggressive_profile_has_no_etags_flag(fake_subprocess_exec, audit_trail, scope_guard):
    fake_subprocess_exec(FakeProcess(stdout=b"", returncode=0))
    wrapper = NucleiWrapper(scope_guard, audit=audit_trail)

    await wrapper.run("10.0.0.5", "agressif")

    command = fake_subprocess_exec.captured_commands[0]
    assert "-etags" not in command


async def test_target_with_port_builds_host_colon_port(fake_subprocess_exec, audit_trail, scope_guard):
    fake_subprocess_exec(FakeProcess(stdout=b"", returncode=0))
    wrapper = NucleiWrapper(scope_guard, audit=audit_trail)

    await wrapper.run("10.0.0.5", "standard", port=8443)

    command = fake_subprocess_exec.captured_commands[0]
    target_arg = command[command.index("-target") + 1]
    assert target_arg == "10.0.0.5:8443"


async def test_successful_run_returns_jsonl_output(fake_subprocess_exec, audit_trail, scope_guard):
    fake_subprocess_exec(FakeProcess(stdout=b'{"template-id": "exposed-panel"}\n', returncode=0))
    wrapper = NucleiWrapper(scope_guard, audit=audit_trail)

    result = await wrapper.run("10.0.0.5", "standard")

    assert result.succeeded
    assert "exposed-panel" in result.raw_output
    assert result.tool == "nuclei"
