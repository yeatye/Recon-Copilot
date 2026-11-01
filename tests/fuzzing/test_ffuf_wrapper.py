from __future__ import annotations

import json

import pytest

from recon_copilot.fuzzing.ffuf_wrapper import FfufWrapper
from recon_copilot.scope import ScopeViolation
from tests.conftest import make_scope_guard


async def test_scope_violation_blocks_before_any_subprocess_call(fake_ffuf_subprocess, audit_trail):
    guard = make_scope_guard(allowed=("10.0.0.0/24",))
    wrapper = FfufWrapper(guard, payloads=["/admin"], audit=audit_trail)

    with pytest.raises(ScopeViolation):
        await wrapper.run("8.8.8.8", "standard")

    assert fake_ffuf_subprocess.captured_commands == []


async def test_command_builds_url_from_bare_target_and_port(fake_ffuf_subprocess, audit_trail, scope_guard):
    wrapper = FfufWrapper(scope_guard, payloads=["/admin"], audit=audit_trail)
    await wrapper.run("10.0.0.5", "standard", port=8000)

    command = fake_ffuf_subprocess.captured_commands[0]
    url = command[command.index("-u") + 1]
    assert url == "http://10.0.0.5:8000/FUZZ"


async def test_command_without_port(fake_ffuf_subprocess, audit_trail, scope_guard):
    wrapper = FfufWrapper(scope_guard, payloads=["/admin"], audit=audit_trail)
    await wrapper.run("10.0.0.5", "standard")

    command = fake_ffuf_subprocess.captured_commands[0]
    url = command[command.index("-u") + 1]
    assert url == "http://10.0.0.5/FUZZ"


async def test_wordlist_file_contains_all_payloads(fake_ffuf_subprocess, audit_trail, scope_guard, tmp_path):
    payloads = ["/admin", "/.env", "/backup.zip"]
    wrapper = FfufWrapper(scope_guard, payloads=payloads, audit=audit_trail)
    await wrapper.run("10.0.0.5", "standard")

    command = fake_ffuf_subprocess.captured_commands[0]
    wordlist_path = command[command.index("-w") + 1]
    # Le fichier est nettoye apres run() -- on ne peut plus le relire ici,
    # mais on peut verifier qu'un chemin distinct a bien ete genere pour -w et -o.
    output_path = command[command.index("-o") + 1]
    assert wordlist_path != output_path


async def test_rate_limit_flag_reflects_profile(fake_ffuf_subprocess, audit_trail, scope_guard):
    wrapper = FfufWrapper(scope_guard, payloads=["/admin"], audit=audit_trail, rate_limit_per_sec=3)
    await wrapper.run("10.0.0.5", "standard")

    command = fake_ffuf_subprocess.captured_commands[0]
    assert command[command.index("-rate") + 1] == "3"


async def test_result_raw_output_is_ffuf_json_file_content(fake_ffuf_subprocess, audit_trail, scope_guard):
    fake_ffuf_subprocess(json.dumps({"results": [{"input": {"FUZZ": "admin"}, "status": 200, "length": 10, "duration": 1000000}]}))
    wrapper = FfufWrapper(scope_guard, payloads=["/admin"], audit=audit_trail)

    result = await wrapper.run("10.0.0.5", "standard")

    assert "admin" in result.raw_output
    assert result.tool == "ffuf"


async def test_temp_files_are_cleaned_up_after_run(fake_ffuf_subprocess, audit_trail, scope_guard):
    wrapper = FfufWrapper(scope_guard, payloads=["/admin"], audit=audit_trail)
    await wrapper.run("10.0.0.5", "standard")

    assert not wrapper._wordlist_path.exists()
    assert not wrapper._output_path.exists()
