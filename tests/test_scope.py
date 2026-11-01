from __future__ import annotations

import pytest

from recon_copilot.scope import ScopeConfig, ScopeGuard, ScopeViolation
from tests.conftest import make_scope_guard


def test_ip_in_allowed_cidr_is_allowed():
    guard = make_scope_guard(allowed=("10.0.0.0/24",))
    allowed, reason = guard.is_allowed("10.0.0.42")
    assert allowed
    assert reason == ""


def test_ip_outside_cidr_is_blocked():
    guard = make_scope_guard(allowed=("10.0.0.0/24",))
    allowed, reason = guard.is_allowed("10.0.1.5")
    assert not allowed
    assert "allowed_targets" in reason


def test_hostname_exact_match_is_allowed():
    guard = make_scope_guard(allowed=("target.example.local",))
    allowed, _ = guard.is_allowed("target.example.local")
    assert allowed


def test_hostname_subdomain_is_allowed():
    guard = make_scope_guard(allowed=("client.local",))
    allowed, _ = guard.is_allowed("api.client.local")
    assert allowed


def test_unrelated_hostname_is_blocked():
    guard = make_scope_guard(allowed=("client.local",))
    allowed, _ = guard.is_allowed("evil.com")
    assert not allowed


def test_excluded_target_wins_over_allowed_range():
    guard = make_scope_guard(allowed=("10.0.0.0/24",), excluded=("10.0.0.254",))
    allowed, reason = guard.is_allowed("10.0.0.254")
    assert not allowed
    assert "exclue" in reason


def test_port_restriction_enforced_when_configured():
    guard = make_scope_guard(allowed=("10.0.0.0/24",), ports=(443, 8443))
    allowed_https, _ = guard.is_allowed("10.0.0.5", port=443)
    allowed_ssh, reason = guard.is_allowed("10.0.0.5", port=22)
    assert allowed_https
    assert not allowed_ssh
    assert "22" in reason


def test_port_unrestricted_when_allowed_ports_empty():
    guard = make_scope_guard(allowed=("10.0.0.0/24",), ports=())
    allowed, _ = guard.is_allowed("10.0.0.5", port=9999)
    assert allowed


def test_enforce_raises_scope_violation_out_of_scope():
    guard = make_scope_guard(allowed=("10.0.0.0/24",))
    with pytest.raises(ScopeViolation):
        guard.enforce("8.8.8.8")


def test_enforce_notifies_on_violation_callback():
    captured = []
    guard = make_scope_guard(
        allowed=("10.0.0.0/24",),
        on_violation=lambda target, reason: captured.append((target, reason)),
    )
    with pytest.raises(ScopeViolation):
        guard.enforce("8.8.8.8")
    assert captured == [("8.8.8.8", "cible absente de allowed_targets")]


def test_enforce_passes_silently_in_scope():
    guard = make_scope_guard(allowed=("10.0.0.0/24",))
    guard.enforce("10.0.0.1")  # ne doit pas lever


def test_scope_config_from_yaml(tmp_path):
    yaml_content = """
scope:
  allowed_targets:
    - "192.168.1.0/24"
  allowed_ports: [80, 443]
  excluded_targets:
    - "192.168.1.1"
"""
    config_path = tmp_path / "engagement.yaml"
    config_path.write_text(yaml_content)

    config = ScopeConfig.from_yaml(config_path)
    guard = ScopeGuard(config)

    assert guard.is_allowed("192.168.1.50", port=443) == (True, "")
    assert guard.is_allowed("192.168.1.1")[0] is False
    assert guard.is_allowed("192.168.1.50", port=22)[0] is False
