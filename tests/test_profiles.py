from __future__ import annotations

import pytest

from recon_copilot.profiles import Aggressiveness, ProfileOverride, get_profile


def test_stealth_profile_disables_fuzzing_by_default():
    profile = get_profile(Aggressiveness.STEALTH)
    assert profile.fuzzing_enabled_by_default is False
    assert profile.nmap_timing == "-T2"


def test_standard_profile_enables_fuzzing_by_default():
    profile = get_profile("standard")
    assert profile.fuzzing_enabled_by_default is True
    assert profile.nmap_timing == "-T3"


def test_aggressive_profile_has_no_excluded_nuclei_tags():
    profile = get_profile(Aggressiveness.AGGRESSIVE)
    assert profile.nuclei_tags_exclude == ()


def test_invalid_profile_name_raises():
    with pytest.raises(ValueError):
        get_profile("ultra-mega-scan")


def test_override_appends_extra_nmap_args_without_dropping_base():
    override = ProfileOverride(
        base=Aggressiveness.STANDARD,
        nmap_extra_args=("--script=vuln",),
        reason="client a demande une passe NSE vuln ciblee",
    )
    resolved = override.resolve()
    assert "-sV" in resolved.nmap_extra_args  # herite du profil standard
    assert "--script=vuln" in resolved.nmap_extra_args
    assert resolved.nmap_timing == "-T3"  # timing du profil de base inchange


def test_override_can_restrict_nuclei_severity():
    override = ProfileOverride(
        base=Aggressiveness.AGGRESSIVE,
        nuclei_severity=("critical",),
        reason="focus critique uniquement pour ce hote sensible",
    )
    resolved = override.resolve()
    assert resolved.nuclei_severity == ("critical",)
