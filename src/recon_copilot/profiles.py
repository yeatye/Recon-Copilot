"""Profils d'agressivite partages entre le scanner et le module de fuzzing.

Centraliser ces definitions ici evite que le scanner et le fuzzer divergent
sur ce que "standard" ou "agressif" veut dire, et permet de les faire evoluer
(ou d'en ajouter un nouveau) a un seul endroit.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class Aggressiveness(str, Enum):
    """Niveaux d'agressivite selectionnables via le CLI ou la config d'engagement."""

    STEALTH = "furtif"
    STANDARD = "standard"
    AGGRESSIVE = "agressif"


@dataclass(frozen=True)
class ScanProfile:
    """Parametres Nmap/Nuclei associes a un niveau d'agressivite."""

    name: Aggressiveness
    nmap_timing: str  # -T0 a -T5
    nmap_extra_args: tuple[str, ...]
    nuclei_severity: tuple[str, ...]
    nuclei_tags_exclude: tuple[str, ...]
    fuzzing_enabled_by_default: bool
    # Delai minimal (secondes) entre deux requetes de fuzzing, pour rester a faible bruit
    fuzz_rate_limit_per_sec: int


PROFILES: dict[Aggressiveness, ScanProfile] = {
    Aggressiveness.STEALTH: ScanProfile(
        name=Aggressiveness.STEALTH,
        nmap_timing="-T2",
        nmap_extra_args=("-Pn", "--top-ports", "100"),
        nuclei_severity=("info", "low"),
        nuclei_tags_exclude=("dos", "fuzz", "intrusive"),
        fuzzing_enabled_by_default=False,
        fuzz_rate_limit_per_sec=1,
    ),
    Aggressiveness.STANDARD: ScanProfile(
        name=Aggressiveness.STANDARD,
        nmap_timing="-T3",
        nmap_extra_args=("-Pn", "-sV"),
        nuclei_severity=("info", "low", "medium", "high", "critical"),
        nuclei_tags_exclude=("dos", "intrusive"),
        fuzzing_enabled_by_default=True,
        fuzz_rate_limit_per_sec=10,
    ),
    Aggressiveness.AGGRESSIVE: ScanProfile(
        name=Aggressiveness.AGGRESSIVE,
        nmap_timing="-T4",
        nmap_extra_args=("-Pn", "-sV", "-sC"),
        nuclei_severity=("info", "low", "medium", "high", "critical"),
        nuclei_tags_exclude=(),
        fuzzing_enabled_by_default=True,
        fuzz_rate_limit_per_sec=40,
    ),
}


def get_profile(level: Aggressiveness | str) -> ScanProfile:
    """Recupere le ScanProfile pour un niveau donne (accepte l'enum ou sa valeur str)."""
    if isinstance(level, str):
        level = Aggressiveness(level)
    return PROFILES[level]


@dataclass(frozen=True)
class ProfileOverride:
    """Override ponctuel explicite (jamais implicite) d'un profil.

    Le scope allowlist n'est PAS overridable ici : cette classe ne touche
    qu'aux parametres d'intensite du scan/fuzzing, jamais aux cibles.
    """

    base: Aggressiveness
    nmap_extra_args: tuple[str, ...] = field(default_factory=tuple)
    nuclei_severity: tuple[str, ...] | None = None
    reason: str = ""  # justification obligatoire, tracee dans l'audit

    def resolve(self) -> ScanProfile:
        base_profile = get_profile(self.base)
        return ScanProfile(
            name=base_profile.name,
            nmap_timing=base_profile.nmap_timing,
            nmap_extra_args=base_profile.nmap_extra_args + self.nmap_extra_args,
            nuclei_severity=self.nuclei_severity or base_profile.nuclei_severity,
            nuclei_tags_exclude=base_profile.nuclei_tags_exclude,
            fuzzing_enabled_by_default=base_profile.fuzzing_enabled_by_default,
            fuzz_rate_limit_per_sec=base_profile.fuzz_rate_limit_per_sec,
        )
