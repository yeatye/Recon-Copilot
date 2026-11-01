"""Application du scope d'engagement.

Ce module est le SEUL endroit qui decide si une cible peut etre scannee ou
fuzzee. Le scanner et le futur module de fuzzing importent tous les deux
`ScopeGuard` plutot que de reimplementer une verification locale — ca evite
qu'un des deux modules "oublie" une exclusion ou diverge sur la semantique
d'un CIDR.

Le blocage est la seule issue possible pour une cible hors scope : il n'y a
pas de mode "warning seulement". Le callback `on_violation` permet au
scanner/fuzzer d'enregistrer la tentative dans la piste d'audit (voir
audit.py) sans que ce module ait besoin de connaitre SQLite.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

import yaml


class ScopeViolation(Exception):
    """Levee quand une cible n'est pas dans l'allowlist ou est explicitement exclue."""

    def __init__(self, target: str, reason: str) -> None:
        self.target = target
        self.reason = reason
        super().__init__(f"Cible hors scope bloquee: {target} ({reason})")


OnViolation = Callable[[str, str], None]  # (target, reason) -> None


def _default_on_violation(target: str, reason: str) -> None:
    # Pas de no-op silencieux par defaut : une violation de scope doit au
    # moins finir dans les logs applicatifs meme si personne n'a branche
    # l'audit trail. Le scanner remplace ce callback par audit.log_scope_violation.
    import logging

    logging.getLogger("recon_copilot.scope").warning(
        "SCOPE VIOLATION bloquee: cible=%s raison=%s", target, reason
    )


@dataclass
class ScopeConfig:
    allowed_targets: tuple[str, ...] = field(default_factory=tuple)
    allowed_ports: tuple[int, ...] = field(default_factory=tuple)
    excluded_targets: tuple[str, ...] = field(default_factory=tuple)

    @classmethod
    def from_yaml(cls, path: str | Path) -> "ScopeConfig":
        with open(path, encoding="utf-8") as fh:
            raw = yaml.safe_load(fh)
        scope = raw.get("scope", {})
        return cls(
            allowed_targets=tuple(scope.get("allowed_targets", []) or []),
            allowed_ports=tuple(scope.get("allowed_ports", []) or []),
            excluded_targets=tuple(scope.get("excluded_targets", []) or []),
        )


def _target_matches(target: str, pattern: str) -> bool:
    """True si `target` (IP ou hostname) est couvert par `pattern`.

    `pattern` peut etre une IP exacte, un CIDR, ou un hostname (match exact
    ou suffixe de domaine, ex: pattern "client.local" couvre "api.client.local").
    """
    try:
        target_ip = ipaddress.ip_address(target)
    except ValueError:
        target_ip = None

    try:
        network = ipaddress.ip_network(pattern, strict=False)
        if target_ip is not None:
            return target_ip in network
        return False
    except ValueError:
        pass  # pattern n'est pas un CIDR/IP -> traiter comme hostname

    if target_ip is not None:
        return False  # target est une IP mais pattern est un hostname : pas de match

    target_l, pattern_l = target.lower(), pattern.lower()
    return target_l == pattern_l or target_l.endswith("." + pattern_l)


class ScopeGuard:
    """Verifie chaque cible/port avant tout scan ou fuzzing.

    Usage :
        guard = ScopeGuard(ScopeConfig.from_yaml("engagement.yaml"), on_violation=audit.log_scope_violation)
        guard.enforce("10.0.0.5")           # leve ScopeViolation si hors scope
        guard.enforce("10.0.0.5", port=443) # verifie aussi le port si allowed_ports est renseigne
    """

    def __init__(self, config: ScopeConfig, on_violation: OnViolation | None = None) -> None:
        self._config = config
        self._on_violation = on_violation or _default_on_violation

    def is_allowed(self, target: str, port: int | None = None) -> tuple[bool, str]:
        for excluded in self._config.excluded_targets:
            if _target_matches(target, excluded):
                return False, f"cible explicitement exclue ({excluded})"

        if not any(_target_matches(target, allowed) for allowed in self._config.allowed_targets):
            return False, "cible absente de allowed_targets"

        if port is not None and self._config.allowed_ports and port not in self._config.allowed_ports:
            return False, f"port {port} absent de allowed_ports"

        return True, ""

    def enforce(self, target: str, port: int | None = None) -> None:
        """Leve ScopeViolation (et notifie on_violation) si la cible n'est pas autorisee."""
        allowed, reason = self.is_allowed(target, port)
        if not allowed:
            self._on_violation(target, reason)
            raise ScopeViolation(target, reason)
