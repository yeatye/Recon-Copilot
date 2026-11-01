"""Module scoring : score de risque composite pour un finding correle.

composite = w_severite * severite_normalisee + w_exposition * exposition + w_criticite * criticite_actif

Les poids par defaut (0.6 / 0.2 / 0.2) donnent la priorite a la severite
technique (CVSS) tout en laissant l'exposition reseau et la criticite
metier de l'actif faire pencher la balance -- un finding "high" sur un
actif interne peu critique peut finir sous un finding "medium" sur un
actif expose et critique. C'est volontairement simple (pas de ML, pas de
ponderation dynamique) pour rester explicable a l'analyste et au client.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum

_SEVERITY_TO_CVSS = {
    "info": 0.0,
    "low": 3.0,
    "medium": 5.5,
    "high": 8.0,
    "critical": 9.5,
}


class RiskLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AssetCriticality(str, Enum):
    LOW = "low"        # ex: environnement de test, actif non expose
    MEDIUM = "medium"  # ex: application interne standard
    HIGH = "high"      # ex: actif en production, donnees sensibles, expose a internet


_CRITICALITY_SCORE = {
    AssetCriticality.LOW: 2.0,
    AssetCriticality.MEDIUM: 5.5,
    AssetCriticality.HIGH: 9.0,
}

# Ports habituellement exposes publiquement (web/mail) -> exposition plus haute
# que des ports d'administration qui ne devraient etre atteignables qu'en interne.
_HIGH_EXPOSURE_PORTS = {80, 443, 8080, 8443, 25, 587, 21}
_LOW_EXPOSURE_PORTS = {22, 3389, 3306, 5432, 6379, 27017}


@dataclass(frozen=True)
class RiskScore:
    composite_score: float  # 0-10
    risk_level: RiskLevel
    severity_component: float
    exposure_component: float
    criticality_component: float


def _severity_score(severity: str, cvss_score: float | None) -> float:
    """Prefere le CVSS fourni par le LLM s'il est present et plausible (0-10), sinon retombe sur un bareme fixe par severite."""
    if cvss_score is not None and 0.0 <= cvss_score <= 10.0:
        return cvss_score
    return _SEVERITY_TO_CVSS.get(severity, 0.0)


def _exposure_score(port_number: int | None) -> float:
    if port_number is None:
        return 5.0  # inconnu -> valeur neutre, ni optimiste ni pessimiste
    if port_number in _HIGH_EXPOSURE_PORTS:
        return 8.0
    if port_number in _LOW_EXPOSURE_PORTS:
        return 4.0
    return 6.0  # port non classifie explicitement -> exposition moderee par defaut


def _bucket(composite: float) -> RiskLevel:
    if composite >= 8.5:
        return RiskLevel.CRITICAL
    if composite >= 6.5:
        return RiskLevel.HIGH
    if composite >= 3.5:
        return RiskLevel.MEDIUM
    return RiskLevel.LOW


def compute_risk_score(
    severity: str,
    cvss_score: float | None,
    asset_criticality: AssetCriticality,
    port_number: int | None = None,
    weight_severity: float = 0.6,
    weight_exposure: float = 0.2,
    weight_criticality: float = 0.2,
) -> RiskScore:
    if abs((weight_severity + weight_exposure + weight_criticality) - 1.0) > 1e-6:
        raise ValueError("les poids severite+exposition+criticite doivent sommer a 1.0")

    severity_component = _severity_score(severity, cvss_score)
    exposure_component = _exposure_score(port_number)
    criticality_component = _CRITICALITY_SCORE[asset_criticality]

    composite = (
        weight_severity * severity_component
        + weight_exposure * exposure_component
        + weight_criticality * criticality_component
    )
    # Les composantes sont sur des echelles 0-10 (severite/exposition) et
    # jusqu'a 9.0 (criticite) -- composite reste donc dans [0, 10].
    composite = round(min(composite, 10.0), 2)

    return RiskScore(
        composite_score=composite,
        risk_level=_bucket(composite),
        severity_component=severity_component,
        exposure_component=exposure_component,
        criticality_component=criticality_component,
    )


def score_and_store(
    conn: sqlite3.Connection,
    finding_id: int,
    asset_criticality: AssetCriticality,
    port_number: int | None = None,
) -> RiskScore:
    """Calcule le score pour `finding_id` et met a jour sa ligne dans correlated_findings."""
    row = conn.execute(
        "SELECT severity, cvss_score FROM correlated_findings WHERE id = ?", (finding_id,)
    ).fetchone()
    if row is None:
        raise ValueError(f"aucun finding avec id={finding_id}")

    score = compute_risk_score(row["severity"], row["cvss_score"], asset_criticality, port_number)

    conn.execute(
        "UPDATE correlated_findings SET risk_score = ?, risk_level = ?, asset_criticality = ? WHERE id = ?",
        (score.composite_score, score.risk_level.value, asset_criticality.value, finding_id),
    )
    conn.commit()
    return score
