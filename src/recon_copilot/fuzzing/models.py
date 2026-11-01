"""Modeles de donnees du module fuzzing."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class FuzzPayload:
    payload: str
    description: str


@dataclass(frozen=True)
class BaselineResponse:
    status_code: int
    body_size: int
    response_time_ms: float


@dataclass(frozen=True)
class FuzzHit:
    payload: str
    status_code: int | None
    body_size: int | None
    response_time_ms: float | None
    is_anomaly: bool


@dataclass(frozen=True)
class AnomalyTriage:
    payload: str
    explanation: str
    severity_guess: str  # info|low|medium|high|critical


@dataclass(frozen=True)
class FuzzRunResult:
    hits: tuple[FuzzHit, ...]
    anomalies: tuple[FuzzHit, ...]
    triage: tuple[AnomalyTriage, ...]
    warnings: tuple[str, ...]
