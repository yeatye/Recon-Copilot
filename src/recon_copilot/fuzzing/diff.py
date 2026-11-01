"""Comparaison de baseline pour la detection d'anomalies.

Une reponse est consideree anormale si elle differe de la baseline sur au
moins un des trois axes -- code HTTP, taille de reponse (au-dela d'une
tolerance relative), ou temps de reponse (au-dela d'une tolerance
relative). Les seuils sont volontairement generreux par defaut pour
limiter les faux positifs qu'un pentester manuel devrait ensuite trier
un par un.
"""

from __future__ import annotations

from recon_copilot.fuzzing.models import BaselineResponse, FuzzHit


def is_anomalous(
    status_code: int | None,
    body_size: int | None,
    response_time_ms: float | None,
    baseline: BaselineResponse,
    size_tolerance_ratio: float = 0.15,
    time_tolerance_ratio: float = 1.0,
    min_baseline_time_ms: float = 5.0,
) -> bool:
    if status_code is None:
        return True  # reponse manquante/erreur reseau = anormal par definition

    if status_code != baseline.status_code:
        return True

    if baseline.body_size > 0 and body_size is not None:
        size_delta_ratio = abs(body_size - baseline.body_size) / baseline.body_size
        if size_delta_ratio > size_tolerance_ratio:
            return True
    elif body_size not in (None, baseline.body_size):
        return True  # baseline vide mais reponse non vide (ou inversement)

    # `min_baseline_time_ms` evite le bruit sur une baseline quasi instantanee
    # (ex: service local tres rapide, ou mock de test) : sous ce plancher, un
    # ratio se met a exploser pour des ecarts de quelques millisecondes sans
    # aucune signification reelle -- on ignore alors le critere temporel.
    if response_time_ms is not None and baseline.response_time_ms >= min_baseline_time_ms:
        time_delta_ratio = abs(response_time_ms - baseline.response_time_ms) / baseline.response_time_ms
        if time_delta_ratio > time_tolerance_ratio:
            return True

    return False


def annotate_anomalies(
    hits: list[FuzzHit], baseline: BaselineResponse, **tolerance_kwargs
) -> list[FuzzHit]:
    """Retourne une NOUVELLE liste de FuzzHit avec `is_anomaly` recalcule contre `baseline`."""
    annotated = []
    for hit in hits:
        anomaly = is_anomalous(hit.status_code, hit.body_size, hit.response_time_ms, baseline, **tolerance_kwargs)
        annotated.append(
            FuzzHit(
                payload=hit.payload,
                status_code=hit.status_code,
                body_size=hit.body_size,
                response_time_ms=hit.response_time_ms,
                is_anomaly=anomaly,
            )
        )
    return annotated
