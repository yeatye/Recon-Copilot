"""Facade du module fuzzing.

Point d'entree unique : `run_fuzz()`. Enchaine : verification que le
profil d'agressivite autorise le fuzzing -> generation des payloads
(1 appel LLM) -> baseline -> execution ffuf -> diff baseline -> triage
des seules anomalies (1 appel LLM, ou 0 si aucune anomalie) -> persistance.
"""

from __future__ import annotations

import sqlite3
from datetime import datetime, timezone

import httpx

from recon_copilot.audit import AuditTrail
from recon_copilot.fuzzing.baseline import fetch_baseline
from recon_copilot.fuzzing.diff import annotate_anomalies
from recon_copilot.fuzzing.ffuf_parser import parse_ffuf_json
from recon_copilot.fuzzing.ffuf_wrapper import FfufWrapper
from recon_copilot.fuzzing.models import FuzzRunResult
from recon_copilot.fuzzing.payload_generator import generate_payloads
from recon_copilot.fuzzing.triage import triage_anomalies
from recon_copilot.llm_client import LlmClient
from recon_copilot.profiles import get_profile
from recon_copilot.scope import ScopeGuard

__all__ = ["FuzzRunResult", "FuzzingDisabledError", "run_fuzz"]


class FuzzingDisabledError(Exception):
    """Leve quand le profil d'agressivite courant desactive le fuzzing (ex: 'furtif')."""


def _persist(conn: sqlite3.Connection, engagement: str, url: str, result: FuzzRunResult) -> None:
    triage_by_payload = {t.payload: t for t in result.triage}
    for hit in result.hits:
        triage = triage_by_payload.get(hit.payload)
        conn.execute(
            """
            INSERT INTO fuzz_results
                (created_at, engagement, target_url, payload, status_code, body_size, response_time_ms,
                 is_anomaly, triage_explanation, triage_severity_guess)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                datetime.now(timezone.utc).isoformat(),
                engagement,
                url,
                hit.payload,
                hit.status_code,
                hit.body_size,
                hit.response_time_ms,
                1 if hit.is_anomaly else 0,
                triage.explanation if triage else None,
                triage.severity_guess if triage else None,
            ),
        )
    conn.commit()


async def run_fuzz(
    conn: sqlite3.Connection,
    engagement: str,
    target: str,
    port: int | None,
    aggressiveness: str,
    tech_hint: str,
    llm_client: LlmClient,
    scope_guard: ScopeGuard,
    chosen_by: str,
    comment: str = "",
    url_scheme: str = "http",
    path_template: str = "/FUZZ",
    force_enable: bool = False,
    http_client: httpx.AsyncClient | None = None,
) -> FuzzRunResult:
    """Lance le fuzzing assiste par IA sur `target:port`.

    Leve `FuzzingDisabledError` si le profil d'agressivite courant
    desactive le fuzzing par defaut et que `force_enable` n'est pas
    explicitement passe -- jamais de fuzzing "silencieux" en profil furtif.

    `http_client` est injectable pour les tests (httpx.AsyncClient avec un
    MockTransport) -- en usage reel, un client par defaut est cree et
    ferme automatiquement.
    """
    profile = get_profile(aggressiveness)
    if not profile.fuzzing_enabled_by_default and not force_enable:
        raise FuzzingDisabledError(
            f"le profil '{aggressiveness}' desactive le fuzzing par defaut -- "
            f"passe force_enable=True avec une justification explicite pour l'activer quand meme"
        )

    # Verification de scope AVANT toute activite reseau -- y compris la
    # baseline, qui est une vraie requete HTTP. La verifier seulement plus
    # tard (dans FfufWrapper.run()) laisserait partir une requete vers une
    # cible hors scope avant meme le premier payload de fuzzing.
    scope_guard.enforce(target, port)

    audit = AuditTrail(conn, chosen_by=chosen_by)
    audit.log_scan_start(tool="fuzzing", target=target, aggressiveness=aggressiveness, command="run_fuzz", comment=comment)

    warnings: list[str] = []

    payloads, gen_warnings = await generate_payloads(tech_hint, llm_client)
    warnings.extend(gen_warnings)

    ffuf = FfufWrapper(
        scope_guard,
        payloads=[p.payload for p in payloads],
        audit=audit,
        rate_limit_per_sec=profile.fuzz_rate_limit_per_sec,
        url_scheme=url_scheme,
        path_template=path_template,
    )

    base_url = f"{url_scheme}://{target if port is None else f'{target}:{port}'}/"
    if http_client is not None:
        baseline = await fetch_baseline(base_url, http_client=http_client)
    else:
        async with httpx.AsyncClient() as owned_client:
            baseline = await fetch_baseline(base_url, http_client=owned_client)

    raw_result = await ffuf.run(target, aggressiveness, port)
    hits, parse_warnings = parse_ffuf_json(raw_result.raw_output)
    warnings.extend(parse_warnings)

    hits = annotate_anomalies(hits, baseline)
    anomalies = [h for h in hits if h.is_anomaly]

    triage, triage_warnings = await triage_anomalies(anomalies, baseline.status_code, baseline.body_size, llm_client)
    warnings.extend(triage_warnings)

    result = FuzzRunResult(
        hits=tuple(hits),
        anomalies=tuple(anomalies),
        triage=tuple(triage),
        warnings=tuple(warnings),
    )

    url = f"{url_scheme}://{target if port is None else f'{target}:{port}'}{path_template}"
    _persist(conn, engagement, url, result)

    for w in warnings:
        conn.execute(
            "INSERT INTO parse_errors (timestamp, raw_scan_result_id, tool, detail) VALUES (?, NULL, 'fuzzing', ?)",
            (datetime.now(timezone.utc).isoformat(), w),
        )
    conn.commit()

    return result
