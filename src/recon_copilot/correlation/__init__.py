"""Facade du module correlation.

Point d'entree unique : `correlate_and_store()`. Prend les objets deja
normalises par le parser (`ParsedHost`, `NucleiDetection`), construit le
prompt (donnees sources + table de connaissances statique + contexte RAG
optionnel), appelle le LLM local UNE fois, verifie chaque citation
retournee contre les donnees reellement fournies, persiste les findings
en base et retourne le resultat.

Le RAG (`rag_index`) est ADDITIF et OPTIONNEL : a `None` (valeur par
defaut), tout se comporte exactement comme avant son introduction --
meme prompt, memes appels, memes tests. La table statique
(`knowledge_base.py`) reste le socle deterministe ; le RAG l'enrichit
quand il est branche, il ne la remplace jamais.
"""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone

from recon_copilot.correlation.knowledge_base import build_kb_context
from recon_copilot.correlation.models import CorrelationResult, Finding
from recon_copilot.correlation.prompt import SYSTEM_PROMPT, build_correlation_prompt
from recon_copilot.correlation.response_parser import parse_llm_response
from recon_copilot.llm_client import LlmClient, LlmError
from recon_copilot.parser.models import ParsedHost
from recon_copilot.parser.nuclei_parser import NucleiDetection
from recon_copilot.rag import RagIndex, format_rag_context

__all__ = ["Finding", "CorrelationResult", "correlate_and_store"]


def _collect_valid_sources(host: ParsedHost | None, nuclei_detections: list[NucleiDetection]) -> list[str]:
    sources: list[str] = []
    if host is not None:
        sources.append(host.source_fragment)
        for extra in host.extraports:
            sources.append(extra.source_fragment)
        for port in host.ports:
            sources.append(port.source_fragment)
            for script in port.scripts:
                sources.append(script.source_fragment)
    for det in nuclei_detections:
        sources.append(det.raw_line)
    return sources


def _persist_finding(conn: sqlite3.Connection, engagement: str, target: str, finding: Finding) -> int:
    cursor = conn.execute(
        """
        INSERT INTO correlated_findings
            (created_at, engagement, target, title, description, severity, cvss_score, confidence,
             source_type, source_citation, citation_verified, cve_refs, cwe_refs, mitre_refs,
             remediation, raw_llm_response, review_status)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending')
        """,
        (
            datetime.now(timezone.utc).isoformat(),
            engagement,
            target,
            finding.title,
            finding.description,
            finding.severity,
            finding.cvss_score,
            finding.confidence,
            finding.source_type,
            finding.source_citation,
            1 if finding.citation_verified else 0,
            json.dumps(list(finding.cve_refs)),
            json.dumps(list(finding.cwe_refs)),
            json.dumps(list(finding.mitre_refs)),
            finding.remediation,
            "",  # rempli separement (voir correlate_and_store) pour eviter de dupliquer le texte complet N fois
        ),
    )
    return cursor.lastrowid


async def correlate_and_store(
    conn: sqlite3.Connection,
    engagement: str,
    target: str,
    llm_client: LlmClient,
    host: ParsedHost | None,
    nuclei_detections: list[NucleiDetection],
    rag_index: RagIndex | None = None,
    rag_n_results: int = 3,
) -> CorrelationResult:
    """Correle les donnees d'UNE cible (un host Nmap + ses detections Nuclei associees).

    Fait UN SEUL appel LLM de generation. Si Ollama n'est pas joignable
    (`LlmError`), l'echec est journalise dans `parse_errors` et propage --
    l'appelant (le pipeline) decide s'il continue avec les autres cibles
    ou s'arrete.

    `rag_index` est optionnel (defaut `None` = comportement identique a
    avant son introduction). S'il est fourni, une recherche semantique est
    effectuee (appel d'embedding supplementaire) pour enrichir le prompt --
    si CETTE recherche echoue (Ollama down pour les embeddings, etc.), la
    correlation continue quand meme avec la seule table statique, degradee
    mais jamais bloquee : le RAG est un plus, pas une dependance dure.
    """
    template_ids = [d.template_id for d in nuclei_detections]
    service_names = [p.service_name for p in (host.ports if host else []) if p.service_name]
    kb_context = build_kb_context(template_ids, service_names)

    rag_context = None
    if rag_index is not None:
        query_terms = list(template_ids) + [d.name for d in nuclei_detections if d.name] + service_names
        query_text = " ".join(t for t in query_terms if t).strip()
        if query_text:
            try:
                rag_results = await rag_index.search(query_text, n_results=rag_n_results)
                rag_context = format_rag_context(rag_results) or None
            except LlmError as exc:
                conn.execute(
                    "INSERT INTO parse_errors (timestamp, raw_scan_result_id, tool, detail) VALUES (?, NULL, 'rag', ?)",
                    (datetime.now(timezone.utc).isoformat(), f"recherche RAG echouee, correlation poursuivie sans : {exc}"),
                )
                conn.commit()

    prompt = build_correlation_prompt(host, nuclei_detections, kb_context, rag_context)

    try:
        raw_response = await llm_client.generate(prompt, system=SYSTEM_PROMPT)
    except LlmError as exc:
        conn.execute(
            "INSERT INTO parse_errors (timestamp, raw_scan_result_id, tool, detail) VALUES (?, NULL, 'correlation', ?)",
            (datetime.now(timezone.utc).isoformat(), str(exc)),
        )
        conn.commit()
        raise

    valid_sources = _collect_valid_sources(host, nuclei_detections)
    findings, warnings = parse_llm_response(raw_response, valid_sources)

    finding_ids = []
    for finding in findings:
        finding_id = _persist_finding(conn, engagement, target, finding)
        conn.execute(
            "UPDATE correlated_findings SET raw_llm_response = ? WHERE id = ?",
            (raw_response, finding_id),
        )
        finding_ids.append(finding_id)
    conn.commit()

    for warning in warnings:
        conn.execute(
            "INSERT INTO parse_errors (timestamp, raw_scan_result_id, tool, detail) VALUES (?, NULL, 'correlation', ?)",
            (datetime.now(timezone.utc).isoformat(), warning),
        )
    conn.commit()

    return CorrelationResult(findings=tuple(findings), raw_llm_response=raw_response, warnings=tuple(warnings))
