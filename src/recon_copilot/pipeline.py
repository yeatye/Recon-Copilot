"""Orchestrateur du pipeline complet : scan -> parsing -> correlation ->
scoring -> (fuzzing optionnel). La revue humaine et la generation de
rapport restent des etapes SEPAREES et deliberement non automatisees ici
(voir review/cli.py et report/__init__.py) -- le pipeline ne genere
jamais de rapport sans passage explicite par la revue.
"""

from __future__ import annotations

import os
import sqlite3
import uuid
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from recon_copilot.audit import AuditTrail
from recon_copilot.correlation import correlate_and_store
from recon_copilot.db import get_connection
from recon_copilot.fuzzing import FuzzingDisabledError, run_fuzz
from recon_copilot.llm_client import LlmClient, OllamaClient, OpenAIClient
from recon_copilot.parser import parse_and_store
from recon_copilot.parser.models import NmapParseResult, NucleiParseResult
from recon_copilot.rag import RagIndex, ingest_nuclei_templates_dir, parse_cisa_kev_json
from recon_copilot.rag.embeddings import LocalEmbeddingClient
from recon_copilot.rag.models import KbDocument
from recon_copilot.scanner import ScanRequest, run_scan
from recon_copilot.scoring import AssetCriticality, score_and_store
from recon_copilot.scope import ScopeConfig, ScopeGuard

__all__ = ["EngagementConfig", "PipelineSummary", "load_engagement_config", "run_pipeline"]


@dataclass(frozen=True)
class RagConfig:
    """Options du module RAG (optionnel, additif).

    `enabled=False` (defaut) : correlation sans contexte RAG, comportement
    historique. Quand active, le pipeline construit/reutilise un index
    ChromaDB persistant dans `persist_directory` (embeddings locaux via
    `LocalEmbeddingClient` -- aucune cle API supplementaire, utile quand la
    cle LLM n'expose pas de endpoint /embeddings).
    """

    enabled: bool = False
    persist_directory: str = "./data/rag_index"
    cisa_kev_path: str = "./data/known_exploited_vulnerabilities.json"
    nuclei_templates_dir: str = "~/.local/nuclei-templates"


@dataclass(frozen=True)
class EngagementConfig:
    name: str
    analyst: str
    scope: ScopeConfig
    default_profile: str
    db_path: str
    llm_provider: str
    llm_api_key: str
    llm_base_url: str
    llm_model: str
    llm_timeout_seconds: float
    rag: RagConfig


def load_engagement_config(path: str | Path) -> EngagementConfig:
    with open(path, encoding="utf-8") as fh:
        raw = yaml.safe_load(fh)

    engagement = raw.get("engagement", {})
    scope_raw = raw.get("scope", {})
    aggressiveness_raw = raw.get("aggressiveness", {})
    audit_raw = raw.get("audit", {})
    llm_raw = raw.get("llm", raw.get("ollama", {}))
    rag_raw = raw.get("rag", {})

    provider = llm_raw.get("provider", "opencode")

    defaults = {
        "opencode": (
            "OPENCODE_API_KEY",
            "https://opencode.ai/zen/v1",
            "deepseek-v4-flash-free",
        ),
        "openai": (
            "OPENAI_API_KEY",
            "https://api.openai.com/v1",
            "gpt-4",
        ),
        "ollama": (
            None,
            "http://localhost:11434",
            "llama3.1:8b",
        ),
    }
    env_var, default_base_url, default_model = defaults.get(provider, defaults["opencode"])

    api_key = llm_raw.get("api_key", "sk-REMPLACEZ_PAR_VOTRE_CLE")
    if env_var and os.environ.get(env_var):
        api_key = os.environ.get(env_var)

    return EngagementConfig(
        name=engagement.get("name", "engagement-sans-nom"),
        analyst=engagement.get("analyst", "analyste-inconnu"),
        scope=ScopeConfig(
            allowed_targets=tuple(scope_raw.get("allowed_targets", []) or []),
            allowed_ports=tuple(scope_raw.get("allowed_ports", []) or []),
            excluded_targets=tuple(scope_raw.get("excluded_targets", []) or []),
        ),
        default_profile=aggressiveness_raw.get("default_profile", "standard"),
        db_path=audit_raw.get("db_path", "./data/recon_copilot.db"),
        llm_provider=provider,
        llm_api_key=api_key,
        llm_base_url=llm_raw.get("base_url", llm_raw.get("host", default_base_url)),
        llm_model=llm_raw.get("model", default_model),
        llm_timeout_seconds=float(llm_raw.get("timeout_seconds", 300.0)),
        rag=RagConfig(
            enabled=bool(rag_raw.get("enabled", False)),
            persist_directory=rag_raw.get("persist_directory", "./data/rag_index"),
            cisa_kev_path=rag_raw.get(
                "cisa_kev_path", "./data/known_exploited_vulnerabilities.json"
            ),
            nuclei_templates_dir=rag_raw.get("nuclei_templates_dir", "~/.local/nuclei-templates"),
        ),
    )


def _build_llm_client(config: EngagementConfig) -> LlmClient:
    """Instancie le client LLM selon `config.llm_provider`."""
    if config.llm_provider == "ollama":
        return OllamaClient(
            host=config.llm_base_url,
            model=config.llm_model,
            timeout_seconds=config.llm_timeout_seconds,
        )

    extra_headers = {}
    if config.llm_provider == "opencode":
        extra_headers["x-opencode-session"] = uuid.uuid4().hex

    return OpenAIClient(
        api_key=config.llm_api_key,
        model=config.llm_model,
        base_url=config.llm_base_url,
        timeout_seconds=config.llm_timeout_seconds,
        extra_headers=extra_headers,
    )


async def _build_rag_index(config: EngagementConfig) -> tuple[RagIndex | None, list[str]]:
    """Construit (ou reutilise) l'index RAG persistant si `config.rag.enabled`.

    Retourne `(None, [])` quand la RAG est desactivee. L'index ChromaDB est
    persistant : si des documents y sont deja presents, on le reutilise tel
    quel (l'ingestion complete des templates Nuclei prend quelques minutes
    sur CPU, on ne la refait pas a chaque scan). Les sources manquantes
    (CISA KEV non telecharge, dossier Nuclei introuvable) sont signalees
    en warning mais n'empechent pas l'indexation des autres sources.
    """
    if not config.rag.enabled:
        return None, []

    warnings: list[str] = []
    index = RagIndex(LocalEmbeddingClient(), config.rag.persist_directory)
    if index.count() > 0:
        return index, warnings  # deja ingere -- reutilise tel quel

    documents: list[KbDocument] = []

    kev_path = Path(config.rag.cisa_kev_path).expanduser()
    if kev_path.is_file():
        kev_docs, kev_errors = parse_cisa_kev_json(kev_path.read_text(encoding="utf-8", errors="replace"))
        documents.extend(kev_docs)
        warnings.extend(f"RAG CISA KEV: {error}" for error in kev_errors)
    else:
        warnings.append(
            f"RAG: catalogue CISA KEV absent ({kev_path}) -- indexation sans KEV. "
            "Telecharge-le : curl -o data/known_exploited_vulnerabilities.json "
            "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
        )

    nuclei_dir = Path(config.rag.nuclei_templates_dir).expanduser()
    nuclei_docs, nuclei_errors = ingest_nuclei_templates_dir(nuclei_dir)
    documents.extend(nuclei_docs)
    warnings.extend(f"RAG Nuclei: {error}" for error in nuclei_errors[:20])

    if documents:
        indexed = await index.index_documents(documents)
        warnings.append(
            f"RAG: {indexed} documents indexes (source: ~/.cache/chroma + {config.rag.persist_directory})"
        )
    else:
        warnings.append("RAG: aucun document ingere -- correlation sans contexte RAG")
    return index, warnings


@dataclass(frozen=True)
class PipelineSummary:
    engagement: str
    target: str
    aggressiveness: str
    hosts_parsed: int
    nuclei_detections_parsed: int
    findings_proposed: int
    findings_unverified_citations: int
    fuzz_hits: int
    fuzz_anomalies: int
    warnings: list[str] = field(default_factory=list)


async def run_pipeline(
    config_path: str | Path,
    target: str,
    chosen_by: str,
    aggressiveness: str | None = None,
    comment: str = "",
    port: int | None = None,
    asset_criticality: AssetCriticality = AssetCriticality.MEDIUM,
    llm_client: LlmClient | None = None,
    enable_fuzzing: bool = False,
    tech_hint: str | None = None,
    conn: sqlite3.Connection | None = None,
) -> PipelineSummary:
    """Lance scan -> parsing -> correlation -> scoring (-> fuzzing optionnel) sur UNE cible.

    Ne genere PAS de rapport et ne prend AUCUNE decision de revue -- voir
    `recon_copilot.review.cli` puis `recon_copilot.report.generate_report`
    pour la suite du pipeline, volontairement separee de cette fonction.
    """
    config = load_engagement_config(config_path)
    aggressiveness = aggressiveness or config.default_profile
    scope_guard = ScopeGuard(config.scope)
    owns_conn = conn is None
    conn = conn or get_connection(config.db_path)
    llm_client = llm_client or _build_llm_client(config)

    warnings: list[str] = []

    rag_index, rag_warnings = await _build_rag_index(config)
    warnings.extend(rag_warnings)

    request = ScanRequest(
        target=target,
        aggressiveness=aggressiveness,
        engagement=config.name,
        chosen_by=chosen_by,
        comment=comment,
        port=port,
    )
    raw_results = await run_scan(request, scope_guard, conn)

    host = None
    nuclei_detections = []
    hosts_parsed = 0
    detections_parsed = 0

    for raw_result in raw_results:
        parsed = parse_and_store(conn, config.name, raw_result)
        if parsed is None:
            warnings.append(f"{raw_result.tool}: sortie non exploitable, voir parse_errors")
            continue
        if isinstance(parsed, NmapParseResult):
            hosts_parsed += len(parsed.hosts)
            if parsed.hosts:
                host = parsed.hosts[0]  # un seul host cible par run_pipeline (une cible = un scan)
        elif isinstance(parsed, NucleiParseResult):
            detections_parsed += len(parsed.detections)
            nuclei_detections = list(parsed.detections)

    correlation_result = await correlate_and_store(
        conn, config.name, target, llm_client, host, nuclei_detections, rag_index=rag_index
    )
    warnings.extend(correlation_result.warnings)

    pending_rows = conn.execute(
        "SELECT id FROM correlated_findings WHERE engagement = ? AND target = ? AND review_status = 'pending'",
        (config.name, target),
    ).fetchall()
    for row in pending_rows:
        score_and_store(conn, row["id"], asset_criticality, port_number=port)

    unverified_count = sum(1 for f in correlation_result.findings if not f.citation_verified)

    fuzz_hits = 0
    fuzz_anomalies = 0
    if enable_fuzzing:
        if not tech_hint:
            tech_hint = _infer_tech_hint(host)
        try:
            fuzz_result = await run_fuzz(
                conn, config.name, target, port, aggressiveness, tech_hint,
                llm_client, scope_guard, chosen_by, comment=comment,
            )
            fuzz_hits = len(fuzz_result.hits)
            fuzz_anomalies = len(fuzz_result.anomalies)
            warnings.extend(fuzz_result.warnings)
        except FuzzingDisabledError as exc:
            warnings.append(str(exc))

    if owns_conn:
        conn.close()

    return PipelineSummary(
        engagement=config.name,
        target=target,
        aggressiveness=aggressiveness,
        hosts_parsed=hosts_parsed,
        nuclei_detections_parsed=detections_parsed,
        findings_proposed=len(correlation_result.findings),
        findings_unverified_citations=unverified_count,
        fuzz_hits=fuzz_hits,
        fuzz_anomalies=fuzz_anomalies,
        warnings=warnings,
    )


def _infer_tech_hint(host) -> str:
    """Construit un indice de techno pour le generateur de payloads a partir des services Nmap."""
    if host is None:
        return "technologie inconnue (pas de resultat Nmap exploitable)"
    parts = []
    for port in host.ports:
        if port.service_name:
            piece = port.service_name
            if port.product:
                piece += f" ({port.product}"
                piece += f" {port.version})" if port.version else ")"
            parts.append(piece)
    return ", ".join(parts) if parts else "technologie non identifiee"
