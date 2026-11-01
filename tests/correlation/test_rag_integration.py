from __future__ import annotations

import json

from recon_copilot.correlation import correlate_and_store
from recon_copilot.correlation.prompt import build_correlation_prompt
from recon_copilot.llm_client import LlmError
from recon_copilot.parser.nmap_parser import parse_nmap_xml
from recon_copilot.parser.nuclei_parser import parse_nuclei_jsonl
from recon_copilot.rag import RagIndex
from recon_copilot.rag.models import KbDocument
from tests.correlation.conftest import FakeLlmClient

NMAP_XML = """<?xml version="1.0"?>
<nmaprun>
<host>
<status state="up"/>
<address addr="10.0.0.5" addrtype="ipv4"/>
<hostnames><hostname name="app.client.local"/></hostnames>
<ports>
<port protocol="tcp" portid="80">
<state state="open"/>
<service name="http" product="nginx" version="1.24.0"/>
</port>
</ports>
</host>
</nmaprun>"""

NUCLEI_JSONL = (
    '{"template-id": "CVE-2021-44228", "info": {"name": "Apache Log4j RCE", '
    '"severity": "critical", "tags": ["kev"]}, "matched-at": "http://10.0.0.5:80/"}'
)


def test_prompt_without_rag_context_unchanged():
    """Garantie de non-regression explicite : meme prompt qu'avant le module RAG."""
    host = parse_nmap_xml(NMAP_XML).hosts[0]
    detections = list(parse_nuclei_jsonl(NUCLEI_JSONL).detections)

    prompt_no_rag_explicit = build_correlation_prompt(host, detections, "kb context")
    prompt_no_rag_default = build_correlation_prompt(host, detections, "kb context", None)

    assert prompt_no_rag_explicit == prompt_no_rag_default
    assert "Contexte RAG" not in prompt_no_rag_explicit


def test_prompt_with_rag_context_adds_dedicated_section():
    host = parse_nmap_xml(NMAP_XML).hosts[0]
    detections = list(parse_nuclei_jsonl(NUCLEI_JSONL).detections)

    prompt = build_correlation_prompt(host, detections, "kb context", "- [cisa_kev] Log4Shell : ...")
    assert "Contexte RAG" in prompt
    assert "Log4Shell" in prompt


async def test_correlate_and_store_without_rag_index_behaves_as_before(db_conn):
    """Le test le plus important : rag_index=None (defaut) => zero changement de comportement."""
    host = parse_nmap_xml(NMAP_XML).hosts[0]
    detections = list(parse_nuclei_jsonl(NUCLEI_JSONL).detections)
    llm = FakeLlmClient(response="[]")

    result = await correlate_and_store(db_conn, "eng-1", "10.0.0.5", llm, host, detections)

    assert len(llm.calls) == 1  # toujours un seul appel LLM
    prompt = llm.calls[0][0]
    assert "Contexte RAG" not in prompt  # aucune section RAG sans rag_index


async def test_correlate_and_store_with_rag_index_enriches_prompt(db_conn, fake_embedding_client, tmp_path):
    host = parse_nmap_xml(NMAP_XML).hosts[0]
    detections = list(parse_nuclei_jsonl(NUCLEI_JSONL).detections)
    llm = FakeLlmClient(response="[]")

    rag_index = RagIndex(fake_embedding_client, tmp_path / "chroma")
    await rag_index.index_documents(
        [
            KbDocument(
                id="CVE-2021-44228",
                source="cisa_kev",
                title="Apache Log4j2 RCE (Log4Shell)",
                content="Apache Log4j2 remote code execution via JNDI lookups, actively exploited",
                metadata={},
            ),
            KbDocument(
                id="unrelated",
                source="cisa_kev",
                title="Completely unrelated vulnerability",
                content="Something about a totally different product and topic",
                metadata={},
            ),
        ]
    )

    await correlate_and_store(db_conn, "eng-1", "10.0.0.5", llm, host, detections, rag_index=rag_index)

    prompt = llm.calls[0][0]
    assert "Contexte RAG" in prompt
    assert "Log4Shell" in prompt  # le document pertinent doit apparaitre dans le prompt


async def test_correlate_and_store_rag_search_failure_degrades_gracefully(db_conn):
    """Si la recherche RAG echoue (Ollama down pour les embeddings), la correlation continue quand meme."""

    class FailingEmbeddingIndex:
        async def search(self, query_text, n_results=3):
            raise LlmError("Ollama injoignable pour les embeddings (simule)")

    host = parse_nmap_xml(NMAP_XML).hosts[0]
    detections = list(parse_nuclei_jsonl(NUCLEI_JSONL).detections)
    llm = FakeLlmClient(response="[]")

    result = await correlate_and_store(
        db_conn, "eng-1", "10.0.0.5", llm, host, detections, rag_index=FailingEmbeddingIndex()
    )

    assert len(llm.calls) == 1  # la correlation a quand meme eu lieu
    errors = db_conn.execute("SELECT * FROM parse_errors WHERE tool='rag'").fetchall()
    assert len(errors) == 1
    assert "poursuivie sans" in errors[0]["detail"]


async def test_correlate_and_store_rag_index_but_no_query_terms_skips_search(db_conn, fake_embedding_client, tmp_path):
    """Aucun template-id/service pour construire une requete => pas d'appel de recherche inutile."""
    llm = FakeLlmClient(response="[]")
    rag_index = RagIndex(fake_embedding_client, tmp_path / "chroma")

    await correlate_and_store(db_conn, "eng-1", "10.0.0.5", llm, None, [], rag_index=rag_index)

    assert fake_embedding_client.calls == []  # aucun embedding calcule
