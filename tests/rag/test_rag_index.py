from __future__ import annotations

from recon_copilot.rag import RagIndex
from recon_copilot.rag.models import KbDocument


def _doc(id_, content) -> KbDocument:
    return KbDocument(id=id_, source="nuclei_template", title=id_, content=content, metadata={})


async def test_index_documents_returns_count(tmp_path, fake_embedding_client):
    index = RagIndex(fake_embedding_client, tmp_path / "chroma")
    docs = [_doc("a", "log4j remote code execution"), _doc("b", "sql injection in login form")]
    n = await index.index_documents(docs)
    assert n == 2
    assert index.count() == 2


async def test_search_finds_semantically_closest_document(tmp_path, fake_embedding_client):
    index = RagIndex(fake_embedding_client, tmp_path / "chroma")
    await index.index_documents(
        [
            _doc("log4shell", "apache log4j remote code execution jndi"),
            _doc("weak-tls", "deprecated tls version accepted by server"),
        ]
    )
    results = await index.search("log4j jndi remote code execution vulnerability")
    assert results[0].document.id == "log4shell"


async def test_search_respects_n_results(tmp_path, fake_embedding_client):
    index = RagIndex(fake_embedding_client, tmp_path / "chroma")
    await index.index_documents([_doc(f"doc{i}", f"content number {i}") for i in range(10)])
    results = await index.search("content", n_results=3)
    assert len(results) == 3


async def test_search_empty_query_returns_empty_without_embedding_call(tmp_path, fake_embedding_client):
    index = RagIndex(fake_embedding_client, tmp_path / "chroma")
    await index.index_documents([_doc("a", "something")])
    results = await index.search("   ")
    assert results == []
    assert fake_embedding_client.calls == [["something"]]  # seul l'appel d'indexation, pas de recherche


async def test_index_documents_batches_embedding_calls(tmp_path, fake_embedding_client):
    index = RagIndex(fake_embedding_client, tmp_path / "chroma")
    docs = [_doc(f"doc{i}", f"content {i}") for i in range(150)]
    await index.index_documents(docs, batch_size=64)
    # 150 documents / 64 par lot = 3 appels (64 + 64 + 22)
    assert len(fake_embedding_client.calls) == 3
    assert [len(c) for c in fake_embedding_client.calls] == [64, 64, 22]


async def test_index_empty_documents_list(tmp_path, fake_embedding_client):
    index = RagIndex(fake_embedding_client, tmp_path / "chroma")
    n = await index.index_documents([])
    assert n == 0
    assert index.count() == 0
