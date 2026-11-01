from __future__ import annotations

from recon_copilot.rag.models import KbDocument
from recon_copilot.rag.store import VectorStore


def _doc(id_, content="contenu", source="nuclei_template", title="titre") -> KbDocument:
    return KbDocument(id=id_, source=source, title=title, content=content, metadata={"severity": "high"})


def test_store_starts_empty(tmp_path):
    store = VectorStore(tmp_path / "chroma")
    assert store.count() == 0


def test_add_and_count(tmp_path):
    store = VectorStore(tmp_path / "chroma")
    store.add_documents([_doc("a"), _doc("b")], [[1.0, 0.0], [0.0, 1.0]])
    assert store.count() == 2


def test_query_returns_closest_first(tmp_path):
    store = VectorStore(tmp_path / "chroma")
    store.add_documents(
        [_doc("close", content="log4j rce"), _doc("far", content="unrelated topic entirely")],
        [[1.0, 0.0, 0.0], [0.0, 1.0, 0.0]],
    )
    results = store.query([0.99, 0.01, 0.0], n_results=2)
    assert results[0].document.id == "close"
    assert results[0].score > results[1].score


def test_query_on_empty_store_returns_empty_list(tmp_path):
    store = VectorStore(tmp_path / "chroma")
    assert store.query([1.0, 0.0], n_results=5) == []


def test_query_n_results_capped_to_available_count(tmp_path):
    store = VectorStore(tmp_path / "chroma")
    store.add_documents([_doc("only-one")], [[1.0, 0.0]])
    results = store.query([1.0, 0.0], n_results=50)
    assert len(results) == 1


def test_add_documents_preserves_metadata_and_source(tmp_path):
    store = VectorStore(tmp_path / "chroma")
    store.add_documents([_doc("x", source="cisa_kev", title="Mon titre")], [[1.0, 0.0]])
    results = store.query([1.0, 0.0], n_results=1)
    assert results[0].document.source == "cisa_kev"
    assert results[0].document.title == "Mon titre"
    assert results[0].document.metadata["severity"] == "high"


def test_add_documents_mismatched_lengths_raises(tmp_path):
    import pytest
    store = VectorStore(tmp_path / "chroma")
    with pytest.raises(ValueError):
        store.add_documents([_doc("a"), _doc("b")], [[1.0, 0.0]])


def test_upsert_updates_existing_document(tmp_path):
    store = VectorStore(tmp_path / "chroma")
    store.add_documents([_doc("x", content="version 1")], [[1.0, 0.0]])
    store.add_documents([_doc("x", content="version 2")], [[1.0, 0.0]])
    assert store.count() == 1  # pas duplique
    results = store.query([1.0, 0.0], n_results=1)
    assert results[0].document.content == "version 2"


def test_clear_empties_the_store(tmp_path):
    store = VectorStore(tmp_path / "chroma")
    store.add_documents([_doc("a")], [[1.0, 0.0]])
    store.clear()
    assert store.count() == 0


def test_add_empty_documents_list_is_noop(tmp_path):
    store = VectorStore(tmp_path / "chroma")
    store.add_documents([], [])
    assert store.count() == 0


def test_persists_across_reopening_same_directory(tmp_path):
    store1 = VectorStore(tmp_path / "chroma")
    store1.add_documents([_doc("persisted")], [[1.0, 0.0]])
    del store1

    store2 = VectorStore(tmp_path / "chroma")
    assert store2.count() == 1


def test_same_id_different_sources_do_not_collide(tmp_path):
    """Regression : un template Nuclei nomme d'apres un CVE (id='CVE-2021-44228')
    et l'entree CISA KEV du meme CVE (id='CVE-2021-44228' aussi) sont deux
    documents DIFFERENTS -- l'un ne doit jamais ecraser l'autre."""
    store = VectorStore(tmp_path / "chroma")
    kev_doc = _doc("CVE-2021-44228", content="entree CISA KEV", source="cisa_kev", title="KEV title")
    nuclei_doc = _doc("CVE-2021-44228", content="template Nuclei", source="nuclei_template", title="Nuclei title")

    store.add_documents([kev_doc, nuclei_doc], [[1.0, 0.0], [0.0, 1.0]])

    assert store.count() == 2  # pas ecrase : 2 documents distincts
    results = store.query([1.0, 0.0], n_results=2)
    contents = {r.document.content for r in results}
    assert contents == {"entree CISA KEV", "template Nuclei"}
    # l'id semantique original (CVE-2021-44228) reste correct sur les deux
    assert all(r.document.id == "CVE-2021-44228" for r in results)
