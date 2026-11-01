from __future__ import annotations

from docx import Document

from recon_copilot.report.docx_report import build_docx, save_docx


def _all_text(doc: Document) -> str:
    return "\n".join(p.text for p in doc.paragraphs)


def test_docx_contains_engagement_and_findings(sample_context):
    doc = build_docx(sample_context, "fr")
    text = _all_text(doc)
    assert "eng-test" in text
    assert "Injection SQL" in text
    assert "TLS obsolete" in text


def test_docx_english_labels(sample_context):
    doc = build_docx(sample_context, "en")
    text = _all_text(doc)
    assert "Executive Summary" in text


def test_docx_includes_scope(sample_context):
    doc = build_docx(sample_context, "fr")
    text = _all_text(doc)
    assert "10.0.0.0/24" in text
    assert "10.0.0.254" in text


def test_docx_includes_command_used(sample_context):
    doc = build_docx(sample_context, "fr")
    text = _all_text(doc)
    assert "nmap -T3 -Pn -sV -oX - 10.0.0.5" in text


def test_docx_empty_context_still_produces_valid_document(empty_context):
    doc = build_docx(empty_context, "fr")
    text = _all_text(doc)
    assert "Aucune constatation" in text


def test_save_docx_writes_real_file(sample_context, tmp_path):
    path = save_docx(sample_context, "fr", tmp_path / "report.docx")
    assert path.exists()
    assert path.stat().st_size > 0
    # doit etre relisible comme un vrai docx
    reopened = Document(str(path))
    assert "eng-test" in _all_text(reopened)
