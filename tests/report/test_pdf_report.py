from __future__ import annotations

from recon_copilot.report.pdf_report import build_pdf, save_pdf


def test_build_pdf_produces_output_bytes(sample_context):
    pdf = build_pdf(sample_context, "fr")
    output = bytes(pdf.output())
    assert output.startswith(b"%PDF")
    assert len(output) > 1000


def test_save_pdf_writes_real_file(sample_context, tmp_path):
    path = save_pdf(sample_context, "en", tmp_path / "report.pdf")
    assert path.exists()
    content = path.read_bytes()
    assert content.startswith(b"%PDF")


def test_save_pdf_empty_context_still_produces_valid_pdf(empty_context, tmp_path):
    path = save_pdf(empty_context, "fr", tmp_path / "empty.pdf")
    assert path.exists()
    assert path.read_bytes().startswith(b"%PDF")


def test_pdf_handles_non_latin1_characters_without_crashing():
    from recon_copilot.report.models import ReportContext, ReportFinding

    context = ReportContext(
        engagement="eng-unicode",
        generated_at="2026-01-01T00:00:00Z",
        findings=(
            ReportFinding(
                target="10.0.0.5",
                title="Test emoji \U0001F6A8 and curly quotes \u201cfoo\u201d",
                description="desc",
                severity="high",
                risk_score=7.0,
                risk_level="high",
                remediation="fix it",
                cve_refs=(),
                cwe_refs=(),
                mitre_refs=(),
                source_citation="x",
                citation_verified=True,
            ),
        ),
    )
    pdf = build_pdf(context, "fr")
    output = bytes(pdf.output())  # ne doit pas lever
    assert output.startswith(b"%PDF")
