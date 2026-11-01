"""Generation du rapport au format DOCX (python-docx)."""

from __future__ import annotations

from pathlib import Path

from docx import Document
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.shared import Pt, RGBColor

from recon_copilot.report.i18n import build_executive_summary, t
from recon_copilot.report.models import ReportContext

_SEVERITY_COLORS = {
    "critical": RGBColor(0x8B, 0x00, 0x00),
    "high": RGBColor(0xC0, 0x39, 0x2B),
    "medium": RGBColor(0xB9, 0x77, 0x0E),
    "low": RGBColor(0x2E, 0x86, 0xC1),
    "info": RGBColor(0x5D, 0x6D, 0x7E),
}


def build_docx(context: ReportContext, lang: str = "fr") -> Document:
    doc = Document()

    title = doc.add_heading(f"{t(lang, 'report_title')} -- {context.engagement}", level=0)

    meta = doc.add_paragraph()
    meta.add_run(f"{t(lang, 'engagement')} : ").bold = True
    meta.add_run(context.engagement)
    meta.add_run(f"\n{t(lang, 'generated_at')} : ").bold = True
    meta.add_run(context.generated_at)

    doc.add_heading(t(lang, "exec_summary"), level=1)
    doc.add_paragraph(build_executive_summary(context.counts_by_severity(), lang))

    doc.add_heading(t(lang, "scope_section"), level=1)
    if context.scope_allowed_targets or context.scope_excluded_targets:
        if context.scope_allowed_targets:
            p = doc.add_paragraph()
            p.add_run(f"{t(lang, 'scope_allowed')} : ").bold = True
            p.add_run(", ".join(context.scope_allowed_targets))
        if context.scope_excluded_targets:
            p = doc.add_paragraph()
            p.add_run(f"{t(lang, 'scope_excluded')} : ").bold = True
            p.add_run(", ".join(context.scope_excluded_targets))
    else:
        doc.add_paragraph(t(lang, "scope_none"))

    doc.add_heading(t(lang, "methodology"), level=1)
    doc.add_paragraph(t(lang, "methodology_text"))

    doc.add_heading(t(lang, "findings_section"), level=1)
    findings = context.sorted_by_severity()
    if not findings:
        doc.add_paragraph(t(lang, "no_findings"))

    for f in findings:
        severity_label = t(lang, "severities")[f.severity]
        heading = doc.add_heading(f"[{severity_label}] {f.title}", level=2)
        for run in heading.runs:
            run.font.color.rgb = _SEVERITY_COLORS.get(f.severity, RGBColor(0, 0, 0))

        meta_p = doc.add_paragraph()
        meta_p.add_run(f"{t(lang, 'target')} : ").bold = True
        meta_p.add_run(f.target)
        meta_p.add_run(f"    {t(lang, 'severity')} : ").bold = True
        meta_p.add_run(severity_label)
        if f.risk_score is not None:
            meta_p.add_run(f"    {t(lang, 'risk_score')} : ").bold = True
            meta_p.add_run(f"{f.risk_score}/10 ({f.risk_level})")

        refs = []
        if f.cve_refs:
            refs.append(f"{t(lang, 'cve_refs')}: {', '.join(f.cve_refs)}")
        if f.cwe_refs:
            refs.append(f"{t(lang, 'cwe_refs')}: {', '.join(f.cwe_refs)}")
        if f.mitre_refs:
            refs.append(f"{t(lang, 'mitre_refs')}: {', '.join(f.mitre_refs)}")
        if refs:
            doc.add_paragraph(" | ".join(refs))

        doc.add_paragraph(f.description)

        if f.remediation:
            rem_p = doc.add_paragraph()
            rem_p.add_run(f"{t(lang, 'remediation')} : ").bold = True
            rem_p.add_run(f.remediation)

        if f.command_used:
            cmd_p = doc.add_paragraph()
            cmd_p.add_run(f"{t(lang, 'command_used')} : ").bold = True
            cmd_run = cmd_p.add_run(f.command_used)
            cmd_run.font.name = "Consolas"
            cmd_run.font.size = Pt(9)

        citation_p = doc.add_paragraph()
        citation_run = citation_p.add_run(f"{t(lang, 'source_citation')} : {f.source_citation}")
        citation_run.italic = True
        citation_run.font.size = Pt(9)

        if not f.citation_verified:
            warn_p = doc.add_paragraph()
            warn_run = warn_p.add_run(f"\u26a0 {t(lang, 'citation_unverified_warning')}")
            warn_run.bold = True
            warn_run.font.color.rgb = RGBColor(0xC0, 0x39, 0x2B)

    doc.add_heading(t(lang, "remediation_priorities"), level=1)
    priority_findings = [f for f in findings if f.severity in ("critical", "high")]
    if not priority_findings:
        doc.add_paragraph(t(lang, "no_findings"))
    for f in priority_findings:
        p = doc.add_paragraph(style="List Bullet")
        p.add_run(f"{f.title} ({t(lang, 'severities')[f.severity]}, {f.target}) -- ").bold = True
        p.add_run(f.remediation)

    return doc


def save_docx(context: ReportContext, lang: str, output_path: str | Path) -> Path:
    doc = build_docx(context, lang)
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    doc.save(str(path))
    return path
