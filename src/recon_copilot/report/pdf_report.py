"""Generation du rapport au format PDF (fpdf2).

Les polices "core" PDF (Helvetica) ne supportent que Latin-1 -- suffisant
pour le francais (accents inclus) et l'anglais, mais pas pour un contenu
LLM qui contiendrait des caracteres hors Latin-1 (emojis, certains
tirets/guillemets typographiques, etc.). `_safe()` neutralise ce risque en
remplacant plutot que de faire planter la generation du PDF -- un rapport
avec quelques '?' est recuperable, un rapport qui ne se genere pas ne
l'est pas.
"""

from __future__ import annotations

from pathlib import Path

from fpdf import FPDF

from recon_copilot.report.i18n import build_executive_summary, t
from recon_copilot.report.models import ReportContext

_SEVERITY_COLORS = {
    "critical": (139, 0, 0),
    "high": (192, 57, 43),
    "medium": (185, 119, 14),
    "low": (46, 134, 193),
    "info": (93, 109, 126),
}


def _safe(text: str) -> str:
    return text.encode("latin-1", errors="replace").decode("latin-1")


def _mc(pdf: FPDF, h: float, text: str) -> None:
    """multi_cell avec reset explicite du curseur -- le defaut de cette version
    de fpdf2 laisse x pres du bord droit apres un multi_cell, ce qui fait
    planter l'appel suivant (voir la note en tete de fichier)."""
    pdf.multi_cell(0, h, text, new_x="LMARGIN", new_y="NEXT")


def build_pdf(context: ReportContext, lang: str = "fr") -> FPDF:
    pdf = FPDF(format="A4")
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()

    pdf.set_font("Helvetica", "B", 18)
    _mc(pdf, 10, _safe(f"{t(lang, 'report_title')} -- {context.engagement}"))
    pdf.ln(2)

    pdf.set_font("Helvetica", "", 10)
    pdf.cell(0, 6, _safe(f"{t(lang, 'engagement')} : {context.engagement}"), new_x="LMARGIN", new_y="NEXT")
    pdf.cell(0, 6, _safe(f"{t(lang, 'generated_at')} : {context.generated_at}"), new_x="LMARGIN", new_y="NEXT")
    pdf.ln(4)

    def section_title(text: str) -> None:
        pdf.set_font("Helvetica", "B", 14)
        pdf.cell(0, 10, _safe(text), new_x="LMARGIN", new_y="NEXT")
        pdf.set_font("Helvetica", "", 10)

    section_title(t(lang, "exec_summary"))
    _mc(pdf, 6, _safe(build_executive_summary(context.counts_by_severity(), lang)))
    pdf.ln(3)

    section_title(t(lang, "scope_section"))
    if context.scope_allowed_targets or context.scope_excluded_targets:
        if context.scope_allowed_targets:
            _mc(pdf, 6, _safe(f"{t(lang, 'scope_allowed')}: {', '.join(context.scope_allowed_targets)}"))
        if context.scope_excluded_targets:
            _mc(pdf, 6, _safe(f"{t(lang, 'scope_excluded')}: {', '.join(context.scope_excluded_targets)}"))
    else:
        _mc(pdf, 6, _safe(t(lang, "scope_none")))
    pdf.ln(3)

    section_title(t(lang, "methodology"))
    _mc(pdf, 6, _safe(t(lang, "methodology_text")))
    pdf.ln(3)

    section_title(t(lang, "findings_section"))
    findings = context.sorted_by_severity()
    if not findings:
        _mc(pdf, 6, _safe(t(lang, "no_findings")))

    for f in findings:
        severity_label = t(lang, "severities")[f.severity]
        color = _SEVERITY_COLORS.get(f.severity, (0, 0, 0))

        pdf.set_font("Helvetica", "B", 12)
        pdf.set_text_color(*color)
        _mc(pdf, 7, _safe(f"[{severity_label}] {f.title}"))
        pdf.set_text_color(0, 0, 0)

        pdf.set_font("Helvetica", "", 9)
        meta = f"{t(lang, 'target')}: {f.target}  |  {t(lang, 'severity')}: {severity_label}"
        if f.risk_score is not None:
            meta += f"  |  {t(lang, 'risk_score')}: {f.risk_score}/10 ({f.risk_level})"
        _mc(pdf, 5, _safe(meta))

        refs = []
        if f.cve_refs:
            refs.append(f"{t(lang, 'cve_refs')}: {', '.join(f.cve_refs)}")
        if f.cwe_refs:
            refs.append(f"{t(lang, 'cwe_refs')}: {', '.join(f.cwe_refs)}")
        if f.mitre_refs:
            refs.append(f"{t(lang, 'mitre_refs')}: {', '.join(f.mitre_refs)}")
        if refs:
            _mc(pdf, 5, _safe(" | ".join(refs)))

        pdf.set_font("Helvetica", "", 10)
        _mc(pdf, 6, _safe(f.description))

        if f.remediation:
            pdf.set_font("Helvetica", "B", 10)
            _mc(pdf, 6, _safe(f"{t(lang, 'remediation')}:"))
            pdf.set_font("Helvetica", "", 10)
            _mc(pdf, 6, _safe(f.remediation))

        if f.command_used:
            pdf.set_font("Helvetica", "B", 9)
            _mc(pdf, 5, _safe(f"{t(lang, 'command_used')}:"))
            pdf.set_font("Courier", "", 8)
            _mc(pdf, 5, _safe(f.command_used))

        pdf.set_font("Helvetica", "I", 8)
        _mc(pdf, 5, _safe(f"{t(lang, 'source_citation')}: {f.source_citation}"))

        if not f.citation_verified:
            pdf.set_font("Helvetica", "B", 9)
            pdf.set_text_color(*_SEVERITY_COLORS["high"])
            _mc(pdf, 5, _safe(f"! {t(lang, 'citation_unverified_warning')}"))
            pdf.set_text_color(0, 0, 0)

        pdf.ln(4)

    section_title(t(lang, "remediation_priorities"))
    priority_findings = [f for f in findings if f.severity in ("critical", "high")]
    pdf.set_font("Helvetica", "", 10)
    if not priority_findings:
        _mc(pdf, 6, _safe(t(lang, "no_findings")))
    for f in priority_findings:
        _mc(pdf, 6, _safe(f"- {f.title} ({t(lang, 'severities')[f.severity]}, {f.target}) -- {f.remediation}"))

    return pdf


def save_pdf(context: ReportContext, lang: str, output_path: str | Path) -> Path:
    pdf = build_pdf(context, lang)
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    pdf.output(str(path))
    return path
