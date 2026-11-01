"""Facade du module report.

Point d'entree unique : `generate_report()`. Construit le contexte depuis
la base (findings 'accepted'/'edited' uniquement -- voir data.py), puis
genere chaque format demande.

SARIF et VEX sont des formats de DONNEES STRUCTUREES pour outillage
(GitHub Security, DefectDojo...), pas des documents destines a la lecture
humaine bilingue -- ils sont donc generes UNE SEULE FOIS par run, pas une
fois par langue comme md/docx/pdf.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

from recon_copilot.report.data import build_report_context
from recon_copilot.report.docx_report import save_docx
from recon_copilot.report.markdown_report import generate_markdown
from recon_copilot.report.models import ReportContext
from recon_copilot.report.pdf_report import save_pdf
from recon_copilot.report.sarif_report import save_sarif
from recon_copilot.report.vex_report import save_vex
from recon_copilot.scope import ScopeConfig

__all__ = ["ReportContext", "generate_report"]

_LANG_SPECIFIC_FORMATS = ("md", "docx", "pdf")
_STRUCTURED_FORMATS = ("sarif", "vex")


def generate_report(
    conn: sqlite3.Connection,
    engagement: str,
    output_dir: str | Path,
    formats: tuple[str, ...] = ("md", "docx", "pdf"),
    langs: tuple[str, ...] = ("fr", "en"),
    scope: ScopeConfig | None = None,
) -> list[Path]:
    context = build_report_context(conn, engagement, scope=scope)
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    generated: list[Path] = []
    safe_engagement = "".join(c if c.isalnum() or c in "-_" else "_" for c in engagement)

    for lang in langs:
        base_name = f"{safe_engagement}_report_{lang}"
        if "md" in formats:
            md_path = output_dir / f"{base_name}.md"
            md_path.write_text(generate_markdown(context, lang), encoding="utf-8")
            generated.append(md_path)
        if "docx" in formats:
            generated.append(save_docx(context, lang, output_dir / f"{base_name}.docx"))
        if "pdf" in formats:
            generated.append(save_pdf(context, lang, output_dir / f"{base_name}.pdf"))

    if "sarif" in formats:
        generated.append(save_sarif(context, output_dir / f"{safe_engagement}.sarif"))
    if "vex" in formats:
        generated.append(save_vex(context, output_dir / f"{safe_engagement}.cyclonedx-vex.json"))

    return generated
